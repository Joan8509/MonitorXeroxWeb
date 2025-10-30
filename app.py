
# app.py
import os, time, io, re, sqlite3, html as htmlmod
from functools import wraps
from typing import Any, Dict, List, Tuple, Optional
from flask import Flask, jsonify, request, Response, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from puresnmp import walk, get as snmp_get

# ---- XLSX pretty export ----
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side, Color
from openpyxl.utils import get_column_letter
from openpyxl.formatting.rule import DataBarRule, CellIsRule

app = Flask(__name__)

# ------------------------- Config -------------------------
DEFAULT_COMMUNITY = os.getenv("SNMP_COMMUNITY", "public")
FLASK_PORT = int(os.getenv("FLASK_PORT", "5000"))
FLASK_HOST = os.getenv("FLASK_HOST", "0.0.0.0")
TTL_DEFAULT = int(os.getenv("TTL_DEFAULT", "15"))
TIMEOUT_DEFAULT = int(os.getenv("TIMEOUT_DEFAULT", "3"))

# Umbrales XLSX (la UI usa filtro fijo 10% para visual)
XLSX_WARN_PCT = max(1, min(99, int(os.getenv("XLSX_WARN_PCT", "20"))))
XLSX_ALERT_PCT = max(1, min(XLSX_WARN_PCT - 1, int(os.getenv("XLSX_ALERT_PCT", "10"))))
XLSX_WARN_FRAC = XLSX_WARN_PCT / 100.0
XLSX_ALERT_FRAC = XLSX_ALERT_PCT / 100.0

# Auth / sessions
app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY", "change-me-please"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(os.getenv("SESSION_COOKIE_SECURE", "0") == "1"),
)
AUTH_DB_PATH = os.getenv("AUTH_DB_PATH", "auth.db")

# ------------------------- OIDs ---------------------------
DESC_BASE   = "1.3.6.1.2.1.43.11.1.1.6"   # prtMarkerSuppliesDescription
MAX_BASE    = "1.3.6.1.2.1.43.11.1.1.8"   # prtMarkerSuppliesMaxCapacity
LEVEL_BASE  = "1.3.6.1.2.1.43.11.1.1.9"   # prtMarkerSuppliesLevel
PRT_NAME    = "1.3.6.1.2.1.43.5.1.1.16.1" # prtGeneralPrinterName
SYS_NAME    = "1.3.6.1.2.1.1.5.0"         # sysName
SYS_DESCR   = "1.3.6.1.2.1.1.1.0"         # sysDescr
PRT_MARKER_LIFECOUNT = "1.3.6.1.2.1.43.10.2.1.4"  # prtMarkerLifeCount
PRT_ALERT_DESC       = "1.3.6.1.2.1.43.18.1.1.8"  # prtAlertDescription

# -------------------- Simple Auth (SQLite) ----------------
def _db():
    conn = sqlite3.connect(AUTH_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def _init_auth_db():
    with _db() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );""")

def create_user(username: str, password: str) -> Optional[str]:
    if not username or not password:
        return "Username and password are required."
    if len(password) < 6:
        return "Password must be at least 6 characters."
    try:
        with _db() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username.strip(), generate_password_hash(password)),
            )
        return None
    except sqlite3.IntegrityError:
        return "Username already exists."

def verify_user(username: str, password: str) -> bool:
    with _db() as conn:
        cur = conn.execute("SELECT id, password_hash FROM users WHERE username = ?", (username.strip(),))
        row = cur.fetchone()
        if not row:
            return False
        return check_password_hash(row["password_hash"], password)

def find_user_id(username: str) -> Optional[int]:
    with _db() as conn:
        cur = conn.execute("SELECT id FROM users WHERE username = ?", (username.strip(),))
        row = cur.fetchone()
        return int(row["id"]) if row else None

def _update_username(user_id: int, new_username: str) -> Optional[str]:
    try:
        with _db() as conn:
            conn.execute("UPDATE users SET username=? WHERE id=?", (new_username.strip(), user_id))
        return None
    except sqlite3.IntegrityError:
        return "Username already exists."

def _update_password(user_id: int, new_password: str):
    with _db() as conn:
        conn.execute("UPDATE users SET password_hash=? WHERE id=?",
                     (generate_password_hash(new_password), user_id))

def login_required(endpoint_name: str = ""):
    def deco(fn):
        @wraps(fn)
        def _wrap(*args, **kwargs):
            if not session.get("user_id"):
                if request.path.startswith("/api/") or request.headers.get("Accept","").startswith("application/json"):
                    return jsonify({"error": "Unauthorized"}), 401
                nxt = request.full_path if request.query_string else request.path
                return redirect(url_for("login", next=nxt))
            return fn(*args, **kwargs)
        return _wrap
    return deco

def _bootstrap_admin_from_env():
    user = os.getenv("ADMIN_USER")
    pw = os.getenv("ADMIN_PASSWORD")
    if user and pw:
        with _db() as conn:
            row = conn.execute("SELECT 1 FROM users WHERE username=?", (user.strip(),)).fetchone()
            if not row:
                conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                             (user.strip(), generate_password_hash(pw)))
                print(f"[bootstrap] Created admin user '{user}' from ENV")

_init_auth_db()
_bootstrap_admin_from_env()

# -------------------- SNMP helper funcs -------------------
def _decode(v: Any) -> Any:
    if isinstance(v, bytes):
        try:
            return v.decode(errors="ignore")
        except Exception:
            return str(v)
    return v

def _snmp_get(host: str, community: str, oid: str, timeout: int) -> str:
    try:
        val = _decode(snmp_get(host, community, oid, timeout=timeout))
        return (str(val) if val is not None else "").strip()
    except Exception:
        return ""

def _snmp_get_name(host: str, community: str, timeout: int) -> str:
    name = _snmp_get(host, community, PRT_NAME, timeout)
    return name or _snmp_get(host, community, SYS_NAME, timeout)

def _guess_hp_model(sys_descr: str, prt_name: str) -> str:
    raw = f"{sys_descr or ''} {prt_name or ''}".strip()
    low = raw.lower()
    if "hp ethernet multi-environment" in low:
        return "HP LaserJet Pro"
    m = re.search(
        r'(?:HP|Hewlett[-\s]?Packard)\s+(?:Color\s+)?'
        r'(?:LaserJet(?:\s+Pro)?|OfficeJet|PageWide|DesignJet|DeskJet)[^\r\n;,]*',
        raw, re.IGNORECASE
    )
    if m:
        model = m.group(0)
        model = model.replace("Hewlett Packard", "HP").replace("Hewlett-Packard", "HP").strip()
        if re.search(r'laserjet\s+pro', model, re.IGNORECASE):
            return "HP LaserJet Pro"
        return model[:80]
    if re.search(r'\bHP\b', raw, re.IGNORECASE):
        return "HP LaserJet Pro"
    return ""

def _snmp_get_model(host: str, community: str, timeout: int) -> str:
    sysd = _snmp_get(host, community, SYS_DESCR, timeout)
    prtn = _snmp_get(host, community, PRT_NAME, timeout)
    cand_lower = f"{(sysd or '').lower()} {(prtn or '').lower()}"
    for token in ("b8155", "b7135", "b415", "c415"):
        if token in cand_lower:
            return token.upper()
    hp_model = _guess_hp_model(sysd, prtn)
    if hp_model:
        return hp_model
    return ""

def _snmp_column_map(host: str, community: str, base_oid: str, timeout: int = TIMEOUT_DEFAULT) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for vb_oid, vb_value in walk(host, community, base_oid, timeout=timeout):
        idx = str(vb_oid).split(".")[-1]
        out[idx] = _decode(vb_value)
    return out

def _safe_pct(level: Any, maxcap: Any) -> float:
    try:
        level = int(level); maxcap = int(maxcap)
    except Exception:
        return -1
    if level < 0 or maxcap <= 0:
        return -1
    return round(100.0 * level / maxcap, 1)

def _get_black_impressions(host: str, community: str, timeout: int) -> int:
    counts: List[int] = []
    try:
        for _, val in walk(host, community, PRT_MARKER_LIFECOUNT, timeout=timeout):
            try: counts.append(int(_decode(val)))
            except Exception: continue
    except Exception:
        return -1
    if not counts: return -1
    pos = [c for c in counts if c >= 0]
    return max(pos) if pos else -1

# --------- Extra para Xerox B7135: leer Fuser/Transfer vía OID privado ----------
# --------- Extra para Xerox B7135: leer Fuser/Transfer vía OID privado ----------
def _b7135_r7_r8_status(host: str, community: str, timeout: int) -> Dict[str, str]:
    out = {"fuser": "Unknown", "transfer_roller": "Unknown"}
    try:
        # Recorremos toda la tabla de consumibles Xerox
        base_oid = "1.3.6.1.4.1.253.8.53.13.2.1.6.1.6"
        table = walk(host, community, base_oid, timeout=timeout)

        for oid, val in table:
            oid_str = str(oid)
            val_str = str(val).strip().lower()

            # Fuser R8
            if oid_str.endswith(".8") or "fuser" in oid_str:
                if val_str in ("1", "end", "expired"):
                    out["fuser"] = "Past end of life"
                elif val_str in ("0", "ok", "normal"):
                    out["fuser"] = "OK"

            # Transfer Roller R7
            if oid_str.endswith(".7") or "transfer" in oid_str:
                if val_str in ("1", "end", "expired"):
                    out["transfer_roller"] = "Past end of life"
                elif val_str in ("0", "ok", "normal"):
                    out["transfer_roller"] = "OK"

        # Si no encontramos valores numéricos, intentar descripciones SNMP
        if out["fuser"] == "Unknown" or out["transfer_roller"] == "Unknown":
            for _, desc in walk(host, community, "1.3.6.1.2.1.43.18.1.1.8", timeout=timeout):
                t = str(desc).lower()
                if "fuser" in t and any(x in t for x in ("end", "replace", "expired", "vida", "fin")):
                    out["fuser"] = "Past end of life"
                if "transfer" in t and any(x in t for x in ("end", "replace", "expired", "vida", "fin")):
                    out["transfer_roller"] = "Past end of life"

        # Defaults
        out["fuser"] = out.get("fuser", "OK")
        out["transfer_roller"] = out.get("transfer_roller", "OK")

    except Exception as e:
        print(f"[DEBUG] Error R7/R8: {e}")
    return out



# -------------------- Categorization ----------------------
def _categorize(desc: str) -> str:
    d = (desc or "").lower()
    if any(k in d for k in ("waste toner","waste container","waste bottle","collection","residuo","residual")):
        return "waste_toner"
    if "r8" in d or "fuser" in d:
        return "fuser"
    if any(k in d for k in ("r7","secondary transfer","second bias","second-bias","sbtr","transfer roll","transfer roller")):
        return "transfer_roller"
    if "clean" in d and "belt" in d:
        return "belt_cleaner"
    if ("belt" in d and "transfer" in d) or "ibt" in d or "r6" in d:
        return "transfer_belt"
    if "imaging" in d or "drum" in d:
        return "drum"
    if ("cartridge" in d or "cartucho" in d) and not any(w in d for w in ("waste","staple","maintenance")):
        return "toner"
    if "toner" in d:
        return "toner"
    return "other"

FRIENDLY_DEFAULT = {
    "toner": "Toner (K)",
    "drum": "Drum / Imaging Unit",
    "fuser": "Fuser R8",
    "transfer_roller": "Transfer Roller R7",
    "waste_toner": "Waste Toner Container",
    "belt_cleaner": "Transfer Belt Cleaner",
    "transfer_belt": "Transfer Belt",
}
FRIENDLY_B8155 = {
    "toner": "Toner",
    "drum": "Drum",
    "waste_toner": "Waste Toner Container",
    "belt_cleaner": "Transfer Belt Cleaner",
    "transfer_roller": "Second Bias Transfer Roll",
}
ALLOWED_B8155 = {"toner", "drum", "waste_toner", "belt_cleaner", "transfer_roller"}

def _friendly_label(category: str, desc: str, model: str) -> str:
    if model == "B8155":
        return FRIENDLY_B8155.get(category, desc or "Other")
    return FRIENDLY_DEFAULT.get(category, desc or "Other")

# -------- B7135: R7/R8 status from alerts --------
ALERT_END_WORDS = [
    "end of life","end-of-life","life end","past of life","past end of life",
    "replace","replacement","change","cambiar","reemplazar",
    "fin de vida","vida util","vida útil","near end"
]
# ---------------------- Cache R7/R8 (SNMP alerts) ----------------------
_r7_cache: Dict[str, Tuple[float, Dict[str, str]]] = {}

def _cached_life_status_from_alerts(host: str, community: str, timeout: int) -> Dict[str, str]:
    """
    Igual que _life_status_from_alerts, pero con caché local de 5 minutos.
    """
    import time
    now = time.time()

    # 🔹 Si tenemos cache reciente, usarlo
    if host in _r7_cache and (now - _r7_cache[host][0]) < 300:
        print(f"[CACHE] Transfer Roller {host} → {_r7_cache[host][1]}")
        return _r7_cache[host][1]

    # 🔹 Ejecutar SNMP real
    status = _life_status_from_alerts(host, community, timeout)
    _r7_cache[host] = (time.time(), status)
    print(f"[R7 ALERTS] {host} → {status} (cacheado)")
    return status

def _life_status_from_alerts(host: str, community: str, timeout: int) -> Dict[str, str]:
    status: Dict[str, str] = {}
    try:
        for _, val in walk(host, community, PRT_ALERT_DESC, timeout=timeout):
            text = str(_decode(val)).lower()
            if not text: continue
            if "fuser" in text or "r8" in text:
                status["fuser"] = "END" if any(w in text for w in ALERT_END_WORDS) else "OK"
            if any(k in text for k in ("transfer","roller","r7")):
                status["transfer_roller"] = "END" if any(w in text for w in ALERT_END_WORDS) else "OK"
    except Exception:
        pass
    status.setdefault("fuser","OK"); status.setdefault("transfer_roller","OK")
    return status

# ---- Percent fallback (HP/raw levels) ----
def _fallback_pct_if_raw_percent(category: str, level: Any, maxcap: Any, desc: str = "") -> float:
    p = _safe_pct(level, maxcap)
    if isinstance(p, (int, float)) and p >= 0:
        return p
    if category in ("waste_toner", "toner"):
        try: lv = int(level)
        except Exception: lv = None
        try: mx = int(maxcap)
        except Exception: mx = None
        if lv is not None and (mx is None or mx <= 0) and 0 <= lv <= 100:
            return float(lv)
    return -1

# === C415 helpers ===========================================================
def _color_from_desc(desc: str) -> str:
    d = (desc or "").lower()
    if "cyan" in d or "cian" in d: return "C"
    if "magenta" in d: return "M"
    if "yellow" in d or "amarill" in d: return "Y"
    if "black" in d or "negro" in d or " k" in d or "k toner" in d or " bk " in d or "bk " in d: return "K"
    t0 = (d.split() or [""])[0]
    if t0 in ("c","cyan","cian"): return "C"
    if t0 in ("m","magenta"): return "M"
    if t0 in ("y","yellow","amarillo","amarilla"): return "Y"
    if t0 in ("k","black","bk","negro"): return "K"
    return ""

def _extract_c415(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "toner": {}, "drum": {},
        "waste_toner": None, "belt_cleaner": None,
        "transfer_belt": None, "transfer_roller": None
    }
    def best(existing: Any, newp: Any) -> Any:
        en = existing if isinstance(existing, (int, float)) else -1
        np = newp if isinstance(newp, (int, float)) else -1
        return np if np > en else existing

    for it in items:
        cat = it.get("category")
        desc = it.get("description") or ""
        p = it.get("percent") if isinstance(it.get("percent"), (int, float)) else -1
        if cat == "toner":
            col = _color_from_desc(desc)
            if col: out["toner"][col] = best(out["toner"].get(col, -1), p)
        elif cat == "drum":
            col = _color_from_desc(desc)
            if col: out["drum"][col] = best(out["drum"].get(col, -1), p)
        elif cat in ("waste_toner","belt_cleaner","transfer_belt","transfer_roller"):
            if (not isinstance(p,(int,float))) or p < 0:
                p = _fallback_pct_if_raw_percent(cat, it.get("level"), it.get("max_capacity"), desc)
            out[cat] = best(out[cat], p)
    return out
# --------- B7135: Lectura Fuser y captura visual del panel ---------
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
import time, re, os 
from datetime import datetime

# ---------------------- Fuser R8 (B7135) con caché ----------------------
_fuser_cache: Dict[str, Tuple[float, str]] = {}

def _b7135_fuser_status(host: str):
    """
    Usa Selenium headless para obtener el estado del Fuser R8 en la Xerox B7135.
    Devuelve 'OK', 'Past end of life' o 'Unknown'.
    Con caché de 1 hora para evitar ejecuciones repetitivas lentas.
    """
    import time
    now = time.time()

    # 🔹 Si ya hay un valor en caché reciente (menos de 1h), usarlo
    if host in _fuser_cache and (now - _fuser_cache[host][0]) < 3600:
        cached_status = _fuser_cache[host][1]
        print(f"[CACHE] Fuser {host} → {cached_status}")
        return cached_status

    status = "Unknown"
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service
        from webdriver_manager.chrome import ChromeDriverManager

        url = f"http://{host}/"
        chrome_options = Options()
        chrome_options.add_argument("--headless=new")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--log-level=3")
        chrome_options.add_argument("--window-size=1920,1080")

        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)
        driver.set_page_load_timeout(20)
        driver.get(url)
        time.sleep(8)  # esperar carga de página
        page_source = driver.page_source.lower()
        driver.quit()

        if "fuser r8" in page_source or "fuser" in page_source:
            if any(word in page_source for word in ("end", "replace", "expired", "vida", "fin")):
                status = "Past end of life"
            else:
                status = "OK"

    except Exception as e:
        print(f"[Fuser Selenium Error] {host}: {e}")

    # 🔹 Guardar en caché el resultado con timestamp
    _fuser_cache[host] = (time.time(), status)
    print(f"[B7135 Fuser] {host} → {status} (cacheado)")

    return status


def _b7135_take_snapshot(host: str):
    """
    Toma una captura visual del panel del B7135 y la guarda en /snapshots/.
    """
    try:
        chrome_options = Options()
        chrome_options.add_argument("--headless=new")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--window-size=1920,1080")
        chrome_options.add_argument("--log-level=3")

        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)
        driver.set_page_load_timeout(25)
        driver.get(f"http://{host}/")
        time.sleep(8)

        out_dir = os.path.join(os.getcwd(), "snapshots")
        os.makedirs(out_dir, exist_ok=True)

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"B7135_{host.replace('.', '-')}_{timestamp}.png"
        out_path = os.path.join(out_dir, filename)
        driver.save_screenshot(out_path)
        driver.quit()

        print(f"[Snapshot B7135] Guardada: {out_path}")
        return filename

    except Exception as e:
        print(f"[Snapshot Error] {e}")
        return None

# -------------------- Core SNMP fetch ---------------------
def fetch_supplies_generic(ip: str, community: str = DEFAULT_COMMUNITY, timeout: int = TIMEOUT_DEFAULT) -> Dict[str, Any]:
    name = _snmp_get_name(ip, community, timeout)
    model = _snmp_get_model(ip, community, timeout)

    descs  = _snmp_column_map(ip, community, DESC_BASE,  timeout=timeout)
    maxs   = _snmp_column_map(ip, community, MAX_BASE,   timeout=timeout)
    levels = _snmp_column_map(ip, community, LEVEL_BASE, timeout=timeout)
    black_impr = _get_black_impressions(ip, community, timeout)

    # --- Ajuste especial B7135: Fuser R8 + Transfer Roller R7 ---
    life_status = {}
    if model == "B7135":
        try:
            # Fuser R8: Selenium (visual)
            fuser_status = _b7135_fuser_status(ip)
        except Exception as e:
            print(f"[B7135] Error Fuser: {e}")
            fuser_status = "Unknown"

        try:
            # Transfer Roller R7: SNMP alerts
            alert_status = _cached_life_status_from_alerts(ip, community, timeout)
            tr_status = alert_status.get("transfer_roller", "Unknown")
        except Exception as e:
            print(f"[B7135] Error Transfer Roller: {e}")
            tr_status = "Unknown"

        life_status = {
            "fuser": "END" if "end" in fuser_status.lower() else "OK",
            "transfer_roller": tr_status
        }

        print(f"[B7135] {ip} -> Fuser={fuser_status}, Transfer Roller={tr_status}")

    # --- Generar lista de items base SNMP ---
    items: List[Dict[str, Any]] = []
    for idx in sorted(set(descs) | set(maxs) | set(levels), key=lambda x: int(x)):
        desc = descs.get(idx)
        cat  = _categorize(desc or "")
        if model == "B8155" and cat not in ALLOWED_B8155:
            continue
        maxc = maxs.get(idx)
        lev = levels.get(idx)
        pct = _fallback_pct_if_raw_percent(cat, lev, maxc, desc or "")

        entry = {
            "index": int(idx),
            "description": desc,
            "max_capacity": maxc,
            "level": lev,
            "percent": pct,
            "category": cat,
            "label": _friendly_label(cat, desc or "Other", model),
        }

        # Aplicar estados de vida útil al B7135
        if model == "B7135" and cat in ("fuser", "transfer_roller"):
            st = life_status.get(cat, "OK")
            entry["status"] = "Past end of life" if st.lower() in ("end", "past end of life") else "OK"
            entry["percent"] = -1

        items.append(entry)

    # --- Modelo HP (rescate) ---
    if (model or "").upper().startswith("HP"):
        toners = [it for it in items if it.get("category") == "toner"]
        has_pct = any(isinstance(it.get("percent"), (int, float)) and it["percent"] >= 0 for it in toners)
        if not toners or not has_pct:
            cand = None
            kws = ("cartridge", "cartucho", "black", "negro", "toner")
            for it in items:
                d = (it.get("description") or "").lower()
                if any(k in d for k in kws):
                    cand = it
                    break
            if cand is None and len(items) == 1:
                cand = items[0]
            if cand is not None:
                lv = cand.get("level")
                mx = cand.get("max_capacity")
                p = _fallback_pct_if_raw_percent("toner", lv, mx, cand.get("description") or "")
                if (not isinstance(p, (int, float))) or p < 0:
                    try:
                        ilv = int(lv)
                        if 0 <= ilv <= 100:
                            p = float(ilv)
                    except Exception:
                        pass
                cand["category"] = "toner"
                cand["label"] = FRIENDLY_DEFAULT["toner"]
                cand["percent"] = p if isinstance(p, (int, float)) else -1

    # --- B8155 split & pick ---
    if model == "B8155":
        toners = [it for it in items if it.get("category") == "toner"]
        if len(toners) >= 2:
            candidate = None
            for it in toners:
                d = (it.get("description") or "").lower()
                if any(k in d for k in ("waste", "container", "bottle", "collection")):
                    candidate = it
                    break
            if candidate is None:
                candidate = max(
                    toners,
                    key=lambda it: it.get("percent")
                    if isinstance(it.get("percent"), (int, float))
                    else -1,
                )
            candidate["category"] = "waste_toner"
            candidate["label"] = FRIENDLY_B8155["waste_toner"]
        toners_left = [it for it in items if it.get("category") == "toner"]
        if toners_left:
            chosen = None
            for it in toners_left:
                dd = (it.get("description") or "").lower()
                if any(k in dd for k in ("toner cartridge", "black toner", "k toner", "bk toner")):
                    chosen = it
                    break
            if chosen is None:
                chosen = max(
                    toners_left,
                    key=lambda it: it.get("percent")
                    if isinstance(it.get("percent"), (int, float))
                    else -1,
                )
            for it in toners_left:
                if it is not chosen:
                    it["category"] = "other"

    # --- Ordenar y extraer C415 ---
    items.sort(
        key=lambda it: (
            it["category"] == "other",
            -(it["percent"] if isinstance(it["percent"], (int, float)) else -1),
        )
    )

    c415_map: Dict[str, Any] = {}
    if model == "C415":
        c415_map = _extract_c415(items)

    return {
        "ip": ip,
        "printer_name": name,
        "model": model,
        "black_impressions": black_impr,
        "items": items,
        "c415": c415_map if model == "C415" else {},
    }


# -------------------------- Cache -------------------------
CACHE: Dict[Tuple[str, str, int], Tuple[float, Dict[str, Any]]] = {}
def get_cached(ip: str, community: str, timeout: int, ttl: int) -> Dict[str, Any]:
    key = (ip, community, timeout)
    now = time.time()
    hit = CACHE.get(key)
    if hit and hit[0] > now:
        return hit[1]
    data = fetch_supplies_generic(ip, community, timeout)
    CACHE[key] = (now + max(1, ttl), data)
    return data

# ----------------------- AUTH PAGES -----------------------
def _auth_base_html(body: str, title: str = "Printers Supplies ", error: str = "") -> str:
    err = f'<div class="err">{htmlmod.escape(error)}</div>' if error else ""
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{htmlmod.escape(title)} · Supplies</title>
  <style>
    :root{{
      --bg:#f3f7ff; --card:#ffffff; --text:#0f172a; --muted:#6b7280; --border:#e6eefc;
      --accent:#2563eb; --accent-2:#3b82f6; --shadow:0 20px 60px rgba(37,99,235,.15);
    }}
    *{{box-sizing:border-box}}
    body{{
      margin:0; min-height:100vh; color:var(--text); font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial;
      background:
        radial-gradient(1000px 600px at -10% -20%, #e1edff 0%, transparent 60%),
        radial-gradient(900px 500px at 110% 120%, #e9f1ff 0%, transparent 60%),
        #f3f7ff;
      display:grid; place-items:center;
    }}
    .wrap{{width:100%; max-width:520px; padding:32px 16px}}
    .card{{background:var(--card); border:1px solid var(--border); border-radius:20px; padding:28px; box-shadow:var(--shadow)}}
    .brand{{display:flex; align-items:center; gap:12px; margin-bottom:10px}}
    .brand .ico{{width:36px; height:36px}}
    .brand .title{{margin:0; font-size:26px; font-weight:800;
      background:linear-gradient(90deg,#60a5fa,#2563eb); -webkit-background-clip:text; background-clip:text; color:transparent}}
    .subtitle{{color:var(--muted); margin:.25rem 0 1.1rem 0; line-height:1.3}}
    label{{display:block; font-size:13px; color:var(--muted); margin:8px 0 6px}}
    input{{width:100%; border:1px solid var(--border); border-radius:14px; padding:12px 14px; font-size:14px; background:#fff; color:#0f172a; outline:none}}
    input:focus{{border-color:var(--accent); box-shadow:0 0 0 4px rgba(37,99,235,.15)}}
    .pw{{position:relative}} .pw input{{padding-right:44px}}
    .pwbtn{{position:absolute; right:10px; top:50%; transform:translateY(-50%); background:transparent; border:0; cursor:pointer; color:#64748b; padding:6px; border-radius:10px}}
    .pwbtn:hover{{background:#f2f6ff}}
    .btn{{width:100%; margin-top:16px; appearance:none; border:0; border-radius:14px; padding:12px 16px; font-weight:700; color:#fff; cursor:pointer;
      background:linear-gradient(135deg, var(--accent), var(--accent-2)); box-shadow:0 10px 22px rgba(37,99,235,.25)}}
    .btn:hover{{filter:brightness(1.05)}}
    .err{{color:#b3261e; font-weight:700; margin-top:10px}}
    .hint{{margin-top:10px; text-align:center; color:var(--muted); font-size:12px}}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card" role="dialog" aria-labelledby="title">
      <div class="brand">
        <svg class="ico" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M7 8V4h10v4" stroke="#2563eb" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
          <rect x="3" y="8" width="18" height="8" rx="2" stroke="#60a5fa" stroke-width="2"/>
          <path d="M7 16v4h10v-4" stroke="#2563eb" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
          <circle cx="17.5" cy="12" r="1" fill="#10b981"/>
        </svg>
        <h1 id="title" class="title">{htmlmod.escape(title)}</h1>
      </div>
      <p class="subtitle">Access is restricted. Please authenticate to continue.</p>
      {body}
      {err}
      <div class="hint">© {time.strftime("%Y")} — Internal tool</div>
    </div>
  </div>
  <script>
    (function(){{
      const btn = document.getElementById('pwToggle');
      const input = document.getElementById('password');
      if (btn && input) {{
        const eye = {{
          open: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12Z" stroke="currentColor" stroke-width="2"/><circle cx="12" cy="12" r="3" fill="currentColor"/></svg>',
          close:'🙈'
        }};
        btn.innerHTML = eye.open;
        btn.addEventListener('click', function(){{
          const show = input.type === 'password';
          input.type = show ? 'text' : 'password';
          btn.innerHTML = show ? eye.close : eye.open;
          btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
          btn.title = show ? 'Hide password' : 'Show password';
        }});
      }}
    }})();
  </script>
</body>
</html>"""

@app.get("/login")
def login():
    if session.get("user_id"):
        return redirect(url_for("home"))
    next_url = request.args.get("next","/")
    body = f"""
    <form method="post" action="/login?next={htmlmod.escape(next_url)}" novalidate>
      <label>Username</label>
      <input name="username" placeholder="your.name" autofocus>
      <label>Password</label>
      <div class="pw">
        <input id="password" name="password" type="password" placeholder="••••••••">
        <button type="button" id="pwToggle" class="pwbtn" aria-label="Show password" title="Show password"></button>
      </div>
      <button class="btn" type="submit">Sign in</button>
    </form>
    """
    return _auth_base_html(body, "Printers Supplies")

@app.post("/login")
def login_post():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    next_url = request.args.get("next","/")
    if not verify_user(username, password):
        body = """
        <form method="post" action="/login" novalidate>
          <label>Username</label><input name="username" placeholder="your.name" autofocus>
          <label>Password</label>
          <div class="pw">
            <input id="password" name="password" type="password" placeholder="••••••••">
            <button type="button" id="pwToggle" class="pwbtn" aria-label="Show password" title="Show password"></button>
          </div>
          <button class="btn" type="submit">Sign in</button>
        </form>"""
        return _auth_base_html(body, "Printers Supplies", "Invalid credentials.")
    uid = find_user_id(username)
    session["user_id"] = uid
    session["username"] = username
    return redirect(next_url or url_for("home"))

@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ----------------------- ACCOUNT (Edit user) -----------------------
def _account_html(form_html: str, message: str = "", is_error: bool = False) -> str:
    note = ""
    if message:
        note = f'<div style="margin-top:10px;{ "color:#b3261e" if is_error else "color:#166534" }">{htmlmod.escape(message)}</div>'
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Account · Supplies</title>
  <style>
    :root{{ --bg:#f6f7fb; --card:#ffffff; --text:#0f172a; --muted:#64748b; --border:#e5e7eb; --accent:#2563eb; }}
    *{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--text);font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial}}
    .container{{max-width:620px;margin:8vh auto;padding:0 16px}}
    .card{{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:18px;box-shadow:0 10px 30px rgba(2,6,23,.06)}}
    h1{{margin:0 0 12px 0;font-size:22px}} p.muted{{color:var(--muted);margin:0 0 14px 0}}
    label{{display:block;font-size:13px;color:var(--muted);margin:8px 0 6px}}
    input{{width:100%;border:1px solid var(--border);border-radius:12px;padding:10px 12px;font-size:14px;background:#fff;color:#0f172a}}
    .btn{{margin-top:14px;background:var(--accent);color:#fff;border:0;border-radius:12px;padding:10px 14px;font-weight:700;cursor:pointer}}
    .row{{display:flex;gap:16px;flex-wrap:wrap}}
    .grow{{flex:1}}
    .linkbar{{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}}
    a{{color:var(--accent);text-decoration:none}}
    .pw{{position:relative}} .pw input{{padding-right:40px}}
    .pwbtn{{position:absolute;right:8px;top:50%;transform:translateY(-50%);background:transparent;border:0;cursor:pointer;color:#64748b;font-size:16px}}
    .pwbtn:focus{{outline:2px solid var(--accent);border-radius:8px}}
  </style>
</head>
<body>
  <div class="container">
    <div class="linkbar">
      <a href="/">← Back to app</a>
      <div><a href="/logout">Logout</a></div>
    </div>
    <div class="card">
      <h1>Account</h1>
      <p class="muted">Update your username and password.</p>
      {form_html}
      {note}
    </div>
  </div>
  <script>
  const toggles = [
    ['current_password','pwToggleCur'],
    ['new_password','pwToggleNew'],
    ['confirm_password','pwToggleCnf']
  ];
  for (const [inputId, btnId] of toggles) {{
    const input = document.getElementById(inputId);
    const btn = document.getElementById(btnId);
    if (input && btn) {{
      btn.addEventListener('click', ()=>{{ 
        const show = input.type === 'password';
        input.type = show ? 'text' : 'password';
        btn.textContent = show ? '🙈' : '👁';
        btn.title = show ? 'Hide' : 'Show';
      }});
    }}
  }}
</script>

</body>
</html>"""

@app.get("/account")
@login_required("account_get")
def account_get():
    username = session.get("username","")
    form = f"""
      <form method="post" action="/account">
        <div class="row">
          <div class="grow">
            <label>Username</label>
            <input name="username" value="{htmlmod.escape(username)}" placeholder="your.name">
          </div>
        </div>
        <div class="row">
          <div class="grow">
            <label>Current password</label>
            <div class="pw">
              <input id="current_password" name="current_password" type="password" placeholder="••••••••" required>
              <button type="button" id="pwToggleCur" class="pwbtn" title="Show">👁</button>
            </div>
          </div>
        </div>
        <div class="row">
          <div class="grow">
            <label>New password (optional)</label>
            <div class="pw">
              <input id="new_password" name="new_password" type="password" placeholder="min. 6 characters">
              <button type="button" id="pwToggleNew" class="pwbtn" title="Show">👁</button>
            </div>
          </div>
          <div class="grow">
            <label>Confirm new password</label>
            <div class="pw">
              <input id="confirm_password" name="confirm_password" type="password" placeholder="repeat new password">
              <button type="button" id="pwToggleCnf" class="pwbtn" title="Show">👁</button>
            </div>
          </div>
        </div>
        <button class="btn" type="submit">Save changes</button>
      </form>
    """
    return _account_html(form)

@app.post("/account")
@login_required("account_post")
def account_post():
    current_user = session.get("username","")
    uid = session.get("user_id")
    if not uid:
        return redirect(url_for("login"))

    username_new = (request.form.get("username") or "").strip()
    current_pw   = request.form.get("current_password") or ""
    new_pw       = request.form.get("new_password") or ""
    confirm_pw   = request.form.get("confirm_password") or ""

    if not verify_user(current_user, current_pw):
        return _account_html(_account_form_prefill(username_new), "Current password is incorrect.", True)

    if username_new and username_new != current_user:
        err = _update_username(uid, username_new)
        if err:
            return _account_html(_account_form_prefill(username_new), err, True)
        session["username"] = username_new

    if new_pw or confirm_pw:
        if len(new_pw) < 6:
            return _account_html(_account_form_prefill(username_new), "New password must be at least 6 characters.", True)
        if new_pw != confirm_pw:
            return _account_html(_account_form_prefill(username_new), "Passwords do not match.", True)
        _update_password(uid, new_pw)

    return _account_html(_account_form_prefill(username_new or current_user), "Changes saved successfully.", False)

def _account_form_prefill(username_value: str) -> str:
    return f"""
      <form method="post" action="/account">
        <div class="row">
          <div class="grow">
            <label>Username</label>
            <input name="username" value="{htmlmod.escape(username_value)}" placeholder="your.name">
          </div>
        </div>
        <div class="row">
          <div class="grow">
            <label>Current password</label>
            <div class="pw">
              <input id="current_password" name="current_password" type="password" placeholder="••••••••" required>
              <button type="button" id="pwToggleCur" class="pwbtn" title="Show">👁</button>
            </div>
          </div>
        </div>
        <div class="row">
          <div class="grow">
            <label>New password (optional)</label>
            <div class="pw">
              <input id="new_password" name="new_password" type="password" placeholder="min. 6 characters">
              <button type="button" id="pwToggleNew" class="pwbtn" title="Show">👁</button>
            </div>
          </div>
          <div class="grow">
            <label>Confirm new password</label>
            <div class="pw">
              <input id="confirm_password" name="confirm_password" type="password" placeholder="repeat new password">
              <button type="button" id="pwToggleCnf" class="pwbtn" title="Show">👁</button>
            </div>
          </div>
        </div>
        <button class="btn" type="submit">Save changes</button>
      </form>
    """

# ----------------------- Web (UI) -------------------------
def _parse_int(value: Optional[str], default: int) -> int:
    try:
        v = int(str(value))
        if v <= 0: return default
        return v
    except Exception:
        return default

@app.get("/")
@login_required("home")
def home():
    username = session.get("username") or ""
    user_menu = f'''
      <nav class="user-menu">
        <span class="um-muted">Signed in as</span> <strong>{htmlmod.escape(username)}</strong>
        <span class="um-sep">·</span><a href="/account">Edit-Account</a>
        <span class="um-sep">·</span><a href="/logout">Logout</a>
      </nav>'''

    html = r'''
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Printers Supplies</title>
  <style>
    :root{
      --bg:#f6f7fb; --card:#ffffff; --text:#0f172a; --muted:#64748b;
      --border:#e5e7eb; --accent:#2563eb; --accent-2:#10b981;
      --okbg:#e7f7ee; --ok:#2e7d32; --badbg:#fdecea; --bad:#b3261e;
      --zebra:#fbfcff; --hover:#eef6ff; --bar:#eef2f7;
      --toast-bg:#0f172a; --toast-fg:#ffffff;
    }
    *{box-sizing:border-box}
    body{
      margin:0; background:var(--bg); color:var(--text);
      font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Arial, "Noto Sans", "Helvetica Neue", sans-serif;
    }
    .container{max-width:min(95vw,1600px); margin:28px auto; padding:0 16px;}

    /* Top bar */
    .topbar{display:flex; align-items:center; justify-content:space-between; margin-bottom:18px}
    .title{display:flex; align-items:center; gap:12px}
    .title-text{
      font-size:28px; font-weight:900; letter-spacing:.3px; margin:0;
      background:linear-gradient(90deg,#60a5fa,#2563eb); -webkit-background-clip:text; background-clip:text; color:transparent;
      text-shadow:0 1px 0 rgba(255,255,255,.35);
    }
    .printer-ico{ width:32px; height:32px; }

    /* User menu – bonito */
    .user-menu{
      display:flex; align-items:center; gap:10px;
      font-size:14.5px; color:#0f172a; letter-spacing:.2px; font-weight:700;
    }
    .user-menu .um-muted{ color:#6b7280; font-weight:600; letter-spacing:.3px; }
    .user-menu strong{
      font-weight:900;
      background:linear-gradient(90deg,#0ea5e9,#2563eb);
      -webkit-background-clip:text; background-clip:text; color:transparent;
    }
    .user-menu .um-sep{ color:#c7d2fe; font-weight:900; margin:0 2px; }
    .user-menu a{
      color:#1d4ed8; text-decoration:none; font-weight:800;
      padding:2px 6px; border-radius:10px; border-bottom:2px solid transparent;
      transition: all .18s ease;
    }
    .user-menu a:hover{ background:#eef2ff; border-bottom-color:#93c5fd; transform: translateY(-.5px); }

    /* Cards / inputs */
    .card{background:var(--card); border:1px solid var(--border); border-radius:16px; padding:16px; box-shadow:0 6px 22px rgba(2,6,23,.06)}
    .sticky-card{ position: sticky; top: 12px; z-index: 30; }
    .toolbar{display:flex; gap:12px; align-items:end; flex-wrap:wrap}
    label{font-size:12px; color:var(--muted); letter-spacing:.6px; text-transform:uppercase; font-weight:800}
    input, textarea{
      width:100%; border:1px solid var(--border); background:#fff; color:#0f172a;
      border-radius:14px; padding:10px 12px; font-size:14px; outline:0; transition:all .15s ease;
      box-shadow: 0 1px 0 rgba(255,255,255,.7) inset;
    }
    input:focus, textarea:focus{border-color:var(--accent); box-shadow:0 0 0 3px rgba(37,99,235,.15)}
    textarea{height:110px; resize:vertical}
    .stack{display:flex; flex-direction:column; gap:6px}
    .row{display:flex; gap:16px; flex-wrap:wrap}
    .w-200{width:200px} .w-280{width:280px} .w-420{width:420px}

    .btn{
      appearance:none; border:0; border-radius:12px; padding:10px 14px; font-weight:800; letter-spacing:.2px;
      cursor:pointer; transition:transform .06s ease, box-shadow .2s ease, background .2s ease, color .2s ease;
      box-shadow: 0 8px 20px rgba(37,99,235,.12);
    }
    .btn:active{transform:translateY(1px)}
    .btn-primary{background:linear-gradient(135deg, #2563eb, #0ea5e9); color:#fff; box-shadow:0 10px 24px rgba(37,99,235,.25)}
    .btn-secondary{background:transparent; color:var(--accent); border:1px solid var(--accent)}
    #spinner{display:none; width:18px; height:18px; border:3px solid #cbd5e1; border-top-color:var(--accent); border-radius:50%;
             animation:spin .8s linear infinite; margin-left:8px}
    @keyframes spin{to{transform:rotate(360deg)}}

    /* Results bar (título izq, filtros der) */
    .resultsbar{ display:flex; align-items:center; justify-content:space-between; gap:12px; margin:20px 0 8px; }
    .section-title{ font-size:20px; font-weight:900; letter-spacing:.3px; color:#0b1220; margin:0; }
    .right-tools{ display:flex; align-items:center; gap:10px; }

    /* Checkbox + select de umbral */
    .check-inline{
      display:flex; align-items:center; gap:10px; user-select:none;
      background:#ffffff; border:1px solid #dbe6ff; padding:6px 10px; border-radius:12px;
      box-shadow:0 4px 12px rgba(37,99,235,.08);
    }
    .check-inline span{ font-size:13.5px; font-weight:800; color:#0f172a; letter-spacing:.3px; }
    .check-inline input{ width:16px; height:16px; }
    .threshold{
      height:34px; border:1px solid #dbe6ff; border-radius:10px; padding:0 10px; font-weight:800; color:#0f172a;
      background:#fff; outline:0;
    }

    /* Tabla */
    .tableWrap{margin-top:16px; background:var(--card); border:1px solid var(--border);
      border-radius:16px; overflow:auto; box-shadow:0 6px 22px rgba(2,6,23,.06)}
    table{width:100%; border-collapse:separate; border-spacing:0}
    thead th{
      position:sticky; top:0; z-index:1; font-weight:700; font-size:13px;
      background:linear-gradient(#f8fafc,#eef2f7); color:#0f172a; text-align:left;
      padding:12px 10px; border-bottom:1px solid var(--border); cursor:pointer; user-select:none
    }
    thead th .sort{font-weight:400; opacity:.6; margin-left:6px}
    tbody td{padding:12px 10px; border-bottom:1px solid var(--border); font-size:14.25px; vertical-align:middle}
    tbody tr:nth-child(odd) td{background:var(--zebra)}
    tbody tr:hover td{background:var(--hover)}
    .nowrap{white-space:nowrap}
    .pill{display:inline-block;padding:3px 10px;border-radius:999px;border:1px solid #99c;background:#eef;font-weight:600;font-size:12px}
    .pill.ok{background:var(--okbg);border-color:#7cc79f;color:#2e7d32}
    .pill.bad{background:var(--badbg);border-color:#f5b5b0;color:#b3261e}
    .bar{height:10px;background:var(--bar);border-radius:999px;overflow:hidden}
    .bar>div{height:100%;border-radius:inherit;transition:width .35s ease}
    .muted{color:var(--muted)}
    .c415-card{margin-top:12px; background:var(--card); border:1px solid var(--border);
      border-radius:16px; padding:16px; box-shadow:0 6px 22px rgba(2,6,23,.06)}
    .kv{display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:12px; margin-top:6px}
    .metric{background:#f9fafb; border:1px solid #eef2ff; border-radius:12px; padding:10px 12px;}
    .metric .label{font-size:12px; color:var(--muted); margin-bottom:4px}
    .err{color:#b00; font-weight:600}
    .empty{border:1px dashed var(--border); border-radius:16px; padding:24px; color:var(--muted); text-align:center}
    .badge{display:inline-block;padding:2px 8px;border-radius:999px;font-weight:800;font-size:11px}
    .badge.alert{background:#fef2f2;border:1px solid #fecaca;color:#b91c1c}

    /* Toast con icono y cerrar */
    .toast-container{ position:fixed; right:16px; bottom:16px; display:flex; flex-direction:column; gap:10px; z-index:9999; }
    .toast{
      background:var(--toast-bg); color:var(--toast-fg); padding:10px 12px; border-radius:12px;
      box-shadow:0 10px 30px rgba(0,0,0,.25); min-width:260px; opacity:0; transform:translateY(8px);
      transition:opacity .2s ease, transform .2s ease; font-weight:700; letter-spacing:.2px;
    }
    .toast.show{ opacity:1; transform:translateY(0); }
    .toast.success{ background:#065f46; }
    .toast.warn{ background:#92400e; }
    .toast.error{ background:#7f1d1d; }
    .toast .row{ display:flex; align-items:center; gap:10px; }
    .toast .icon{ width:18px; height:18px; flex:0 0 18px; }
    .toast .msg{ flex:1; }
    .toast .close{
      background:transparent; color:#fff; border:0; font-size:16px; line-height:1; cursor:pointer;
      padding:2px 6px; border-radius:8px;
    }
    .toast .close:hover{ background:rgba(255,255,255,.12); }
  </style>
</head>
<body>
  <div class="container">

    <div class="topbar">
      <div class="title">
        <svg class="printer-ico" viewBox="0 0 24 24" fill="none">
          <path d="M7 8V4h10v4" stroke="#2563eb" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
          <rect x="3" y="8" width="18" height="8" rx="2" stroke="#0ea5e9" stroke-width="2"/>
          <path d="M7 16v4h10v-4" stroke="#2563eb" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
          <circle cx="17.5" cy="12" r="1" fill="#10b981"/>
        </svg>
        <h1 class="title-text">Printers Supplies</h1>
      </div>
      __USER_MENU__
    </div>

    <!-- QUERY CARD -->
    <div class="card sticky-card">
      <form id="f" class="toolbar" autocomplete="off">
        <label class="switch">
          <input type="checkbox" id="listmode" checked>
          <span>List mode</span>
        </label>

        <div id="singleInputs" class="row" style="display:none">
          <div class="stack w-280">
            <label>IP</label>
            <input id="ip" placeholder="192.168.1.100">
          </div>
        </div>

        <div id="listInputs" class="row">
          <div class="stack w-420">
            <label>IPs (one per line or comma-separated)</label>
            <textarea id="ips" placeholder="192.168.1.100
192.168.1.101"></textarea>
          </div>
        </div>

        <button id="btnQ" class="btn btn-primary">Query</button>
        <button id="btnXLSX" type="button" class="btn btn-secondary">Export to Excel</button>
      </form>
    </div>

    <!-- Results bar (con umbral seleccionable) -->
    <div class="resultsbar">
      <h2 class="section-title">Results</h2>
      <div class="right-tools">
        <label class="check-inline">
          <input id="onlyLow" type="checkbox">
          <span>Show only below</span>
        </label>
        <select id="threshold" class="threshold">
          <option value="10" selected>10%</option>
          <option value="15">15%</option>
          <option value="20">20%</option>
        </select>
      </div>
    </div>

    <div class="row" style="margin-bottom:10px">
      <div class="stack" style="flex:1">
        <label>Search</label>
        <input id="filter" placeholder="Filter by IP, Printer or Model">
      </div>
    </div>

    <div id="out" class="empty">No data yet. Run a query to see results.</div>
    <div id="extras"></div>
  </div>

  <!-- Toast container -->
  <div class="toast-container" id="toasts"></div>

  <script>
    // ====== Utils ======
    function pctColor(p){ if(p<0) return '#cbd5e1'; if(p>=50) return '#16a34a'; if(p>=20) return '#f59e0b'; return '#ef4444'; }

    // ====== Toast con icono + cerrar ======
    function showToast(msg, type='warn', ms=2600){
      const icons = {
        success: '<svg class="icon" viewBox="0 0 24 24" fill="none"><path d="M20 7L9 18l-5-5" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
        warn:    '<svg class="icon" viewBox="0 0 24 24" fill="none"><path d="M12 9v4m0 4h.01M10.29 3.86l-8.49 14.7A2 2 0 003.53 21h16.94a2 2 0 001.73-3l-8.49-14.7a2 2 0 00-3.42 0z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
        error:   '<svg class="icon" viewBox="0 0 24 24" fill="none"><path d="M15 9l-6 6m0-6l6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>'
      };
      const box = document.getElementById('toasts');
      const el = document.createElement('div');
      el.className = 'toast ' + (type||'');
      el.innerHTML = `<div class="row">
          ${icons[type] || icons.warn}
          <div class="msg">${msg}</div>
          <button class="close" aria-label="Close">×</button>
        </div>`;
      box.appendChild(el);
      requestAnimationFrame(()=> el.classList.add('show'));
      const kill = ()=>{ el.classList.remove('show'); setTimeout(()=> el.remove(), 180); };
      el.querySelector('.close').addEventListener('click', kill);
      setTimeout(kill, ms);
    }

    // ====== Estado / Controles ======
    const state = { rows:[], sortKey:'ip', sortDir:'asc', filter:'', onlyLow:false, threshold:10 };

    const listmode = document.getElementById('listmode');
    const singleInputs = document.getElementById('singleInputs');
    const listInputs = document.getElementById('listInputs');
    listmode.addEventListener('change', ()=>{
      const on = listmode.checked;
      singleInputs.style.display = on ? 'none' : 'flex';
      listInputs.style.display   = on ? 'flex' : 'none';
    });

    const cbLow = document.getElementById('onlyLow');
    const selTh = document.getElementById('threshold');
    cbLow.addEventListener('change', ()=>{ state.onlyLow = !!cbLow.checked; renderTable(); });
    selTh.addEventListener('change', ()=>{
      const v = parseInt(selTh.value, 10);
      state.threshold = isNaN(v) ? 10 : v;
      renderTable();
    });

    // ====== Helpers de render ======
    function valueHTML(item){
      if(!item) return '';
      if(item.status){
        const good = String(item.status).toLowerCase()==='ok';
        return `<span class="pill ${good?'ok':'bad'}">${item.status}</span>`;
      }
      const p = (typeof item.percent==='number' && item.percent>=0) ? item.percent : -1;
      if(p<0) return '';
      const w = Math.max(0, Math.min(100, p));
      const badge = (p <= 10) ? `<span class="badge alert">ALERT</span>` : '';
      return `<div class="muted" style="margin-bottom:4px;display:flex;gap:8px;align-items:center">
                ${p.toFixed(1)}% ${badge}
              </div>
              <div class="bar"><div style="width:${w}%;background:${pctColor(p)}"></div></div>`;
    }
    function pickBest(items, category){
      const arr = items.filter(it => it.category === category);
      if(!arr.length) return null;
      return arr.slice().sort((a,b)=>{
        const pa = (typeof a.percent==='number')?a.percent:-1;
        const pb = (typeof b.percent==='number')?b.percent:-1;
        return pb-pa;
      })[0];
    }

    const COLS = [
      {key:'ip', label:'IP'},
      {key:'printer', label:'Printer'},
      {key:'model', label:'Model'},
      {key:'black', label:'Black Impressions'},
      {key:'toner', label:'Toner'},
      {key:'drum', label:'Drum/Imaging Unit'},
      {key:'tr_r7', label:'Transfer Roller R7'},
      {key:'fuser', label:'Fuser R8'},
      {key:'waste', label:'Waste Toner Container'},
      {key:'beltcl', label:'Transfer Belt Cleaner'},
      {key:'sbtr', label:'Second Bias Transfer Roll'}
    ];

    function headerHTML(sortKey, sortDir){
      return `<thead><tr>${
        COLS.map(c=>{
          const arrow = (sortKey===c.key) ? (sortDir==='asc'?'▲':'▼') : '';
          return `<th data-key="${c.key}">${c.label}<span class="sort">${arrow}</span></th>`;
        }).join('')
      }</tr></thead>`;
    }

    function pivotRowHTML(d){
      const items = d.items || [];
      const model = (d.model||'').toUpperCase();
      if(model==='C415') return '';

      const toner   = pickBest(items,'toner');
      const drum    = pickBest(items,'drum');
      const tr      = pickBest(items,'transfer_roller');
      const fuser   = pickBest(items,'fuser');
      const waste   = pickBest(items,'waste_toner');
      const beltcl  = pickBest(items,'belt_cleaner');

      let trR7 = null, sbtr = null;
      if(tr){ if(model==='B8155') sbtr = tr; else trR7 = tr; }

      let bi = 'N/A';
      if(typeof d.black_impressions === 'number' && d.black_impressions >= 0){
        try{ bi = Number(d.black_impressions).toLocaleString(); }
        catch(e){ bi = String(d.black_impressions); }
      }

      return `<tr>
        <td class="nowrap">${d.ip||''}</td>
        <td>${(d.printer_name||'').trim()||'(unnamed)'}</td>
        <td class="nowrap">${d.model||''}</td>
        <td class="nowrap">${bi}</td>
        <td>${valueHTML(toner)}</td>
        <td>${valueHTML(drum)}</td>
        <td>${valueHTML(trR7)}</td>
        <td>${valueHTML(fuser)}</td>
        <td>${valueHTML(waste)}</td>
        <td>${valueHTML(beltcl)}</td>
        <td>${valueHTML(sbtr)}</td>
      </tr>`;
    }

    function tableHTML(rowsHTML, sortKey, sortDir){
      const thead = headerHTML(sortKey, sortDir);
      const tbody = `<tbody>${rowsHTML}</tbody>`;
      return `<div class="tableWrap"><table>${thead}${tbody}</table></div>`;
    }

    function pctBar(p){
      if(!(typeof p==='number') || p<0) return '';
      const w = Math.max(0, Math.min(100, p));
      return `<div class="muted" style="margin-bottom:4px">${p.toFixed(1)}%</div>
              <div class="bar"><div style="width:${w}%;background:${pctColor(p)}"></div></div>`;
    }
    function cmykRow(title, m){
      const order = ["K","C","M","Y"].filter(k => Object.prototype.hasOwnProperty.call(m,k));
      if(!order.length) return '';
      const nameMap = (title === 'Toner') ? { K: 'Black' } : {};
      const cells = order.map(k=>{
        const tag = nameMap[k] || k;
        return `<div class="metric"><div class="label">${title} ${tag}</div>${pctBar(m[k])}</div>`;
      }).join('');
      return `<div class="kv">${cells}</div>`;
    }
    function c415CardHTML(d){
      if(!d || String(d.model).toUpperCase()!=='C415') return '';
      const c = d.c415 || {};
      const t = c.toner || {};
      const drum = c.drum || {};
      const waste = (typeof c.waste_toner==='number' && c.waste_toner>=0) ? pctBar(c.waste_toner) : '';
      const beltcl = (typeof c.belt_cleaner==='number' && c.belt_cleaner>=0) ? pctBar(c.belt_cleaner) : '';
      const belt = (typeof c.transfer_belt==='number' && c.transfer_belt>=0) ? pctBar(c.transfer_belt) : '';
      const tr = (typeof c.transfer_roller==='number' && c.transfer_roller>=0) ? pctBar(c.transfer_roller) : '';

      let bi = 'N/A';
      if(typeof d.black_impressions === 'number' && d.black_impressions >= 0){
        try{ bi = Number(d.black_impressions).toLocaleString(); } catch(e){ bi = String(d.black_impressions); }
      }

      return `
        <div class="c415-card">
          <div style="font-weight:800; font-size:16px">${d.printer_name || '(unnamed)'} — ${d.ip} <span class="muted">[C415]</span></div>
          <div class="muted" style="margin:4px 0 10px">Black Impressions: <strong>${bi}</strong></div>
          ${cmykRow('Toner', t)}
          ${cmykRow('Drum', drum)}
          <div class="kv">
            ${waste?`<div class="metric"><div class="label">Waste Toner Container</div>${waste}</div>`:''}
            ${beltcl?`<div class="metric"><div class="label">Transfer Belt Cleaner</div>${beltcl}</div>`:''}
            ${belt?`<div class="metric"><div class="label">Transfer Belt</div>${belt}</div>`:''}
            ${tr?`<div class="metric"><div class="label">Transfer Roller</div>${tr}</div>`:''}
          </div>
        </div>
      `;
    }

    function metricSortValue(item){
      if(!item) return -1;
      if(item.status){
        return String(item.status).toLowerCase()==='ok' ? 100 : -1;
      }
      const p = (typeof item.percent==='number' && item.percent>=0) ? item.percent : -1;
      return p;
    }

    function buildRow(d){
      const items = d.items || [];
      const model = (d.model||'').toUpperCase();
      const toner   = pickBest(items,'toner');
      const drum    = pickBest(items,'drum');
      const tr      = pickBest(items,'transfer_roller');
      const fuser   = pickBest(items,'fuser');
      const waste   = pickBest(items,'waste_toner');
      const beltcl  = pickBest(items,'belt_cleaner');

      let trR7 = null, sbtr = null;
      if(tr){ if(model==='B8155') sbtr = tr; else trR7 = tr; }

      const bi = (typeof d.black_impressions === 'number' && d.black_impressions >= 0) ? d.black_impressions : -1;

      return {
        raw: d,
        sort: {
          ip: (d.ip||'').toLowerCase(),
          printer: (d.printer_name||'').toLowerCase(),
          model: (d.model||'').toLowerCase(),
          black: bi,
          toner: metricSortValue(toner),
          drum: metricSortValue(drum),
          tr_r7: metricSortValue(trR7),
          fuser: metricSortValue(fuser),
          waste: metricSortValue(waste),
          beltcl: metricSortValue(beltcl),
          sbtr: metricSortValue(sbtr),
        }
      };
    }

    function rowIsBelowThreshold(d){
      const items = d.items || [];
      const KEYS = ['toner','drum','transfer_roller','fuser','waste_toner','belt_cleaner'];
      const T = Number(state.threshold) || 10;
      for(const k of KEYS){
        const it = pickBest(items, k);
        if(it && typeof it.percent==='number' && it.percent>=0 && it.percent <= T){
          return true;
        }
      }
      return false;
    }

    function filteredRows(){
      const f = state.filter.trim().toLowerCase();
      let rows = state.rows;
      if(f){
        rows = rows.filter(r=> r.sort.ip.includes(f) || r.sort.printer.includes(f) || r.sort.model.includes(f));
      }
      if(state.onlyLow){
        rows = rows.filter(r => rowIsBelowThreshold(r.raw));
      }
      return rows;
    }

    function sortedRows(rows){
      const k = state.sortKey;
      const dir = state.sortDir === 'asc' ? 1 : -1;
      return rows.slice().sort((a,b)=>{
        const va = a.sort[k], vb = b.sort[k];
        if(typeof va === 'string' || typeof vb === 'string'){
          return String(va).localeCompare(String(vb)) * dir;
        }
        return ((va||0) - (vb||0)) * dir;
      });
    }

    function renderTable(){
      const out=document.getElementById('out');
      const rows1 = filteredRows();
      const rows2 = sortedRows(rows1);

      if(!rows2.length){
        out.className='empty';
        out.innerHTML = 'No data yet. Run a query to see results.';
        return;
      }

      const htmlRows = rows2.map(r=>pivotRowHTML(r.raw)).join('');
      out.className='';
      out.innerHTML = tableHTML(htmlRows, state.sortKey, state.sortDir);

      const ths = out.querySelectorAll('thead th');
      ths.forEach(th=>{
        th.addEventListener('click', ()=>{
          const key = th.getAttribute('data-key');
          if(!key) return;
          if(state.sortKey===key){
            state.sortDir = (state.sortDir==='asc')?'desc':'asc';
          }else{
            state.sortKey = key;
            state.sortDir = (key==='ip' || key==='printer' || key==='model') ? 'asc' : 'desc';
          }
          renderTable();
        });
      });
    }

    document.getElementById('filter').addEventListener('input', (e)=>{
      state.filter = e.target.value || '';
      renderTable();
    });

    async function q(url){
  try {
    const r = await fetch(url);
    return await r.json();
  } catch(e) {
    console.error(e);
    return {error:'Network error'};
  }
}


    function buildQS(extra){ const p = new URLSearchParams({...extra}); return p.toString(); }

document.getElementById('f').addEventListener('submit', async (e)=>{
  e.preventDefault();

  // 🔹 Eliminar mensajes previos de "Completed ..."
  document.querySelectorAll('.query-status-msg').forEach(el => el.remove());

  // === Crear barra de progreso con spinner + contador ===
  const wrap = document.createElement('div');
  wrap.className = 'query-status-msg'; // <-- identificador para limpiarlo luego
  wrap.style.cssText = 'margin-top:10px;text-align:center;font-weight:700;color:#0f172a;font-size:13px;display:flex;flex-direction:column;align-items:center;gap:6px;';

  const topRow = document.createElement('div');
  topRow.style.cssText = 'display:flex;align-items:center;gap:8px;';

  const spinner = document.createElement('div');
  spinner.style.cssText = 'width:16px;height:16px;border:3px solid #cbd5e1;border-top-color:#2563eb;border-radius:50%;animation:spin .8s linear infinite;';
  const keyframes = document.createElement('style');
  keyframes.textContent = '@keyframes spin{to{transform:rotate(360deg)}}';
  if (!document.head.querySelector('style[data-spin]')) {
    keyframes.setAttribute('data-spin','1');
    document.head.appendChild(keyframes);
  }

  const label = document.createElement('div');
  label.textContent = 'Starting query...';
  topRow.appendChild(spinner);
  topRow.appendChild(label);

  const bar = document.createElement('div');
  bar.style.cssText = 'width:100%;background:#e2e8f0;border-radius:10px;overflow:hidden;box-shadow:inset 0 1px 3px rgba(0,0,0,.1)';
  const inner = document.createElement('div');
  inner.style.cssText = 'height:10px;width:0;background:#2563eb;transition:width .15s ease';
  bar.appendChild(inner);

  wrap.appendChild(topRow);
  wrap.appendChild(bar);
  document.querySelector('.sticky-card').appendChild(wrap);

  // === Determinar impresoras totales ===
  let total = 1;
  let ips = [];
  if (listmode.checked) {
    const ipsTxt = document.getElementById('ips').value || '';
    ips = ipsTxt.split(/[,\n\r\t\s]+/).map(s=>s.trim()).filter(Boolean);
    total = ips.length;
    if (!total) { showToast('Enter at least one IP.','error'); wrap.remove(); return; }
  } else {
    const ip = document.getElementById('ip').value.trim();
    if (!ip) { showToast('Enter an IP.','error'); wrap.remove(); return; }
    ips = [ip];
  }

  let pct = 0;
  const anim = setInterval(()=>{
    if (pct < 95) pct = Math.min(95, pct + Math.random() * 5);
    inner.style.width = pct + '%';
    label.textContent = `Querying ${ips.length > 1 ? ips.length + ' printers' : 'printer'}... ${Math.round(pct)}%`;
  }, 400);

  try {
    let data;
    if (listmode.checked) {
      const qs = buildQS({ ips: ips.join(',') });
      data = await q(`/api/supplies_list?${qs}`);
    } else {
      const qs = buildQS({ ip: ips[0] });
      data = await q(`/api/supplies?${qs}`);
    }

    // === Finalización ===
    clearInterval(anim);
    spinner.remove();
    inner.style.width = '100%';
    label.textContent = `✅ Completed ${ips.length} ${ips.length===1?'printer':'printers'} successfully`;

    bar.remove();
    wrap.style.marginTop = '12px';
    wrap.style.fontSize = '14px';
    wrap.style.color = '#166534'; // verde

    if (data.error) { showToast(data.error, 'error'); return; }
    prepare(data);

  } catch(err) {
    clearInterval(anim);
    wrap.remove();
    showToast('Query failed','error');
  }
});



    function prepare(data){
      const arr = Array.isArray(data.results) ? data.results : [data];
      const main = arr.filter(d => String(d.model||'').toUpperCase()!=='C415');
      state.rows = main.map(buildRow);
      renderTable();
      const cards = arr.filter(d=>String(d.model||'').toUpperCase()==='C415').map(c415CardHTML).join('');
      document.getElementById('extras').innerHTML = cards ? `<div class="section-title" style="margin-top:18px">C415 Details</div>${cards}` : '';
    }

    // Export con verificación y toast
    document.getElementById('btnXLSX').addEventListener('click', ()=>{
      if (!state.rows || state.rows.length === 0) { showToast('Run a query first.','warn'); return; }
      const visible = filteredRows();
      if (!visible || visible.length === 0) { showToast('No data to export','warn'); return; }

      const pct_max = state.onlyLow ? state.threshold : '';
      const text = state.filter || '';

      if (listmode.checked) {
        const ipsTxt = document.getElementById('ips').value||'';
        const ips = ipsTxt.split(/[,\n\r\t\s]+/).map(s=>s.trim()).filter(Boolean);
        if(!ips.length){ showToast('Enter at least one IP.','error'); return; }
        const qs = new URLSearchParams({ips: ips.join(','), pct_max, text}).toString();
        window.location = `/api/export_xlsx_list_pivot?${qs}`;
      } else {
        const ip = (document.getElementById('ip').value||'').trim();
        if(!ip){ showToast('Enter an IP.','error'); return; }
        const qs = new URLSearchParams({ip, pct_max, text}).toString();
        window.location = `/api/export_xlsx_pivot?${qs}`;
      }
    });
  </script>
</body>
</html>
'''
    return html.replace("__USER_MENU__", user_menu)


# ---------------------- JSON API (web) --------------------
def _parse_ips_param() -> List[str]:
    raw = request.args.get("ips", "") or ""
    ips = [p.strip() for p in raw.replace("\r", "\n").replace(",", "\n").split("\n")]
    return [p for p in ips if p]

def _get_timeout_param() -> int:
    # UI no expone timeout; backend mantiene default
    return _parse_int(request.args.get("timeout"), TIMEOUT_DEFAULT)

@app.get("/api/supplies")
@login_required("api_supplies")
def api_supplies():
    ip = request.args.get("ip")
    if not ip: return jsonify({"error": "Missing 'ip' parameter"}), 400
    community = request.args.get("community", DEFAULT_COMMUNITY)
    timeout = _get_timeout_param()
    try:
        data = get_cached(ip, community, timeout, TTL_DEFAULT)
        return jsonify(data)
    except Exception as e:
        return jsonify({"ip": ip, "error": str(e)}), 500

@app.get("/api/supplies_list")
@login_required("api_supplies_list")
def api_supplies_list():
    import threading

    ips = _parse_ips_param()
    if not ips:
        return jsonify({"error": "Missing 'ips' parameter with at least one IP"}), 400

    community = request.args.get("community", DEFAULT_COMMUNITY)
    timeout = _get_timeout_param()
    results = []
    threads = []

    # Función interna para procesar una impresora
    def worker(ip):
        try:
            data = get_cached(ip, community, timeout, TTL_DEFAULT)
            results.append(data)
        except Exception as e:
            print(f"[THREAD ERROR] {ip}: {e}")
            results.append({"ip": ip, "error": str(e)})

    # Crear y lanzar un hilo por IP
    for ip in ips:
        t = threading.Thread(target=worker, args=(ip,), daemon=True)
        threads.append(t)
        t.start()

    # Esperar que todos terminen
    for t in threads:
        t.join()

    return jsonify({"results": results})


# ---------------------- Export XLSX -----------------
CSV_HEADERS = [
    "IP","Printer","Model","Black Impressions",
    "Toner","Drum/Imaging Unit",
    "Transfer Roller R7","Fuser R8",
    "Waste Toner Container","Transfer Belt Cleaner",
    "Second Bias Transfer Roll",
    "Exported At"
]

def _pick_best(items: List[Dict[str, Any]], category: str) -> Dict[str, Any]:
    cands = [it for it in items if it.get("category") == category]
    if not cands: return {}
    return max(cands, key=lambda it: (it.get("percent") if isinstance(it.get("percent"), (int, float)) else -1))

def pivot_row_for_xlsx(data: Dict[str, Any], exported_at: str) -> List[Any] | None:
    model = (data.get("model") or "").upper()
    if model == "C415":
        return None
    items = data.get("items", [])

    tr_item    = _pick_best(items, "transfer_roller")
    fuser_item = _pick_best(items, "fuser")
    toner_item = _pick_best(items, "toner")
    drum_item  = _pick_best(items, "drum")
    waste_item = _pick_best(items, "waste_toner")
    beltcl_it  = _pick_best(items, "belt_cleaner")

    def pct_num(it):
        if not it: return None
        if "status" in it and it["status"]:
            return it["status"]
        p = it.get("percent")
        if isinstance(p, (int, float)) and p >= 0:
            return float(p) / 100.0
        return None

    bi = data.get("black_impressions")
    bi_val = bi if isinstance(bi, int) and bi >= 0 else None

    tr_r7 = None
    sbtr  = None
    if tr_item:
        if model == "B8155": sbtr = pct_num(tr_item)
        else: tr_r7 = pct_num(tr_item)

    return [
        data.get("ip",""),
        data.get("printer_name",""),
        data.get("model",""),
        bi_val,
        pct_num(toner_item),
        pct_num(drum_item),
        tr_r7,
        pct_num(fuser_item),
        pct_num(waste_item),
        pct_num(beltcl_it),
        sbtr,
        exported_at
    ]

def _xlsx_apply_styles(ws):
    header_fill = PatternFill("solid", fgColor="F3F3F3")
    bold = Font(bold=True)
    thin = Side(style="thin", color="DDDDDD")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)
    for col, title in enumerate(CSV_HEADERS, start=1):
        c = ws.cell(row=1, column=col, value=title)
        c.fill = header_fill; c.font = bold; c.alignment = Alignment(vertical="center"); c.border = border
    widths = [14, 22, 24, 18, 12, 16, 20, 14, 22, 22, 26, 20]
    for i, w in enumerate(widths, start=1):
        ws.column_dimensions[get_column_letter(i)].width = w

def _xlsx_apply_grid(ws, start_row, start_col, end_row, end_col):
    thin = Side(style="thin", color="DDDDDD")
    medium = Side(style="medium", color="AAAAAA")
    for r in range(start_row, end_row+1):
        for c in range(start_col, end_col+1):
            left   = medium if c == start_col else thin
            right  = medium if c == end_col   else thin
            top    = medium if r == start_row else thin
            bottom = medium if r == end_row   else thin
            cell = ws.cell(row=r, column=c)
            cell.border = Border(left=left, right=right, top=top, bottom=bottom)

def _xlsx_format_body(ws, nrows):
    # EVITA aplicar formatos cuando no hay filas de datos
    if nrows < 2:
        return
    for r in range(2, nrows+1):
        ws.cell(row=r, column=4).number_format = '#,##0'
    for r in range(2, nrows+1):
        ws.cell(row=r, column=4).number_format = '#,##0'
    for c in range(5, 12):
        for r in range(2, nrows+1):
            cell = ws.cell(row=r, column=c)
            if isinstance(cell.value, float):
                cell.number_format = '0%'

    green = Color(rgb="FF63BE7B")
    for c in range(5, 12):
        col_letter = get_column_letter(c)
        rng = f"{col_letter}2:{col_letter}{nrows}"
        ws.conditional_formatting.add(rng, DataBarRule(start_type="num", start_value=0, end_type="num", end_value=1, color=green, showValue=True))

    ok_fill  = PatternFill("solid", fgColor="E7F7EE")
    bad_fill = PatternFill("solid", fgColor="FDECEA")
    ws.conditional_formatting.add(f"G2:G{nrows}", CellIsRule(operator='equal', formula=['\"OK\"'], stopIfTrue=True, fill=ok_fill))
    ws.conditional_formatting.add(f"G2:G{nrows}", CellIsRule(operator='equal', formula=['\"Past end of life\"'], stopIfTrue=True, fill=bad_fill))
    ws.conditional_formatting.add(f"H2:H{nrows}", CellIsRule(operator='equal', formula=['\"OK\"'], stopIfTrue=True, fill=ok_fill))
    ws.conditional_formatting.add(f"H2:H{nrows}", CellIsRule(operator='equal', formula=['\"Past end of life\"'], stopIfTrue=True, fill=bad_fill))

    # sombreado warn/alert (independiente del UI)
    warn_fill  = PatternFill("solid", fgColor="FFF7ED")
    alert_fill = PatternFill("solid", fgColor="FEF2F2")
    for c in range(5, 12):
        col_letter = get_column_letter(c)
        rng = f"{col_letter}2:{col_letter}{nrows}"
        ws.conditional_formatting.add(rng, CellIsRule(operator='lessThanOrEqual', formula=[str(XLSX_ALERT_FRAC)], stopIfTrue=False, fill=alert_fill))
        ws.conditional_formatting.add(rng, CellIsRule(operator='lessThanOrEqual', formula=[str(XLSX_WARN_FRAC)],  stopIfTrue=False, fill=warn_fill))

    _xlsx_apply_grid(ws, 1, 1, nrows, len(CSV_HEADERS))

# ---------- Extra sheet: C415 Details ----------
def _xlsx_apply_styles_c415(ws, headers):
    header_fill = PatternFill("solid", fgColor="F3F3F3")
    bold = Font(bold=True)
    for col, title in enumerate(headers, start=1):
        c = ws.cell(row=1, column=col, value=title)
        c.fill = header_fill; c.font = bold; c.alignment = Alignment(vertical="center")
    widths = [14, 22, 10, 18] + [12]*12 + [20]
    for i, w in enumerate(widths[:len(headers)], start=1):
        ws.column_dimensions[get_column_letter(i)].width = w

def _add_c415_sheet(wb: Workbook, datas: List[Dict[str, Any]], exported_at: str):
    rows = [d for d in datas if (d.get("model") or "").upper() == "C415"]
    if not rows: return
    ws = wb.create_sheet(title="C415 Details")
    HEAD = [
        "IP","Printer","Model","Black Impressions",
        "Toner Black","Toner C","Toner M","Toner Y",
        "Drum K","Drum C","Drum M","Drum Y",
        "Waste Toner","Transfer Belt Cleaner","Transfer Belt","Transfer Roller",
        "Exported At"
    ]
    _xlsx_apply_styles_c415(ws, HEAD)

    rcount = 1
    def frac(v):
        try: v = float(v); return None if v < 0 else v/100.0
        except Exception: return None

    for d in rows:
        c = d.get("c415", {}) or {}
        t = c.get("toner", {}) or {}
        dr = c.get("drum", {}) or {}
        bi = d.get("black_impressions")
        bi_val = bi if isinstance(bi, int) and bi >= 0 else None

        row = [
            d.get("ip",""), d.get("printer_name",""), d.get("model",""), bi_val,
            frac(t.get("K", -1)), frac(t.get("C", -1)), frac(t.get("M", -1)), frac(t.get("Y", -1)),
            frac(dr.get("K", -1)), frac(dr.get("C", -1)), frac(dr.get("M", -1)), frac(dr.get("Y", -1)),
            frac(c.get("waste_toner", -1)),
            frac(c.get("belt_cleaner", -1)),
            frac(c.get("transfer_belt", -1)),
            frac(c.get("transfer_roller", -1)),
            exported_at
        ]
        ws.append(row); rcount += 1

    for r in range(2, rcount+1):
        ws.cell(row=r, column=4).number_format = '#,##0'
        for c in range(5, 17):
            cell = ws.cell(row=r, column=c)
            if isinstance(cell.value, float):
                cell.number_format = '0%'

    green = Color(rgb="FF63BE7B")
    for c in range(5, 17):
        col_letter = get_column_letter(c)
        rng = f"{col_letter}2:{col_letter}{rcount}"
        ws.conditional_formatting.add(rng, DataBarRule(start_type="num", start_value=0, end_type="num", end_value=1, color=green, showValue=True))

    warn_fill  = PatternFill("solid", fgColor="FFF7ED")
    alert_fill = PatternFill("solid", fgColor="FEF2F2")
    for c in range(5, 17):
        col_letter = get_column_letter(c)
        rng = f"{col_letter}2:{col_letter}{rcount}"
        ws.conditional_formatting.add(rng, CellIsRule(operator='lessThanOrEqual', formula=[str(XLSX_ALERT_FRAC)], stopIfTrue=False, fill=alert_fill))
        ws.conditional_formatting.add(rng, CellIsRule(operator='lessThanOrEqual', formula=[str(XLSX_WARN_FRAC)],  stopIfTrue=False, fill=warn_fill))

    _xlsx_apply_grid(ws, 1, 1, rcount, len(HEAD))

# --- Helpers para filtrar export ---
EXPORT_KEYS = ['toner','drum','transfer_roller','fuser','waste_toner','belt_cleaner']

def _any_metric_leq_pct(items: List[Dict[str, Any]], pct_max: float) -> bool:
    for k in EXPORT_KEYS:
        cand = _pick_best(items, k)
        if not cand:
            continue
        p = cand.get("percent")
        if isinstance(p, (int, float)) and p >= 0 and p <= pct_max:
            return True
        if k in ('fuser','transfer_roller') and isinstance(cand.get("status"), str):
            if cand["status"].lower() != "ok":
                return True
    return False

def _row_matches_filters(data: Dict[str, Any], pct_max: Optional[float], text: str) -> bool:
    ip = (data.get("ip") or "").lower()
    printer = (data.get("printer_name") or "").lower()
    model = (data.get("model") or "").lower()
    if text:
        t = text.lower().strip()
        if t and not (t in ip or t in printer or t in model):
            return False
    if pct_max is not None:
        items = data.get("items") or []
        if not _any_metric_leq_pct(items, pct_max):
            return False
    return True

def _parse_pct_max_arg(arg_val: Optional[str]) -> Optional[float]:
    if arg_val is None:
        return None
    s = str(arg_val).strip()
    if not s:
        return None
    try:
        v = float(s)
        if v < 0: v = 0.0
        if v > 100: v = 100.0
        return v
    except Exception:
        return None

@app.get("/api/export_xlsx_pivot")
@login_required("export_xlsx_pivot")
def export_xlsx_pivot():
    ip = request.args.get("ip")
    if not ip: return jsonify({"error": "Missing 'ip' parameter"}), 400
    community = request.args.get("community", DEFAULT_COMMUNITY)
    timeout = _get_timeout_param()

    # filtros recibidos
    pct_max = _parse_pct_max_arg(request.args.get("pct_max"))
    text = (request.args.get("text") or "").strip()

    data = get_cached(ip, community, timeout, TTL_DEFAULT)

    exported_at = datetime.now().strftime("%Y-%m-%d %H:%M")
    fname_stamp = datetime.now().strftime("%Y%m%d-%H%M")

    wb = Workbook()
    ws = wb.active; ws.title = "Supplies"
    _xlsx_apply_styles(ws)

    if _row_matches_filters(data, pct_max, text):
        row = pivot_row_for_xlsx(data, exported_at)
        if row: ws.append(row)

    _xlsx_format_body(ws, nrows=ws.max_row)



    # Hoja C415: aplica mismo filtro por consistencia
    if _row_matches_filters(data, pct_max, text):
        _add_c415_sheet(wb, [data], exported_at)

    bio = io.BytesIO(); wb.save(bio); bio.seek(0)
    fname = f"xerox_supplies_{ip.replace('.', '-')}_{fname_stamp}.xlsx"
    headers = {"Content-Type":"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
               "Content-Disposition":f'attachment; filename="{fname}"'}
    return Response(bio.getvalue(), headers=headers)

@app.get("/api/export_xlsx_list_pivot")
@login_required("export_xlsx_list_pivot")
def export_xlsx_list_pivot():
    ips = _parse_ips_param()
    if not ips: return jsonify({"error": "Missing 'ips' parameter with at least one IP"}), 400
    community = request.args.get("community", DEFAULT_COMMUNITY)
    timeout = _get_timeout_param()

    # filtros recibidos
    pct_max = _parse_pct_max_arg(request.args.get("pct_max"))
    text = (request.args.get("text") or "").strip()

    exported_at = datetime.now().strftime("%Y-%m-%d %H:%M")
    fname_stamp = datetime.now().strftime("%Y%m%d-%H%M")

    wb = Workbook()
    ws = wb.active; ws.title = "Supplies"
    _xlsx_apply_styles(ws)

    all_data = []
    for ip in ips:
        d = get_cached(ip, community, timeout, TTL_DEFAULT)
        if _row_matches_filters(d, pct_max, text):
            all_data.append(d)
            row = pivot_row_for_xlsx(d, exported_at)
            if row: ws.append(row)

    _xlsx_format_body(ws, nrows=ws.max_row)


    _add_c415_sheet(wb, all_data, exported_at)

    bio = io.BytesIO(); wb.save(bio); bio.seek(0)
    fname = f"xerox_supplies_list_{fname_stamp}.xlsx"
    headers = {"Content-Type":"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
               "Content-Disposition":f'attachment; filename="{fname}"'}
    return Response(bio.getvalue(), headers=headers)

# --------------------- Diagnostics ------------------------
@app.get("/api/dump_supplies")
@login_required("api_dump_supplies")
def api_dump_supplies():
    ip = request.args.get("ip")
    if not ip: return jsonify({"error": "Missing 'ip' parameter"}), 400
    community = request.args.get("community", DEFAULT_COMMUNITY)
    timeout = _get_timeout_param()
    try:
        model = _snmp_get_model(ip, community, timeout)
        descs  = _snmp_column_map(ip, community, DESC_BASE,  timeout=timeout)
        maxs   = _snmp_column_map(ip, community, MAX_BASE,   timeout=timeout)
        levels = _snmp_column_map(ip, community, LEVEL_BASE, timeout=timeout)

        rows = []
        for idx in sorted(set(descs) | set(maxs) | set(levels), key=lambda x: int(x)):
            desc = descs.get(idx) or ""
            pct  = _safe_pct(levels.get(idx), maxs.get(idx))
            rows.append({
                "index": int(idx),
                "desc": desc,
                "category": _categorize(desc),
                "level": levels.get(idx),
                "max": maxs.get(idx),
                "percent": pct
            })
        return jsonify({"ip": ip, "model": model, "rows": rows})
    except Exception as e:
        return jsonify({"ip": ip, "error": str(e)}), 500

@app.get("/api/debug")
@login_required("api_debug")
def api_debug():
    ip = request.args.get("ip")
    if not ip: return jsonify({"error": "Missing 'ip' parameter"}), 400
    community = request.args.get("community", DEFAULT_COMMUNITY)
    timeout = _get_timeout_param()
    try:
        sys_descr = _snmp_get(ip, community, SYS_DESCR, timeout)
        prt_name  = _snmp_get(ip, community, PRT_NAME, timeout)
        sys_name  = _snmp_get(ip, community, SYS_NAME, timeout)
        name = prt_name or sys_name
        model = _snmp_get_model(ip, community, timeout)
        descs  = _snmp_column_map(ip, community, DESC_BASE,  timeout=timeout)
        maxs   = _snmp_column_map(ip, community, MAX_BASE,   timeout=timeout)
        levels = _snmp_column_map(ip, community, LEVEL_BASE, timeout=timeout)
        sample = []
        for idx in sorted(set(list(descs)[:5] + list(maxs)[:5] + list(levels)[:5]), key=lambda x: int(x)):
            sample.append({"index": int(idx), "desc": descs.get(idx), "max": maxs.get(idx), "level": levels.get(idx)})
        black_impr = _get_black_impressions(ip, community, timeout)
        return jsonify({
            "ip": ip, "community_used": community, "model": model,
            "printer_name": name, "sys_name": sys_name, "sys_descr": sys_descr,
            "counts": {"descs": len(descs), "maxs": len(maxs), "levels": len(levels)},
            "sample_rows": sample, "black_impressions": black_impr
        })
    except Exception as e:
        return jsonify({"ip": ip, "community_used": community, "error": str(e)}), 500

@app.get("/healthz")
def healthz():
    return jsonify({"ok": True})

# -------------------------- main --------------------------
if __name__ == "__main__":
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=True)
