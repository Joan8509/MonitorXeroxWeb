import os, re, time
from typing import Any, Dict, List, Tuple
from puresnmp import walk, get as snmp_get

# ------------------- CONFIG --------------------
DEFAULT_COMMUNITY = os.getenv("SNMP_COMMUNITY", "public")
TIMEOUT_DEFAULT = int(os.getenv("TIMEOUT_DEFAULT", "3"))
TTL_DEFAULT = int(os.getenv("TTL_DEFAULT", "15"))

# ------------------- OIDs ----------------------
DESC_BASE   = "1.3.6.1.2.1.43.11.1.1.6"
MAX_BASE    = "1.3.6.1.2.1.43.11.1.1.8"
LEVEL_BASE  = "1.3.6.1.2.1.43.11.1.1.9"
PRT_NAME    = "1.3.6.1.2.1.43.5.1.1.16.1"
SYS_NAME    = "1.3.6.1.2.1.1.5.0"
SYS_DESCR   = "1.3.6.1.2.1.1.1.0"
PRT_MARKER_LIFECOUNT = "1.3.6.1.2.1.43.10.2.1.4"
PRT_ALERT_DESC       = "1.3.6.1.2.1.43.18.1.1.8"

# ------------------- SNMP Helpers ---------------
def _decode(v: Any) -> Any:
    if isinstance(v, bytes):
        try:
            return v.decode(errors="ignore")
        except Exception:
            return str(v)
    return v

def _snmp_get(host: str, community: str, oid: str, timeout: int):
    try:
        val = _decode(snmp_get(host, community, oid, timeout=timeout))
        return (str(val) if val is not None else "").strip()
    except Exception:
        return ""

def _snmp_get_name(host: str, community: str, timeout: int) -> str:
    name = _snmp_get(host, community, PRT_NAME, timeout)
    return name or _snmp_get(host, community, SYS_NAME, timeout)

def _snmp_get_model(host: str, community: str, timeout: int) -> str:
    sysd = _snmp_get(host, community, SYS_DESCR, timeout)
    prtn = _snmp_get(host, community, PRT_NAME, timeout)
    cand = f"{(sysd or '').lower()} {(prtn or '').lower()}"
    for token in ("b8155", "b7135", "b415", "c415"):
        if token in cand:
            return token.upper()
    return ""

def _snmp_column_map(host: str, community: str, base_oid: str, timeout: int = TIMEOUT_DEFAULT):
    out: Dict[str, Any] = {}
    for vb_oid, vb_value in walk(host, community, base_oid, timeout=timeout):
        idx = str(vb_oid).split(".")[-1]
        out[idx] = _decode(vb_value)
    return out

def _safe_pct(level: Any, maxcap: Any) -> float:
    try:
        level = int(level)
        maxcap = int(maxcap)
    except Exception:
        return -1
    if level < 0 or maxcap <= 0:
        return -1
    return round(100.0 * level / maxcap, 1)

def _get_black_impressions(host: str, community: str, timeout: int) -> int:
    counts: List[int] = []
    try:
        for _, val in walk(host, community, PRT_MARKER_LIFECOUNT, timeout=timeout):
            try:
                counts.append(int(_decode(val)))
            except Exception:
                continue
    except Exception:
        return -1
    if not counts:
        return -1
    pos = [c for c in counts if c >= 0]
    return max(pos) if pos else -1

# ------------------- CATEGORIZACIÓN ----------------------
def _categorize(desc: str) -> str:
    d = (desc or "").lower()
    if any(k in d for k in ("waste toner","waste container","waste bottle","collection","residuo","residual")):
        return "waste_toner"
    if "r8" in d or "fuser" in d:
        return "fuser"
    if any(k in d for k in ("r7","secondary transfer","second bias","sbtr","transfer roll","transfer roller")):
        return "transfer_roller"
    if "clean" in d and "belt" in d:
        return "belt_cleaner"
    if ("belt" in d and "transfer" in d) or "ibt" in d or "r6" in d:
        return "transfer_belt"
    if "imaging" in d or "drum" in d:
        return "drum"
    if "toner" in d or "cartridge" in d or "cartucho" in d:
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

# ------------------- FALLBACK % ----------------------
def _fallback_pct_if_raw_percent(category: str, level: Any, maxcap: Any, desc: str = "") -> float:
    p = _safe_pct(level, maxcap)
    if isinstance(p, (int, float)) and p >= 0:
        return p
    if category in ("waste_toner", "toner"):
        try:
            lv = int(level)
        except Exception:
            lv = None
        try:
            mx = int(maxcap)
        except Exception:
            mx = None
        if lv is not None and (mx is None or mx <= 0) and 0 <= lv <= 100:
            return float(lv)
    return -1

# ------------------- FETCH GENÉRICO ----------------------
CACHE: Dict[Tuple[str, str, int], Tuple[float, Dict[str, Any]]] = {}

def get_cached(ip: str, community: str, timeout: int, ttl: int):
    """Devuelve los datos cacheados por TTL"""
    key = (ip, community, timeout)
    now = time.time()
    hit = CACHE.get(key)
    if hit and hit[0] > now:
        return hit[1]
    data = fetch_supplies_generic(ip, community, timeout)
    CACHE[key] = (now + max(1, ttl), data)
    return data

def fetch_supplies_generic(ip: str, community: str = DEFAULT_COMMUNITY, timeout: int = TIMEOUT_DEFAULT):
    """Consulta SNMP y retorna datos de consumibles."""
    name = _snmp_get_name(ip, community, timeout)
    model = _snmp_get_model(ip, community, timeout)
    descs  = _snmp_column_map(ip, community, DESC_BASE,  timeout=timeout)
    maxs   = _snmp_column_map(ip, community, MAX_BASE,   timeout=timeout)
    levels = _snmp_column_map(ip, community, LEVEL_BASE, timeout=timeout)
    black_impr = _get_black_impressions(ip, community, timeout)

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
        items.append(entry)

    return {
        "ip": ip,
        "printer_name": name,
        "model": model,
        "black_impressions": black_impr,
        "items": items,
        "c415": {} if model != "C415" else {}
    }
