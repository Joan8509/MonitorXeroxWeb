# -*- coding: utf-8 -*-
import os, re, time
from typing import Any, Dict, List
from puresnmp import get as snmp_get, walk

DEFAULT_COMMUNITY = os.getenv("SNMP_COMMUNITY", "public")
TIMEOUT_DEFAULT = int(os.getenv("TIMEOUT_DEFAULT", "3"))
TTL_DEFAULT = int(os.getenv("TTL_DEFAULT", "15"))

_cache: Dict[str, Dict[str, Any]] = {}

# ------------------------- CACHE -------------------------
def get_cached(ip: str):
    entry = _cache.get(ip)
    if not entry:
        return None
    if time.time() - entry["ts"] > TTL_DEFAULT:
        _cache.pop(ip, None)
        return None
    return entry["data"]

def set_cache(ip: str, data: Dict[str, Any]):
    _cache[ip] = {"data": data, "ts": time.time()}

# ------------------------- SNMP SAFE -------------------------
def decode(val: Any) -> str:
    if isinstance(val, bytes):
        try:
            return val.decode("utf-8", errors="ignore").strip()
        except Exception:
            return val.decode("latin-1", errors="ignore").strip()
    return str(val).strip() if val else ""

def safe_get(ip: str, oid: str, community=DEFAULT_COMMUNITY, timeout=TIMEOUT_DEFAULT) -> str:
    try:
        val = snmp_get(ip, community, oid, timeout=timeout)
        return decode(val)
    except Exception:
        return ""

def safe_walk(ip: str, oid: str, community=DEFAULT_COMMUNITY, timeout=TIMEOUT_DEFAULT) -> Dict[str, str]:
    res = {}
    try:
        for oid_str, val in walk(ip, community, oid, timeout=timeout):
            res[str(oid_str)] = decode(val)
    except Exception:
        pass
    return res

# ------------------------- OIDs -------------------------
SYS_DESCR   = "1.3.6.1.2.1.1.1.0"
SYS_NAME    = "1.3.6.1.2.1.1.5.0"
PRT_NAME    = "1.3.6.1.2.1.43.5.1.1.16.1"
PRT_LIFE    = "1.3.6.1.2.1.43.10.2.1.4"
DESC_BASE   = "1.3.6.1.2.1.43.11.1.1.6"
MAX_BASE    = "1.3.6.1.2.1.43.11.1.1.8"
LEVEL_BASE  = "1.3.6.1.2.1.43.11.1.1.9"
ALERT_BASE  = "1.3.6.1.2.1.43.18.1.1.8"

# ------------------------- CLASIFICAR -------------------------
def classify(desc: str) -> str:
    d = desc.lower()
    if "waste" in d and "toner" in d:
        return "waste_toner"
    if "transfer belt" in d and "clean" in d:
        return "belt_cleaner"
    if "transfer" in d and "roller" in d:
        return "transfer_roller"
    if "fuser" in d:
        return "fuser"
    if "drum" in d or "imaging" in d:
        return "drum"
    if "toner" in d or "cartridge" in d:
        return "toner"
    return "other"

# ------------------------- DETECTAR MODELO -------------------------
def detect_model(sys_descr: str) -> str:
    d = sys_descr.upper()
    for tag in ("B415", "B8155", "B7135", "C415"):
        if tag in d:
            return tag
    return "Unknown"

# ------------------------- CALCULO PORCENTAJE -------------------------
def calc_percent(level: str, maxcap: str, desc: str) -> float:
    try:
        lv = float(level)
        mx = float(maxcap)
        if mx > 0 and lv >= 0:
            return round((lv / mx) * 100, 1)
    except Exception:
        pass
    m = re.search(r"(\d{1,3})\s*%", desc or "")
    if m:
        try:
            v = float(m.group(1))
            if 0 <= v <= 100:
                return v
        except Exception:
            pass
    return -1.0

# ------------------------- ALERTAS VIDA ÚTIL (B7135) -------------------------
def b7135_life(ip: str, community: str) -> Dict[str, str]:
    alerts = safe_walk(ip, ALERT_BASE, community)
    st = {"fuser": "OK", "transfer_roller": "OK"}
    for _, val in alerts.items():
        t = val.lower()
        if "fuser" in t or "r8" in t:
            if any(x in t for x in ("end", "expired", "replace", "life")):
                st["fuser"] = "END"
        if "transfer" in t or "r7" in t:
            if any(x in t for x in ("end", "expired", "replace", "life")):
                st["transfer_roller"] = "END"
    return st

# ------------------------- FORMATO VISUAL -------------------------
def beautify(info: Dict[str, Any]) -> Dict[str, Any]:
    for it in info.get("items", []):
        cat = it["category"]
        p = it.get("percent", -1)
        if cat in ("fuser", "transfer_roller"):
            if p <= 0:
                it["display"] = "Past end of life"; it["color"] = "alert"
            else:
                it["display"] = "OK"; it["color"] = "ok"
            continue
        if p < 0:
            it["display"] = "N/A"; it["color"] = "muted"
        elif p >= 90:
            it["display"] = f"{p:.0f}%"; it["color"] = "ok"
        elif 50 <= p < 90:
            it["display"] = f"{p:.0f}%"; it["color"] = "warn"
        elif 10 <= p < 50:
            it["display"] = "Near end of life"; it["color"] = "alert"
        else:
            it["display"] = "Past end of life"; it["color"] = "alert"
    return info

# ------------------------- FUNCIÓN PRINCIPAL -------------------------
def fetch_supplies_generic(ip: str, community=DEFAULT_COMMUNITY, timeout=TIMEOUT_DEFAULT) -> Dict[str, Any]:
    cached = get_cached(ip)
    if cached:
        return cached

    info: Dict[str, Any] = {
        "ip": ip,
        "printer_name": safe_get(ip, PRT_NAME, community, timeout) or safe_get(ip, SYS_NAME, community, timeout),
        "model": detect_model(safe_get(ip, SYS_DESCR, community, timeout)),
        "black_impressions": -1,
        "items": []
    }

    # Impressions
    try:
        counts = []
        for _, v in walk(ip, community, PRT_LIFE, timeout=timeout):
            try:
                n = int(decode(v))
                if n >= 0:
                    counts.append(n)
            except Exception:
                pass
        if counts:
            info["black_impressions"] = max(counts)
    except Exception:
        pass

    descs  = safe_walk(ip, DESC_BASE, community, timeout)
    maxs   = safe_walk(ip, MAX_BASE,  community, timeout)
    levels = safe_walk(ip, LEVEL_BASE, community, timeout)

    items: List[Dict[str, Any]] = []
    for oid, desc in descs.items():
        idx = oid.split(".")[-1]
        maxcap = maxs.get(f"{MAX_BASE}.{idx}", "")
        level  = levels.get(f"{LEVEL_BASE}.{idx}", "")
        cat = classify(desc)
        pct = calc_percent(level, maxcap, desc)
        items.append({"category": cat, "percent": pct})

    # B7135: agregar chips de vida
    if info["model"] == "B7135":
        life = b7135_life(ip, community)
        items.append({"category": "transfer_roller", "percent": 100 if life["transfer_roller"] == "OK" else 0})
        items.append({"category": "fuser", "percent": 100 if life["fuser"] == "OK" else 0})

    ordered = ["toner","drum","transfer_roller","fuser","waste_toner","belt_cleaner","transfer_belt"]
    final = []
    for c in ordered:
        val = -1
        for it in items:
            if it["category"] == c and it["percent"] > val:
                val = it["percent"]
        final.append({"category": c, "percent": val})
    info["items"] = final

    info = beautify(info)
    set_cache(ip, info)
    return info
