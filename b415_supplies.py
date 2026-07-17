# b415_supplies.py
from typing import Any, Dict, List
from puresnmp import walk

# Printer-MIB prtMarkerSuppliesTable
DESC_BASE  = "1.3.6.1.2.1.43.11.1.1.6"  # prtMarkerSuppliesDescription
MAX_BASE   = "1.3.6.1.2.1.43.11.1.1.8"  # prtMarkerSuppliesMaxCapacity
LEVEL_BASE = "1.3.6.1.2.1.43.11.1.1.9"  # prtMarkerSuppliesLevel

def _snmp_column_map(host: str, community: str, base_oid: str, timeout: int = 3) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for vb_oid, vb_value in walk(host, community, base_oid, timeout=timeout):
        idx = str(vb_oid).split(".")[-1]
        if isinstance(vb_value, bytes):
            try:
                vb_value = vb_value.decode(errors="ignore")
            except Exception:
                vb_value = str(vb_value)
        out[new_func(idx)] = vb_value
    return out

def new_func(idx):
    return idx

def _safe_pct(level: Any, maxcap: Any) -> float:
    try:
        level = int(level); maxcap = int(maxcap)
    except Exception:
        return -1
    if level < 0 or maxcap <= 0:
        return -1
    return round(100.0 * level / maxcap, 1)

def _categorize_b415(desc: str) -> str:
    d = (desc or "").strip().lower()
    if "toner" in d: return "toner"
    if "imaging" in d or "drum" in d: return "drum"
    return "other"

def fetch_b415_supplies(ip: str, community: str = "public", timeout: int = 3) -> Dict[str, Any]:
    if not ip:
        raise ValueError("Falta parámetro 'ip'")
    descs  = _snmp_column_map(ip, community, DESC_BASE,  timeout=timeout)
    maxs   = _snmp_column_map(ip, community, MAX_BASE,   timeout=timeout)
    levels = _snmp_column_map(ip, community, LEVEL_BASE, timeout=timeout)

    items: List[Dict[str, Any]] = []
    for idx in sorted(set(descs) | set(maxs) | set(levels), key=lambda x: int(x)):
        desc = descs.get(idx)
        cat  = _categorize_b415(desc or "")
        if cat not in {"toner", "drum"}:
            continue  # solo lo relevante B415
        maxc = maxs.get(idx)
        lev  = levels.get(idx)
        pct  = _safe_pct(lev, maxc)
        label = "Tóner (K)" if cat == "toner" else "Drum / Imaging Unit"
        items.append({
            "index": int(idx),
            "description": desc,
            "max_capacity": maxc,
            "level": lev,
            "percent": pct,
            "category": cat,
            "label": label,
        })

    items.sort(key=lambda it: (it["label"], -(it["percent"] if isinstance(it["percent"], (int, float)) else -1)))
    return {"ip": ip, "community": community, "model": "B415", "items": items}
