import io
from datetime import datetime
from typing import Any, Dict, List, Optional
from flask import Response
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side, Color
from openpyxl.utils import get_column_letter
from openpyxl.formatting.rule import DataBarRule, CellIsRule

# ===================== CONFIG =====================
XLSX_WARN_PCT = 20
XLSX_ALERT_PCT = 10
XLSX_WARN_FRAC = XLSX_WARN_PCT / 100.0
XLSX_ALERT_FRAC = XLSX_ALERT_PCT / 100.0

# ===================== HEADERS =====================
CSV_HEADERS = [
    "IP","Printer","Model","Black Impressions",
    "Toner","Drum/Imaging Unit",
    "Transfer Roller R7","Fuser R8",
    "Waste Toner Container","Transfer Belt Cleaner",
    "Second Bias Transfer Roll","Exported At"
]

# ===================== HELPERS =====================
def _pick_best(items: List[Dict[str, Any]], category: str) -> Dict[str, Any]:
    cands = [it for it in items if it.get("category") == category]
    if not cands:
        return {}
    return max(cands, key=lambda it: (it.get("percent") if isinstance(it.get("percent"), (int, float)) else -1))

def _xlsx_apply_styles(ws):
    header_fill = PatternFill("solid", fgColor="F3F3F3")
    bold = Font(bold=True)
    thin = Side(style="thin", color="DDDDDD")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)
    for col, title in enumerate(CSV_HEADERS, start=1):
        c = ws.cell(row=1, column=col, value=title)
        c.fill = header_fill
        c.font = bold
        c.alignment = Alignment(vertical="center")
        c.border = border
    widths = [14, 22, 24, 18, 12, 16, 20, 14, 22, 22, 26, 20]
    for i, w in enumerate(widths, start=1):
        ws.column_dimensions[get_column_letter(i)].width = w

def _xlsx_apply_grid(ws, start_row, start_col, end_row, end_col):
    thin = Side(style="thin", color="DDDDDD")
    medium = Side(style="medium", color="AAAAAA")
    for r in range(start_row, end_row + 1):
        for c in range(start_col, end_col + 1):
            left   = medium if c == start_col else thin
            right  = medium if c == end_col   else thin
            top    = medium if r == start_row else thin
            bottom = medium if r == end_row   else thin
            cell = ws.cell(row=r, column=c)
            cell.border = Border(left=left, right=right, top=top, bottom=bottom)

def _xlsx_format_body(ws, nrows):
    if nrows < 2:
        return
    # formato números
    for r in range(2, nrows + 1):
        ws.cell(row=r, column=4).number_format = '#,##0'
    # formato porcentajes
    for c in range(5, 12):
        for r in range(2, nrows + 1):
            cell = ws.cell(row=r, column=c)
            if isinstance(cell.value, float):
                cell.number_format = '0%'

    # barras y colores condicionales
    green = Color(rgb="FF63BE7B")
    for c in range(5, 12):
        col_letter = get_column_letter(c)
        rng = f"{col_letter}2:{col_letter}{nrows}"
        ws.conditional_formatting.add(rng, DataBarRule(start_type="num", start_value=0, end_type="num", end_value=1, color=green, showValue=True))

    ok_fill  = PatternFill("solid", fgColor="E7F7EE")
    bad_fill = PatternFill("solid", fgColor="FDECEA")
    ws.conditional_formatting.add(f"G2:G{nrows}", CellIsRule(operator='equal', formula=['\"OK\"'], fill=ok_fill))
    ws.conditional_formatting.add(f"G2:G{nrows}", CellIsRule(operator='equal', formula=['\"Past end of life\"'], fill=bad_fill))
    ws.conditional_formatting.add(f"H2:H{nrows}", CellIsRule(operator='equal', formula=['\"OK\"'], fill=ok_fill))
    ws.conditional_formatting.add(f"H2:H{nrows}", CellIsRule(operator='equal', formula=['\"Past end of life\"'], fill=bad_fill))

    # alertas por bajo nivel
    warn_fill  = PatternFill("solid", fgColor="FFF7ED")
    alert_fill = PatternFill("solid", fgColor="FEF2F2")
    for c in range(5, 12):
        col_letter = get_column_letter(c)
        rng = f"{col_letter}2:{col_letter}{nrows}"
        ws.conditional_formatting.add(rng, CellIsRule(operator='lessThanOrEqual', formula=[str(XLSX_ALERT_FRAC)], fill=alert_fill))
        ws.conditional_formatting.add(rng, CellIsRule(operator='lessThanOrEqual', formula=[str(XLSX_WARN_FRAC)], fill=warn_fill))

    _xlsx_apply_grid(ws, 1, 1, nrows, len(CSV_HEADERS))

# ===================== EXPORT MAIN =====================
def pivot_row_for_xlsx(data: Dict[str, Any], exported_at: str):
    model = (data.get("model") or "").upper()
    if model == "C415":
        return None
    items = data.get("items", [])
    def pct_num(it):
        if not it:
            return None
        if "status" in it and it["status"]:
            return it["status"]
        p = it.get("percent")
        if isinstance(p, (int, float)) and p >= 0:
            return float(p) / 100.0
        return None
    bi = data.get("black_impressions")
    bi_val = bi if isinstance(bi, int) and bi >= 0 else None
    tr_item = _pick_best(items, "transfer_roller")
    fuser_item = _pick_best(items, "fuser")
    toner_item = _pick_best(items, "toner")
    drum_item = _pick_best(items, "drum")
    waste_item = _pick_best(items, "waste_toner")
    beltcl_it = _pick_best(items, "belt_cleaner")
    tr_r7, sbtr = None, None
    if tr_item:
        if model == "B8155":
            sbtr = pct_num(tr_item)
        else:
            tr_r7 = pct_num(tr_item)
    return [
        data.get("ip", ""),
        data.get("printer_name", ""),
        data.get("model", ""),
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

# ===================== FILTERS =====================
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
        return max(0.0, min(100.0, v))
    except Exception:
        return None

# ===================== MAIN EXPORT HANDLERS =====================
def handle_export_xlsx_pivot(data: Dict[str, Any], pct_max=None, text=""):
    """Genera y devuelve un Excel para una sola impresora."""
    exported_at = datetime.now().strftime("%Y-%m-%d %H:%M")
    fname_stamp = datetime.now().strftime("%Y%m%d-%H%M")
    wb = Workbook()
    ws = wb.active
    ws.title = "Supplies"
    _xlsx_apply_styles(ws)
    if _row_matches_filters(data, pct_max, text):
        row = pivot_row_for_xlsx(data, exported_at)
        if row:
            ws.append(row)
    _xlsx_format_body(ws, nrows=ws.max_row)
    bio = io.BytesIO()
    wb.save(bio)
    bio.seek(0)
    fname = f"xerox_supplies_{data.get('ip','unknown').replace('.', '-')}_{fname_stamp}.xlsx"
    headers = {
        "Content-Type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "Content-Disposition": f'attachment; filename="{fname}"'
    }
    return Response(bio.getvalue(), headers=headers)

def handle_export_xlsx_list_pivot(all_data: List[Dict[str, Any]], pct_max=None, text=""):
    """Genera Excel con múltiples impresoras."""
    exported_at = datetime.now().strftime("%Y-%m-%d %H:%M")
    fname_stamp = datetime.now().strftime("%Y%m%d-%H%M")
    wb = Workbook()
    ws = wb.active
    ws.title = "Supplies"
    _xlsx_apply_styles(ws)
    for d in all_data:
        if _row_matches_filters(d, pct_max, text):
            row = pivot_row_for_xlsx(d, exported_at)
            if row:
                ws.append(row)
    _xlsx_format_body(ws, nrows=ws.max_row)
    bio = io.BytesIO()
    wb.save(bio)
    bio.seek(0)
    fname = f"xerox_supplies_list_{fname_stamp}.xlsx"
    headers = {
        "Content-Type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "Content-Disposition": f'attachment; filename="{fname}"'
    }
    return Response(bio.getvalue(), headers=headers)
