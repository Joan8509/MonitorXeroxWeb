import requests
from bs4 import BeautifulSoup


def normalize_consumables(consumables, printer_info=None):
    """Normalize Xerox consumables names to simple keys for later Flask integration."""
    normalized = {
        "model": "",
        "serial": "",
        "ip": "",
        "toner": "",
        "drum": "",
        "imaging_unit": "",
        "transfer_roller": "",
        "fuser": "",
        "transfer_belt_cleaner": "",
        "second_bias_transfer_roll": "",
        "waste_toner": "",
        "black_impressions": -1,
    }

    if printer_info:
        normalized["model"] = printer_info.get("model", "")
        normalized["serial"] = printer_info.get("serial", "")
        normalized["ip"] = printer_info.get("ip", "")
        try:
            normalized["black_impressions"] = int(printer_info.get("black_impressions", -1))
        except (TypeError, ValueError):
            normalized["black_impressions"] = -1

    for item in consumables or []:
        name = (item.get("name") or "").strip()
        level = item.get("level", "")
        if not name:
            continue

        lname = name.lower()

        if any(token in lname for token in ("black toner", "toner cartridge")):
            normalized["toner"] = level
        elif "black imaging unit" in lname or "imaging unit" in lname:
            normalized["imaging_unit"] = level
            if not normalized["drum"]:
                normalized["drum"] = level
        elif "drum cartridge" in lname or "drum" in lname:
            normalized["drum"] = level
        elif "transfer roller" in lname:
            normalized["transfer_roller"] = level
        elif "fuser" in lname:
            normalized["fuser"] = level
        elif "transfer belt cleaner" in lname:
            normalized["transfer_belt_cleaner"] = level
        elif "second bias transfer roll" in lname:
            normalized["second_bias_transfer_roll"] = level
        elif "waste toner container" in lname:
            normalized["waste_toner"] = level

    return normalized


def get_consumables(
    asset_id,
    asset_account_id,
    asset_encrypted_id,
    token,
    referer,
    cookie,
):
    url = "https://office.services.xerox.com/FMP/Printers/PrinterDetails/InvokeTab"

    payload = {
        "model[AssetID]": asset_id,
        "model[TabName]": "Consumables",
        "model[AssetAccountID]": asset_account_id,
        "model[AssetEncryptedId]": asset_encrypted_id,
        "model[DataSorceID]": "Grid_Printers",
    }

    headers = {
        "accept": "*/*",
        "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
        "origin": "https://office.services.xerox.com",
        "referer": referer,
        "requestverificationtoken": token,
        "x-requested-with": "XMLHttpRequest",
        "user-agent": "Mozilla/5.0",
        "cookie": cookie,
    }

    r = requests.post(
        url,
        headers=headers,
        data=payload,
        timeout=30
    )

    if r.status_code != 200:
        return {
            "success": False,
            "error": f"HTTP {r.status_code}"
        }
    
    soup = BeautifulSoup(r.text, "html.parser")

    consumables = []

    title = soup.find("span", string=lambda s: s and "Imaging Related Consumables" in s)

    if title:
        table = title.find_parent("div").find_next("table")

        for row in table.select("tbody tr"):
            cols = [c.get_text(" ", strip=True) for c in row.select("td")]

            if len(cols) >= 3:
                name = cols[0]
                level = cols[2]

                if name:
                    consumables.append({
                        "name": name,
                        "level": level
                    })

    return {
        "success": True,
        "consumables": consumables
    }
