import datetime as dt
import re
from typing import Any

from config import BDU_XLSX
from python_calamine import CalamineWorkbook

BDU_SHEET = "Уязвимости"
CVE_PATTERN = re.compile(r"(?<![A-Z0-9])CVE-\d{4}-\d+(?![A-Z0-9])", re.IGNORECASE)
COLUMNS = {
    "bdu_id": "Идентификатор",
    "published_bdu": "Дата публикации",
    "cve_ids": "Идентификаторы других систем описаний уязвимости",
    "cvss_bdu_20": "CVSS 2.0",
    "cvss_bdu_30": "CVSS 3.0",
    "cvss_bdu_31": "CVSS 3.1",
    "cvss_bdu_40": "CVSS 4.0",
}


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _date_text(value: Any) -> str:
    if isinstance(value, (dt.datetime, dt.date)):
        return value.date().isoformat() if isinstance(value, dt.datetime) else value.isoformat()
    text = _text(value)
    for date_format in ("%d.%m.%Y", "%Y-%m-%d", "%d/%m/%Y"):
        try:
            return dt.datetime.strptime(text, date_format).date().isoformat()
        except ValueError:
            pass
    return text


def _join(records: list[dict[str, str]], field: str) -> str:
    return "; ".join(dict.fromkeys(record[field] for record in records if record[field]))


def enrich_rows_with_bdu(rows: list[dict[str, str]]) -> int:
    wanted = {_text(row["cve_id"]).upper() for row in rows if row.get("cve_id")}
    workbook = CalamineWorkbook.from_path(str(BDU_XLSX))
    sheet = workbook.get_sheet_by_name(BDU_SHEET)
    sheet_rows = sheet.to_python(skip_empty_area=False)

    header = None
    header_row_index = None
    for row_index, row in enumerate(sheet_rows):
        names: dict[str, int] = {}
        for index, value in enumerate(row):
            name = _text(value)
            if name:
                names.setdefault(name, index)
        if all(names.get(COLUMNS[key]) is not None for key in ("bdu_id", "published_bdu", "cve_ids")):
            header = {key: names.get(name) for key, name in COLUMNS.items()}
            header_row_index = row_index
            break
    if header is None or header_row_index is None:
        raise ValueError(f"BDU sheet '{BDU_SHEET}' has no expected header row")

    records: dict[str, list[dict[str, str]]] = {}
    for row in sheet_rows[header_row_index + 1 :]:
        bdu_id = _text(row[header["bdu_id"]])
        cve_cell = _text(row[header["cve_ids"]])
        if not bdu_id or not cve_cell:
            continue

        cvss = ""
        cvss_version = ""
        for key, version in (("cvss_bdu_31", "3.1"), ("cvss_bdu_30", "3.0"), ("cvss_bdu_40", "4.0"), ("cvss_bdu_20", "2.0")):
            index = header[key]
            cvss = _text(row[index]) if index is not None else ""
            if cvss:
                cvss_version = version
                break

        record = {
            "bdu_id": bdu_id,
            "published_bdu": _date_text(row[header["published_bdu"]]),
            "cvss_bdu": cvss,
            "cvss_bdu_version": cvss_version,
        }

        for cve_id in {match.upper() for match in CVE_PATTERN.findall(cve_cell)} & wanted:
            records.setdefault(cve_id, []).append(record)

    matched = 0
    for row in rows:
        matches = records.get(_text(row["cve_id"]).upper(), [])
        for field in ("bdu_id", "published_bdu", "cvss_bdu", "cvss_bdu_version"):
            row[field] = _join(matches, field)
        matched += bool(matches)
    return matched
