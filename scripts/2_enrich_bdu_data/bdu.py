import csv
import datetime as dt
import re
import tempfile
from pathlib import Path
from typing import Any

from python_calamine import CalamineWorkbook

ROOT = Path(__file__).resolve().parents[2]
REVIEWED_CSV = ROOT / "data" / "vulnerabilities.csv"
INCLUDED_CSV = ROOT / "data" / "vulnerabilities_included.csv"
BDU_XLSX = ROOT / "data" / "bdu_vullist.xlsx"
BDU_SHEET = "Уязвимости"
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)
REQUIRED_COLUMNS = {
    "bdu_id": "Идентификатор",
    "published_bdu": "Дата публикации",
    "cve_ids": "Идентификаторы других систем описаний уязвимости",
    "cvss_bdu_20": "CVSS 2.0",
    "cvss_bdu_30": "CVSS 3.0",
    "cvss_bdu_40": "CVSS 4.0",
}


def _cell(row: list[Any], index: int) -> Any:
    return row[index] if index < len(row) else None


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


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


def _load_bdu_records(path: Path) -> dict[str, list[dict[str, str]]]:
    if not path.is_file():
        raise FileNotFoundError(f"BDU workbook not found: {path}")

    workbook = CalamineWorkbook.from_path(str(path))
    if BDU_SHEET not in workbook.sheet_names:
        raise ValueError(f"Expected BDU sheet '{BDU_SHEET}', found: {', '.join(workbook.sheet_names)}")
    sheet = workbook.get_sheet_by_name(BDU_SHEET)

    header: dict[str, int] | None = None
    rows = iter(sheet.iter_rows())
    for row in rows:
        names = {_text(value): index for index, value in enumerate(row) if _text(value)}
        if all(column in names for column in REQUIRED_COLUMNS.values()):
            header = {key: names[name] for key, name in REQUIRED_COLUMNS.items()}
            break
    if header is None:
        expected = ", ".join(REQUIRED_COLUMNS.values())
        raise ValueError(f"Could not find BDU header row with required columns: {expected}")

    records: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        bdu_id = _text(_cell(row, header["bdu_id"]))
        cve_cell = _text(_cell(row, header["cve_ids"]))
        if not bdu_id or not cve_cell:
            continue

        cvss = ""
        cvss_version = ""
        for key, version in (("cvss_bdu_30", "3.0"), ("cvss_bdu_40", "4.0"), ("cvss_bdu_20", "2.0")):
            cvss = _text(_cell(row, header[key]))
            if cvss:
                cvss_version = version
                break

        record = {
            "bdu_id": bdu_id,
            "published_bdu": _date_text(_cell(row, header["published_bdu"])),
            "cvss_bdu": cvss,
            "cvss_bdu_version": cvss_version,
        }
        for cve_id in {match.upper() for match in CVE_PATTERN.findall(cve_cell)}:
            records.setdefault(cve_id, []).append(record)
    return records


def _join_unique(records: list[dict[str, str]], field: str) -> str:
    return "; ".join(dict.fromkeys(record[field] for record in records if record[field]))


def _write_csv(path: Path, rows: list[dict[str, str]], fieldnames: list[str]) -> None:
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            newline="",
            encoding="utf-8-sig",
            dir=path.parent,
            suffix=".tmp",
            delete=False,
        ) as output:
            temporary_path = Path(output.name)
            writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        temporary_path.replace(path)
    finally:
        if temporary_path and temporary_path.exists():
            temporary_path.unlink()


def enrich_csv_with_bdu(
    source_csv: Path = REVIEWED_CSV,
    output_csv: Path = INCLUDED_CSV,
    bdu_path: Path = BDU_XLSX,
) -> tuple[int, int, int, int]:
    if not source_csv.is_file():
        raise FileNotFoundError(f"Reviewed vulnerability table not found: {source_csv}")
    if source_csv.resolve() == output_csv.resolve():
        raise ValueError("The included-only output must be a separate file from the reviewed source table.")

    with source_csv.open(newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        fieldnames = reader.fieldnames
        if not fieldnames:
            raise ValueError(f"CSV has no header: {csv_path}")
        required_csv_columns = {
            "cve_id",
            "review_status",
            "bdu_id",
            "published_bdu",
            "cvss_bdu",
            "cvss_bdu_version",
        }
        missing = required_csv_columns - set(fieldnames)
        if missing:
            raise ValueError(f"CSV is missing required columns: {', '.join(sorted(missing))}")
        rows = list(reader)

    statuses = {row["review_status"] for row in rows}
    unexpected_statuses = statuses - {"included", "excluded"}
    if unexpected_statuses:
        raise ValueError(
            "Finish manual review first; only 'included' and 'excluded' are allowed. "
            f"Found: {', '.join(sorted(unexpected_statuses))}"
        )

    included = [row for row in rows if row["review_status"] == "included"]
    excluded_count = sum(row["review_status"] == "excluded" for row in rows)
    if not included:
        raise ValueError("No included rows found; BDU enrichment was not run.")

    bdu_records = _load_bdu_records(bdu_path)
    matched = 0
    multiple_matches = 0
    for row in included:
        matches = bdu_records.get(row["cve_id"].strip().upper(), [])
        row["bdu_id"] = _join_unique(matches, "bdu_id")
        row["published_bdu"] = _join_unique(matches, "published_bdu")
        row["cvss_bdu"] = _join_unique(matches, "cvss_bdu")
        row["cvss_bdu_version"] = _join_unique(matches, "cvss_bdu_version")
        if matches:
            matched += 1
        if len({record["bdu_id"] for record in matches}) > 1:
            multiple_matches += 1

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    _write_csv(output_csv, included, fieldnames)
    unmatched = len(included) - matched
    print(f"Source rows: {len(rows)}")
    print(f"Included rows written: {len(included)}")
    print(f"Excluded rows omitted: {excluded_count}")
    print(f"Matched to BDU: {matched}")
    print(f"No BDU match: {unmatched}")
    if multiple_matches:
        print(f"Rows with multiple BDU matches: {multiple_matches}")
    print(f"Output: {output_csv}")
    return len(included), excluded_count, matched, unmatched


def main() -> None:
    enrich_csv_with_bdu()
