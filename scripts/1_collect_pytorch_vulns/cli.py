import csv

from api_client import ApiClient
from bdu import enrich_rows_with_bdu
from config import FIELDS, OUTPUT_CSV, parse_args
from sources import collect_epss, collect_github, collect_kev, collect_nvd, collect_osv
from transform import build_rows


MANUAL_FIELDS = ("review_status", "review_notes", "fix_commit", "fix_date", "reporter", "channel")


def load_previous_manual_fields() -> dict[str, dict[str, str]]:
    previous: dict[str, dict[str, str]] = {}
    if not OUTPUT_CSV.is_file():
        return previous
    with OUTPUT_CSV.open(newline="", encoding="utf-8-sig") as source:
        for row in csv.DictReader(source):
            cve_id = (row.get("cve_id") or "").strip().upper()
            if not cve_id:
                continue
            previous[cve_id] = {field: (row.get(field) or "").strip() for field in MANUAL_FIELDS}
    return previous


def restore_previous_manual_fields(rows: list[dict[str, str]], previous: dict[str, dict[str, str]]) -> int:
    """Restore manually maintained fields in place; count rows with a saved review status."""
    restored = 0
    for row in rows:
        saved = previous.get(row["cve_id"].strip().upper(), {})
        for field in MANUAL_FIELDS:
            row[field] = saved.get(field, "")
        if row["review_status"]:
            restored += 1
    return restored


def main() -> None:
    previous_manual_fields = load_previous_manual_fields()
    end = parse_args()
    print(f"Collecting PyTorch vulnerability candidates through {end.isoformat()}.", flush=True)

    api = ApiClient()
    try:
        nvd = collect_nvd(api=api, end=end)
        osv = collect_osv(api=api)
        github = collect_github(api=api)
        cves = sorted(
            {item.get("id", "") for item in nvd if item.get("id")}
            | {
                alias
                for item in osv
                for alias in {item.get("id", ""), *(item.get("aliases", []) or [])}
                if alias.startswith("CVE-")
            }
            | {str(item.get("cve_id") or "") for item in github if str(item.get("cve_id") or "").startswith("CVE-")}
        )
        epss = collect_epss(api=api, cves=cves)
        kev = collect_kev(api=api)
        rows = build_rows(nvd=nvd, osv=osv, github=github, epss=epss, kev=kev, end=end)
        bdu_matches = enrich_rows_with_bdu(rows=rows)
        restored_reviews = restore_previous_manual_fields(rows=rows, previous=previous_manual_fields)
    finally:
        api.close()

    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_CSV.open("w", newline="", encoding="utf-8-sig") as output:
        writer = csv.DictWriter(output, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"NVD candidates: {len(nvd)}; OSV records: {len(osv)}; GHSA records: {len(github)}")
    print(f"CSV rows in period: {len(rows)}")
    print(f"BDU matches: {bdu_matches}")
    print(f"Previous review decisions restored: {restored_reviews}")
    print(
        "Manual metadata values restored: "
        f"{sum(bool(row[field]) for row in rows for field in MANUAL_FIELDS[2:])}"
    )
    print(f"Rows still requiring manual review: {len(rows) - restored_reviews}")
    print(f"Output: {OUTPUT_CSV}")
    print("Review each row with a blank review_status; set it to included or excluded.")
