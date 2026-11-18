import csv

from api_client import ApiClient
from bdu import enrich_rows_with_bdu
from config import FIELDS, OUTPUT_CSV, parse_args
from sources import collect_epss, collect_github, collect_kev, collect_nvd, collect_osv
from transform import build_rows


REVIEW_FIELDS = ("review_status", "review_notes")


def load_previous_reviews() -> dict[str, dict[str, str]]:
    reviews: dict[str, dict[str, str]] = {}
    if not OUTPUT_CSV.is_file():
        return reviews
    with OUTPUT_CSV.open(newline="", encoding="utf-8-sig") as source:
        for row in csv.DictReader(source):
            cve_id = (row.get("cve_id") or "").strip().upper()
            if not cve_id:
                continue
            saved = reviews.setdefault(cve_id, {})
            for field in REVIEW_FIELDS:
                value = (row.get(field) or "").strip()
                if value:
                    saved[field] = value
    return reviews


def restore_previous_reviews(rows: list[dict[str, str]], reviews: dict[str, dict[str, str]]) -> int:
    """Restore review fields in place and return the number of rows with a saved status."""
    restored = 0
    for row in rows:
        previous = reviews.get(row["cve_id"].strip().upper(), {})
        for field in REVIEW_FIELDS:
            row[field] = previous.get(field, "")
        if row["review_status"]:
            restored += 1
    return restored


def main() -> None:
    previous_reviews = load_previous_reviews()
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
        restored_reviews = restore_previous_reviews(rows=rows, reviews=previous_reviews)
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
    print(f"Rows still requiring manual review: {len(rows) - restored_reviews}")
    print(f"Output: {OUTPUT_CSV}")
    print("Review each row with a blank review_status; set it to included or excluded.")
