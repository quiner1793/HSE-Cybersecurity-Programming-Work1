import csv

from api_client import ApiClient
from config import FIELDS, OUTPUT_CSV, parse_args
from sources import collect_epss, collect_github, collect_kev, collect_nvd, collect_osv
from transform import build_rows


def main() -> None:
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
    finally:
        api.close()

    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_CSV.open("w", newline="", encoding="utf-8-sig") as output:
        writer = csv.DictWriter(output, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"NVD candidates: {len(nvd)}; OSV records: {len(osv)}; GHSA records: {len(github)}")
    print(f"CSV rows (in period, requiring manual review): {len(rows)}")
    print(f"Output: {OUTPUT_CSV}")
    print("BDU fields and verified fix dates still need manual research.")
