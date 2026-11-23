import datetime as dt
import json
import os
import time
from typing import Any

import httpx

from api_client import ApiClient
from config import RAW_DIR, START_DATE

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_URL = "https://api.osv.dev/v1/query"
GITHUB_URL = "https://api.github.com/advisories"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CVE_URL = "https://cveawg.mitre.org/api/cve"


def save_json(name: str, payload: Any) -> None:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    (RAW_DIR / name).write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def date_windows(end: dt.date):
    cursor = START_DATE
    while cursor <= end:
        last = min(end, cursor + dt.timedelta(days=119))
        yield cursor, last
        cursor = last + dt.timedelta(days=1)


def collect_nvd(api: ApiClient, end: dt.date) -> list[dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    api_key = os.getenv("NVD_API_KEY")
    windows = list(date_windows(end))
    jobs = [(term, first, last) for term in ("PyTorch", "torch") for first, last in windows]
    for job_number, (term, first, last) in enumerate(jobs, start=1):
        print(f"[NVD {job_number}/{len(jobs)}] {term}, {first}..{last}", flush=True)
        params = {
            "keywordSearch": term,
            "pubStartDate": f"{first.isoformat()}T00:00:00.000",
            "pubEndDate": f"{last.isoformat()}T23:59:59.999",
            "resultsPerPage": 2000,
        }
        headers = {"apiKey": api_key} if api_key else {}
        start_index = 0
        while True:
            params["startIndex"] = start_index
            payload = api.get_json(NVD_URL, params=params, headers=headers)
            page = payload.get("vulnerabilities", [])
            for entry in page:
                cve = entry.get("cve", {})
                if cve.get("id"):
                    records[cve["id"]] = cve
            total = int(payload.get("totalResults", 0))
            page_size = int(payload.get("resultsPerPage", 0))
            print(f"  page at {start_index}: {len(page)} records; {total} matches", flush=True)
            start_index += page_size
            if not page_size or start_index >= total:
                break
            time.sleep(0.7 if api_key else 6.0)
        time.sleep(0.7 if api_key else 6.0)
    result = sorted(records.values(), key=lambda cve: (cve.get("published", ""), cve.get("id", "")))
    save_json("nvd_candidates.json", result)
    print(f"[NVD] {len(result)} unique candidate CVEs saved.", flush=True)
    return result


def complete_nvd_by_id(api: ApiClient, records: list[dict[str, Any]], cve_ids: list[str]) -> list[dict[str, Any]]:
    """Check CVEs found in other catalogs that were absent from NVD keyword search."""
    by_id = {record["id"]: record for record in records}
    missing = [cve_id for cve_id in cve_ids if cve_id not in by_id]
    if not missing:
        return records

    api_key = os.getenv("NVD_API_KEY")
    headers = {"apiKey": api_key} if api_key else {}
    for number, cve_id in enumerate(missing, start=1):
        print(f"[NVD by ID {number}/{len(missing)}] {cve_id}", flush=True)
        payload = api.get_json(NVD_URL, params={"cveId": cve_id}, headers=headers)
        entries = [entry["cve"] for entry in payload.get("vulnerabilities", [])]
        if entries:
            if len(entries) != 1 or entries[0].get("id") != cve_id:
                raise ValueError(f"Unexpected NVD response for {cve_id}")
            by_id[cve_id] = entries[0]
        if number < len(missing):
            time.sleep(0.7 if api_key else 6.0)

    result = sorted(by_id.values(), key=lambda cve: (cve.get("published", ""), cve["id"]))
    save_json("nvd_candidates.json", result)
    print(f"[NVD] {len(result)} candidates after direct CVE lookup.", flush=True)
    return result


def collect_osv(api: ApiClient) -> list[dict[str, Any]]:
    print("[OSV] Querying torch (PyPI)...", flush=True)
    payload = api.post_json(OSV_URL, {"package": {"name": "torch", "ecosystem": "PyPI"}})
    records = payload.get("vulns", [])
    save_json("osv_torch_pypi.json", records)
    print(f"[OSV] {len(records)} records saved.", flush=True)
    return records


def collect_cve_records(api: ApiClient, cve_ids: list[str]) -> dict[str, dict[str, Any]]:
    path = RAW_DIR / "cve_records.json"
    cached = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    records = {cve_id: cached[cve_id] for cve_id in cve_ids if cve_id in cached}
    missing = [cve_id for cve_id in cve_ids if cve_id not in records]
    print(f"[CVE List] {len(records)} cached; {len(missing)} records to fetch.", flush=True)
    for number, cve_id in enumerate(missing, start=1):
        try:
            record = api.get_json(f"{CVE_URL}/{cve_id}")
        except httpx.HTTPStatusError as error:
            if error.response.status_code != 404:
                raise
            print(f"[CVE List] {cve_id}: no public record (404).", flush=True)
            continue
        metadata = record.get("cveMetadata", {})
        if metadata.get("cveId") != cve_id:
            raise ValueError(f"Unexpected CVE List record for {cve_id}")
        records[cve_id] = record
        if number % 10 == 0 or number == len(missing):
            save_json("cve_records.json", records)
            print(f"[CVE List] fetched {number}/{len(missing)}", flush=True)
    return records


def collect_github(api: ApiClient) -> list[dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for package in ("torch", "pytorch"):
        for advisory_type in ("reviewed", "unreviewed"):
            print(f"[GitHub Advisory] {package}, {advisory_type}", flush=True)
            params = {"ecosystem": "pip", "affects": package, "type": advisory_type, "per_page": 100}
            url = GITHUB_URL
            while url:
                response = api.request("GET", url, params=params, headers={"Accept": "application/vnd.github+json"})
                page = response.json()
                if not isinstance(page, list):
                    raise RuntimeError("Unexpected GitHub advisories response")
                for advisory in page:
                    if advisory.get("ghsa_id"):
                        records[advisory["ghsa_id"]] = advisory
                next_page = response.links.get("next", {}).get("url")
                print(f"  page: {len(page)} advisories", flush=True)
                url, params = next_page or "", None
    result = sorted(records.values(), key=lambda item: item.get("ghsa_id", ""))
    save_json("github_advisories_torch_pip.json", result)
    print(f"[GitHub Advisory] {len(result)} unique advisories saved.", flush=True)
    return result


def collect_epss(api: ApiClient, cves: list[str]) -> dict[str, dict[str, str]]:
    scores: dict[str, dict[str, str]] = {}
    chunks = [cves[start : start + 100] for start in range(0, len(cves), 100)]
    for number, chunk in enumerate(chunks, start=1):
        print(f"[EPSS {number}/{len(chunks)}] querying {len(chunk)} CVEs", flush=True)
        payload = api.get_json(EPSS_URL, params={"cve": ",".join(chunk)})
        for row in payload.get("data", []):
            if row.get("cve"):
                scores[row["cve"]] = row
        time.sleep(0.2)
    save_json("epss.json", scores)
    print(f"[EPSS] scores returned for {len(scores)} CVEs.", flush=True)
    return scores


def collect_kev(api: ApiClient) -> dict[str, dict[str, Any]]:
    print("[CISA KEV] Downloading catalog...", flush=True)
    payload = api.get_json(KEV_URL)
    save_json("kev_catalog.json", payload)
    records = {row["cveID"]: row for row in payload.get("vulnerabilities", []) if row.get("cveID")}
    print(f"[CISA KEV] {len(records)} catalog entries loaded.", flush=True)
    return records
