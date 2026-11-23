import argparse
import datetime as dt
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RAW_DIR = ROOT / "data" / "raw"
BDU_XLSX = RAW_DIR / "bdu_vullist.xlsx"
OUTPUT_CSV = ROOT / "data" / "vulnerabilities.csv"
START_DATE = dt.date(2020, 1, 1)

FIELDS = [
    "cve_id",
    "ghsa_id",
    "osv_id",
    "bdu_id",
    "published_cve",
    "published_nvd",
    "published_osv",
    "published_ghsa",
    "published_bdu",
    "cwe",
    "cwe_source",
    "cvss31_nvd",
    "cvss31_cna",
    "cvss40",
    "cvss_bdu",
    "cvss_bdu_version",
    "epss",
    "epss_percentile",
    "epss_date",
    "in_kev",
    "kev_date_added",
    "affected",
    "fixed_version",
    "fix_commit",
    "fix_date",
    "reporter",
    "channel",
    "snapshot_date",
    "description",
    "nvd_cpe",
    "review_status",
    "review_notes",
]


def parse_args() -> dt.date:
    parser = argparse.ArgumentParser(description="Collect PyTorch vulnerability candidates from public APIs.")
    parser.add_argument(
        "--end",
        type=dt.date.fromisoformat,
        default=dt.date.today(),
        help="Inclusive end date in YYYY-MM-DD format (default: today).",
    )
    args = parser.parse_args()
    if args.end < START_DATE:
        parser.error("--end must not precede 2020-01-01")
    from dotenv import load_dotenv

    load_dotenv(ROOT / ".env")
    return args.end
