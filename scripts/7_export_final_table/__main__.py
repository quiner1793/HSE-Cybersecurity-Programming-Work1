"""Выгрузить итоговую таблицу из проверенной рабочей таблицы.

Запуск: uv run python scripts/7_export_final_table
"""

import csv
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "data/vulnerabilities.csv"
OUTPUT = ROOT / "data/vulnerabilities_final.csv"

FINAL_FIELDS = (
    "cve_id", "ghsa_id", "osv_id", "bdu_id",
    "published_cve", "published_bdu",
    "cwe", "cwe_source",
    "cvss31_nvd", "cvss31_cna", "cvss40", "cvss_bdu", "cvss_bdu_version",
    "epss", "epss_percentile", "epss_date",
    "in_kev", "kev_date_added",
    "affected", "fixed_version", "fix_commit", "fix_date",
    "reporter", "channel", "snapshot_date",
)


def main() -> None:
    with SOURCE.open(encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        missing = set(FINAL_FIELDS) - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"В исходной таблице отсутствуют поля: {sorted(missing)}")
        rows = [
            {field: row[field] for field in FINAL_FIELDS}
            for row in reader
            if row["review_status"] == "included"
        ]

    with OUTPUT.open("w", encoding="utf-8-sig", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=FINAL_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Итоговая таблица: {OUTPUT}")
    print(f"Включено CVE: {len(rows)}")


if __name__ == "__main__":
    main()
