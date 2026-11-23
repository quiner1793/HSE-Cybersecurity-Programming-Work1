"""Вопрос 1: пересечения каталогов и задержка публикации в БДУ.

Запуск: uv run python scripts/2_compare_sources
"""

import argparse
import csv
from collections import Counter
from datetime import date
from pathlib import Path
from statistics import median

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


ROOT = Path(__file__).resolve().parents[2]
BASES = ("NVD", "OSV", "БДУ")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=ROOT / "data/vulnerabilities.csv")
    parser.add_argument("--output", type=Path, default=ROOT / "data/analysis/1_sources")
    args = parser.parse_args()

    with args.input.open(encoding="utf-8-sig", newline="") as file:
        rows = [row for row in csv.DictReader(file) if row["review_status"] == "included"]
    args.output.mkdir(parents=True, exist_ok=True)

    lag_rows = []
    lag_days: list[int] = []
    patterns = Counter()
    coverage_counts = Counter()
    for row in rows:
        # Поле osv_id уже содержит результат сопоставления по CVE и aliases.
        flags = (
            row.get("in_nvd") == "yes" or bool(row.get("published_nvd")),
            bool(row["osv_id"]),
            bool(row["bdu_id"]),
        )
        pattern = " + ".join(base for base, flag in zip(BASES, flags) if flag) or "Нет данных"
        patterns[pattern] += 1
        coverage_counts[sum(flags)] += 1
        if flags[0] and flags[2]:
            published_cve = row["published_cve"]
            published_bdu = row["published_bdu"]
            days = (
                (date.fromisoformat(published_bdu) - date.fromisoformat(published_cve)).days
                if published_cve and published_bdu else None
            )
            lag_rows.append({
                "cve_id": row["cve_id"], "published_cve": published_cve,
                "published_bdu": published_bdu, "days_to_bdu": days if days is not None else "",
            })
            if days is not None:
                lag_days.append(days)

    lag_path = args.output / "bdu_lag.csv"
    with lag_path.open("w", encoding="utf-8-sig", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=["cve_id", "published_cve", "published_bdu", "days_to_bdu"])
        writer.writeheader()
        writer.writerows(sorted(lag_rows, key=lambda item: item["cve_id"]))

    combinations = []
    for mask in (1, 2, 4, 3, 5, 6, 7):
        bases = " + ".join(base for index, base in enumerate(BASES) if mask & (1 << index))
        label = f"Только {bases}" if mask.bit_count() == 1 else bases
        combinations.append({"combination": label, "count": patterns[bases]})

    fig, ax = plt.subplots(figsize=(10, 5))
    bars = ax.barh(
        [item["combination"] for item in reversed(combinations)],
        [item["count"] for item in reversed(combinations)],
        color="#4472c4",
    )
    ax.set_xlabel("Число CVE")
    ax.set_title(f"Пересечения NVD, OSV и БДУ (n={len(rows)})")
    ax.set_xlim(0, max((item["count"] for item in combinations), default=0) + 2)
    ax.bar_label(bars, padding=3)
    fig.tight_layout()
    fig.savefig(args.output / "intersections.png", dpi=180)
    plt.close(fig)
    print(f"График: {args.output / 'intersections.png'}; таблица задержек: {lag_path}")


if __name__ == "__main__":
    main()
