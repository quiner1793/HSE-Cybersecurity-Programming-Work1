"""Вопрос 4: исследователи, каналы раскрытия и даты исправления/публикации.

fix_date — дата выхода первой подтверждённой исправленной стабильной версии.

Запуск: uv run python scripts/5_analyze_disclosure
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


def write_csv(path: Path, fieldnames: list[str], rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=ROOT / "data/vulnerabilities.csv")
    parser.add_argument("--output", type=Path, default=ROOT / "data/analysis/4_disclosure")
    args = parser.parse_args()
    with args.input.open(encoding="utf-8-sig", newline="") as file:
        rows = [row for row in csv.DictReader(file) if row["review_status"] == "included"]
    args.output.mkdir(parents=True, exist_ok=True)

    disclosure = []
    channel_counts = Counter()
    gaps = []
    for row in rows:
        channel = row["channel"].strip() or "Не установлен"
        channel_counts[channel] += 1
        fix_date = row["fix_date"].strip()
        publication = row["published_cve"].strip()
        days = (date.fromisoformat(publication) - date.fromisoformat(fix_date)).days if fix_date and publication else None
        if days is not None:
            gaps.append(days)
        disclosure.append({
            "cve_id": row["cve_id"], "reporter": row["reporter"], "channel": channel,
            "fix_date": fix_date, "published_cve": publication,
        })

    columns = ["cve_id", "reporter", "channel", "fix_date", "published_cve"]
    counts = [{"channel": channel, "cve_count": count} for channel, count in
              sorted(channel_counts.items(), key=lambda item: (-item[1], item[0]))]
    write_csv(args.output / "disclosure_by_cve.csv", columns, disclosure)

    fig, ax = plt.subplots(figsize=(9, max(4, 0.55 * len(counts) + 1)))
    ax.barh([item["channel"] for item in reversed(counts)],
            [item["cve_count"] for item in reversed(counts)], color="#4472c4")
    ax.set_xlabel("Число CVE")
    ax.set_title(f"Каналы раскрытия, включённые CVE (n={len(rows)})")
    if ax.containers:
        ax.bar_label(ax.containers[0], padding=3)
    fig.tight_layout()
    fig.savefig(args.output / "channels.png", dpi=180)
    plt.close(fig)
    print(f"График: {args.output / 'channels.png'}; таблица: {args.output / 'disclosure_by_cve.csv'}")
    print(f"Пар с датами: {len(gaps)} из {len(rows)}; медиана «публикация CVE минус выпуск исправленной версии»: {median(gaps) if gaps else 'нет данных'} дней")
    print(f"Исправленная версия выпущена после публикации CVE: {sum(day < 0 for day in gaps)}")


if __name__ == "__main__":
    main()
