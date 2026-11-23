"""Вопрос 2: частые CWE, типы ошибок и сравнение с CWE Top 25 за 2025 год.

Запуск: uv run python scripts/3_analyze_cwe
"""

import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


ROOT = Path(__file__).resolve().parents[2]
TOP_25_URL = "https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html"
TOP_25 = (
    "CWE-79", "CWE-89", "CWE-352", "CWE-862", "CWE-787", "CWE-22", "CWE-416", "CWE-125", "CWE-78",
    "CWE-94", "CWE-120", "CWE-434", "CWE-476", "CWE-121", "CWE-502", "CWE-122", "CWE-863", "CWE-20",
    "CWE-284", "CWE-200", "CWE-306", "CWE-918", "CWE-77", "CWE-639", "CWE-770",
)
TOP_25_RANK = {code: rank for rank, code in enumerate(TOP_25, 1)}

# Аналитическая группировка для этой работы
GROUPS = {
    # 1. Работа с сырой памятью и указателями (C/C++)
    "CWE-119": "Ошибки памяти",
    "CWE-122": "Ошибки памяти",
    "CWE-125": "Ошибки памяти",
    "CWE-416": "Ошибки памяти",
    "CWE-787": "Ошибки памяти",

    # 2. Встраивание недоверенных данных в интерпретаторы и команды
    "CWE-77": "Инъекции и исполнение кода",
    "CWE-94": "Инъекции и исполнение кода",

    # 3. Небезопасная обработка сложных структур данных
    "CWE-502": "Десериализация",

    # 4. Валидация входных данных
    "CWE-20": "Валидация входных данных",

    # 5. Математические и логические вычисления
    "CWE-190": "Арифметические ошибки",
    "CWE-682": "Арифметические ошибки",

    # 6. Управление ресурсами и вычислительной нагрузкой
    "CWE-400": "Управление ресурсами",
    "CWE-404": "Управление ресурсами",
    "CWE-1176": "Управление ресурсами",

    # 7. Состояние переменных, потоков и аварийное завершение
    "CWE-248": "Состояние и обработка ошибок",
    "CWE-617": "Состояние и обработка ошибок",
    "CWE-665": "Состояние и обработка ошибок",
    "CWE-667": "Состояние и обработка ошибок",
}


def save_chart(path: Path, items: list[tuple[str, int]], title: str) -> None:
    fig, ax = plt.subplots(figsize=(10, max(4, 0.55 * len(items) + 1.5)))
    labels, values = zip(*reversed(items)) if items else ((), ())
    bars = ax.barh(labels, values, color="#4472c4")
    ax.bar_label(bars, padding=3)
    ax.set_xlabel("Число CVE")
    ax.set_xlim(0, max(values, default=0) + 1)
    ax.set_title(title)
    fig.tight_layout()
    fig.savefig(path, dpi=180)
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=ROOT / "data/vulnerabilities.csv")
    parser.add_argument("--output", type=Path, default=ROOT / "data/analysis/2_cwe")
    args = parser.parse_args()
    with args.input.open(encoding="utf-8-sig", newline="") as file:
        rows = [row for row in csv.DictReader(file) if row["review_status"] == "included"]
    args.output.mkdir(parents=True, exist_ok=True)

    counts = Counter()
    group_cves = defaultdict(set)
    top25_cves = set()
    without_cwe = 0
    unmapped = set()
    for row in rows:
        codes = {code.strip() for code in row["cwe"].split(";") if code.strip()}
        if not codes:
            without_cwe += 1
        for code in codes:
            counts[code] += 1
            group_cves[GROUPS.get(code, "Прочие ошибки")].add(row["cve_id"])
            if code not in GROUPS:
                unmapped.add(code)
            if code in TOP_25_RANK:
                top25_cves.add(row["cve_id"])

    ranking = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    fifth_count = ranking[min(4, len(ranking) - 1)][1] if ranking else 0
    top = [(code, count) for code, count in ranking if count >= fifth_count]
    save_chart(
        args.output / "top_cwe.png",
        top,
        f"Пять самых частых CWE",
    )

    groups = sorted(((group, len(cves)) for group, cves in group_cves.items()), key=lambda item: (-item[1], item[0]))
    save_chart(
        args.output / "cwe_groups.png",
        groups,
        f"CWE по группам",
    )

    with (args.output / "top25_comparison.csv").open("w", encoding="utf-8-sig", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["cwe", "cve_count", "top25_2025_rank"])
        writer.writerows((code, count, TOP_25_RANK.get(code, "")) for code, count in ranking)

    print(f"Включённых CVE: {len(rows)}; без CWE: {without_cwe}")
    print(f"CVE с кодом из CWE Top 25 (2025): {len(top25_cves)}")
    print(f"Графики: {args.output / 'top_cwe.png'}, {args.output / 'cwe_groups.png'}")
    print(f"Сравнение с Top 25: {args.output / 'top25_comparison.csv'} ({TOP_25_URL})")
    if unmapped:
        print(f"CWE в группе «Прочие ошибки»: {', '.join(sorted(unmapped))}")


if __name__ == "__main__":
    main()
