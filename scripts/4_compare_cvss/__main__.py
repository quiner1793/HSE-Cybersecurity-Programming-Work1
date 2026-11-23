"""Вопрос 3: сравнение CVSS NVD/CNA/БДУ и график CVSS–EPSS.

Запуск: uv run python scripts/4_compare_cvss
"""

import argparse
import csv
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle
from cvss import CVSS3, CVSS4


ROOT = Path(__file__).resolve().parents[2]
VERSIONS = {"3.0", "3.1", "4.0"}
BASE_METRICS = {
    "3.0": ("AV", "AC", "PR", "UI", "S", "C", "I", "A"),
    "3.1": ("AV", "AC", "PR", "UI", "S", "C", "I", "A"),
    "4.0": ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"),
}


def write_csv(path: Path, fieldnames: list[str], rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def parse_score(value: str, version: str) -> dict:
    """Берёт балл каталога; для вектора без балла рассчитывает базовый CVSS."""
    if not value:
        return {}
    if "CVSS:" in value:
        prefix, vector_tail = value.split("CVSS:", 1)
        vector = "CVSS:" + vector_tail.strip()
        reported = float(prefix.strip()) if prefix.strip() else None
    else:
        vector = f"CVSS:{version}/{value.strip()}"
        reported = None
    if not vector.startswith(f"CVSS:{version}/"):
        raise ValueError(f"Версия вектора не совпадает с колонкой: {value}")
    calculated = (CVSS4(vector) if version == "4.0" else CVSS3(vector)).scores()[0]
    return {"score": reported if reported is not None else calculated, "vector": vector}


def metrics(vector: str, version: str) -> dict[str, str]:
    values = dict(part.split(":", 1) for part in vector.split("/")[1:] if ":" in part)
    return {key: values.get(key, "") for key in BASE_METRICS[version]}


def compare(cve_id: str, first: dict, second: dict) -> dict:
    first_metrics = metrics(first["vector"], first["version"])
    second_metrics = metrics(second["vector"], second["version"])
    changed = [f"{key}: {first_metrics[key]} → {second_metrics[key]}" for key in first_metrics
               if first_metrics[key] != second_metrics[key]]
    delta = round(first["score"] - second["score"], 1)
    return {
        "cve_id": cve_id, "source_a": first["source"], "version_a": first["version"],
        "score_a": first["score"], "vector_a": first["vector"],
        "source_b": second["source"], "version_b": second["version"],
        "score_b": second["score"], "vector_b": second["vector"],
        "delta_a_minus_b": delta, "abs_delta": round(abs(delta), 1),
        "different_base_metrics": "; ".join(changed) if changed else "Базовые метрики совпадают",
    }


def plot_by_cve(path: Path, rows: list[dict]) -> None:
    """Показывает точные оценки 3.x в компактной матрице по каждой CVE."""
    rows = sorted(rows, key=lambda row: row["cve_id"])
    bdu_versions = sorted({row["БДУ"]["version"] for row in rows if row["БДУ"]})
    bdu_header = "БДУ " + "/".join(bdu_versions) if bdu_versions else "БДУ 3.x"
    sources = (("NVD", "NVD 3.1"), ("CNA", "CNA 3.1"), ("БДУ", bdu_header))
    split = (len(rows) + 1) // 2
    groups = (rows[:split], rows[split:])
    fig, axes = plt.subplots(1, 2, figsize=(14, max(7, 0.46 * split + 2)))
    palette = plt.get_cmap("YlOrRd")

    for ax, group in zip(axes, groups):
        divergent_rows = []
        for index, row in enumerate(group):
            scores = [row[source]["score"] for source, _ in sources if row[source] is not None]
            for column, (source, _) in enumerate(sources):
                entry = row[source]
                color = palette(0.12 + 0.83 * entry["score"] / 10) if entry else "#eceff1"
                ax.add_patch(Rectangle((column - 0.5, index - 0.5), 1, 1,
                                       facecolor=color, edgecolor="white", linewidth=2))
                label = f"{entry['score']:.1f}" if entry else "—"
                if source == "БДУ" and entry and len(bdu_versions) > 1:
                    label += f" ({entry['version']})"
                ax.text(column, index, label, ha="center", va="center", fontsize=10,
                        fontweight="bold" if entry else "normal",
                        color="white" if entry and entry["score"] >= 7 else "#263238")
            if len(scores) >= 2 and max(scores) - min(scores) >= 1:
                divergent_rows.append(index)

        ax.set_xlim(-0.5, 2.5)
        ax.set_ylim(len(group) - 0.5, -0.5)
        ax.set_xticks(range(len(sources)), [label for _, label in sources])
        ax.xaxis.tick_top()
        ax.set_yticks(range(len(group)), [row["cve_id"] for row in group])
        for index in divergent_rows:
            ax.get_yticklabels()[index].set_color("#b71c1c")
            ax.get_yticklabels()[index].set_fontweight("bold")
        ax.tick_params(length=0, pad=7)
        for spine in ax.spines.values():
            spine.set_visible(False)

    fig.suptitle(f"Оценки CVSS 3.x по CVE (n={len(rows)})", fontsize=14)
    fig.text(0.5, 0.035,
             "Серый — нет оценки данного источника; оценки ADP не показаны. "
             "Красный CVE — разброс от 1 балла.",
             ha="center", fontsize=9)
    fig.tight_layout(rect=(0, 0.07, 1, 0.94), w_pad=4)
    fig.savefig(path, dpi=180)
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=ROOT / "data/vulnerabilities.csv")
    parser.add_argument("--output", type=Path, default=ROOT / "data/analysis/3_cvss")
    args = parser.parse_args()
    with args.input.open(encoding="utf-8-sig", newline="") as file:
        rows = [row for row in csv.DictReader(file) if row["review_status"] == "included"]
    args.output.mkdir(parents=True, exist_ok=True)

    comparisons = []
    points = []
    chart_rows = []
    for row in rows:
        by_source: dict[str, dict[str, dict]] = {source: {} for source in ("NVD", "CNA", "БДУ", "CVSS 4.0")}
        for source, field in (("NVD", "cvss31_nvd"), ("CNA", "cvss31_cna"), ("CVSS 4.0", "cvss40")):
            version = "4.0" if source == "CVSS 4.0" else "3.1"
            if row.get(field, ""):
                entry = {"cve_id": row["cve_id"], "source": source, "version": version,
                         **parse_score(row[field], version)}
                by_source[source][version] = entry
        if row["cvss_bdu"] and row["cvss_bdu_version"] == "2.0":
            # CVSS 2.0 нельзя сопоставлять с оценками 3.x/4.0.
            pass
        elif row["cvss_bdu"]:
            version = row["cvss_bdu_version"]
            if version not in VERSIONS:
                raise ValueError(f"Неизвестная версия CVSS БДУ у {row['cve_id']}: {version}")
            entry = {"cve_id": row["cve_id"], "source": "БДУ", "version": version,
                     **parse_score(row["cvss_bdu"], version)}
            by_source["БДУ"][version] = entry

        if "3.1" in by_source["NVD"] and "3.1" in by_source["CNA"]:
            comparisons.append(compare(row["cve_id"], by_source["NVD"]["3.1"], by_source["CNA"]["3.1"]))
        # С БДУ сравниваем оценки 3.x; 4.0 сопоставляем только с 4.0.
        for source in ("NVD", "CNA"):
            if "3.1" in by_source[source]:
                for bdu_version in ("3.0", "3.1"):
                    if bdu_version in by_source["БДУ"]:
                        comparisons.append(compare(row["cve_id"], by_source[source]["3.1"],
                                                   by_source["БДУ"][bdu_version]))
        if "4.0" in by_source["CVSS 4.0"] and "4.0" in by_source["БДУ"]:
            comparisons.append(compare(row["cve_id"], by_source["CVSS 4.0"]["4.0"], by_source["БДУ"]["4.0"]))

        chart_rows.append({
            "cve_id": row["cve_id"],
            "NVD": by_source["NVD"].get("3.1"),
            "CNA": by_source["CNA"].get("3.1"),
            "БДУ": by_source["БДУ"].get("3.1") or by_source["БДУ"].get("3.0"),
        })

        # На одном графике только CVSS 3.x; приоритет источников задан ниже.
        plot_entry = next((by_source[source][version] for source, version in
                           (("NVD", "3.1"), ("CNA", "3.1"), ("БДУ", "3.1"), ("БДУ", "3.0"))
                           if version in by_source[source]), None)
        if plot_entry and row["epss"]:
            points.append({"cve_id": row["cve_id"], "epss_percent": round(float(row["epss"]) * 100, 6),
                           "cvss_score": plot_entry["score"], "cvss_source": plot_entry["source"],
                           "cvss_version": plot_entry["version"], "in_kev": row["in_kev"]})

    comparison_columns = ["cve_id", "source_a", "version_a", "score_a", "vector_a", "source_b", "version_b",
                          "score_b", "vector_b", "delta_a_minus_b", "abs_delta", "different_base_metrics"]
    write_csv(args.output / "comparisons.csv", comparison_columns, comparisons)
    plot_by_cve(args.output / "cvss_by_cve.png", chart_rows)

    fig, ax = plt.subplots(figsize=(9, 6))
    colors = {"NVD": "#4472c4", "CNA": "#70ad47", "БДУ": "#ed7d31"}
    for source, color in colors.items():
        subset = [item for item in points if item["cvss_source"] == source]
        if subset:
            ax.scatter([item["epss_percent"] for item in subset], [item["cvss_score"] for item in subset],
                       color=color, s=50, alpha=0.8, label=f"{source} (n={len(subset)})")
    kev = [item for item in points if item["in_kev"].lower() == "yes"]
    if kev:
        ax.scatter([item["epss_percent"] for item in kev], [item["cvss_score"] for item in kev],
                   facecolors="none", edgecolors="#c00000", s=170, linewidths=2, label=f"KEV (n={len(kev)})")
        for item in kev:
            ax.annotate(item["cve_id"], (item["epss_percent"], item["cvss_score"]), xytext=(5, 5),
                        textcoords="offset points", fontsize=8)
    else:
        ax.text(0.98, 0.98, "Записей в KEV: 0", transform=ax.transAxes, ha="right", va="top",
                fontsize=9, bbox={"facecolor": "white", "edgecolor": "#cccccc"})
    if points and all(item["epss_percent"] > 0 for item in points):
        ax.set_xscale("log")
        ax.set_xlabel("EPSS, % (логарифмическая шкала)")
    else:
        ax.set_xlabel("EPSS, %")
    ax.set_ylabel("Базовый балл CVSS 3.x")
    ax.set_ylim(0, 10.5)
    ax.set_title(f"CVSS и EPSS, включённые CVE (n={len(points)}, KEV={len(kev)})")
    ax.grid(alpha=0.2)
    if ax.get_legend_handles_labels()[0]:
        ax.legend()
    fig.tight_layout()
    fig.savefig(args.output / "cvss_epss.png", dpi=180)
    plt.close(fig)
    print(f"Графики: {args.output / 'cvss_by_cve.png'}, {args.output / 'cvss_epss.png'}")
    print(f"Таблица пар оценок: {args.output / 'comparisons.csv'}")
    print(f"Сопоставимых пар: {len(comparisons)}; расхождений от 1 балла: {sum(item['abs_delta'] >= 1 for item in comparisons)}")
    print(f"Точек CVSS–EPSS: {len(points)} из {len(rows)}; из них в KEV: {len(kev)}")


if __name__ == "__main__":
    main()
