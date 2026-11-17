#!/usr/bin/env python3
"""Create separate KEM and signature figures from summary_results.csv."""

from __future__ import annotations

import csv
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import StrMethodFormatter


INPUT_CSV = "summary_results.csv"
ENVIRONMENT_FILE = "environment.txt"

EXPECTED_ALGORITHMS = {
    "X25519",
    "ML-KEM-768",
    "Classic-McEliece-460896",
    "HQC-192",
    "Hybrid-X25519-ML-KEM-768",
    "ML-KEM-1024",
    "Classic-McEliece-6960119",
    "HQC-256",
    "Hybrid-X25519-ML-KEM-1024",
    "Ed25519",
    "ML-DSA-87",
    "SLH-DSA-SHA2-256s",
    "SLH-DSA-SHA2-256f",
}


def load_rows() -> list[dict[str, str]]:
    with open(INPUT_CSV, newline="", encoding="utf-8") as source:
        rows = list(csv.DictReader(source))
    names = [row["algorithm"] for row in rows]
    if len(rows) != 13 or len(set(names)) != 13 or set(names) != EXPECTED_ALGORITHMS:
        raise ValueError("expected the 13 benchmarked algorithms exactly once")
    if sum(row["kind"] == "KEM" for row in rows) != 9:
        raise ValueError("expected 9 KEM rows")
    if sum(row["kind"] == "SIG" for row in rows) != 4:
        raise ValueError("expected 4 signature rows")
    return rows


def machine_footer() -> str:
    path = Path(ENVIRONMENT_FILE)
    if not path.exists():
        return ""
    return next(
        (line for line in path.read_text(encoding="utf-8").splitlines() if line.startswith("Machine:")),
        "",
    )


def add_footer(fig: plt.Figure, footer: str) -> None:
    if footer:
        fig.text(0.01, 0.01, footer, ha="left", va="bottom", fontsize=6.5)


def positive_values(rows: list[dict[str, str]], field: str) -> list[float]:
    result = [float(row[field]) for row in rows]
    if any(value <= 0 for value in result):
        raise ValueError(f"{field} contains non-positive values")
    return result


def log_chart_with_table(
    rows: list[dict[str, str]],
    fields: list[str],
    labels: list[str],
    title: str,
    ylabel: str,
    output_path: str,
    integer_values: bool,
    ratio_label: str,
    footer: str,
    show_iqr: bool = False,
) -> None:
    names = [row["algorithm"] for row in rows]
    x = list(range(len(rows)))
    width = 0.24
    offsets = (-width, 0.0, width)
    figure_width = 23 if len(rows) > 6 else 19
    fig, (ax, table_ax) = plt.subplots(
        1,
        2,
        figsize=(figure_width, 8),
        gridspec_kw={"width_ratios": [1.65, 1.0]},
    )

    for field, label, offset in zip(fields, labels, offsets):
        values = positive_values(rows, field)
        error = None
        if show_iqr:
            prefix = field.removesuffix("_ms_median")
            q1 = positive_values(rows, f"{prefix}_ms_q1")
            q3 = positive_values(rows, f"{prefix}_ms_q3")
            error = [
                [max(0.0, value - low) for value, low in zip(values, q1)],
                [max(0.0, high - value) for value, high in zip(values, q3)],
            ]
        ax.bar(
            [position + offset for position in x],
            values,
            width=width,
            label=label,
            yerr=error,
            capsize=2 if error else 0,
        )

    ax.set_yscale("log")
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=25, ha="right", fontsize=8)
    ax.legend(fontsize=8)
    ax.grid(axis="y", which="both", alpha=0.22)

    def display_value(row: dict[str, str], field: str) -> str:
        if integer_values:
            return f"{int(row[field]):,}"
        prefix = field.removesuffix("_ms_median")
        return f"{float(row[field]):.4f} [{float(row[f'{prefix}_ms_iqr']):.4f}]"

    table_rows = []
    for row in rows:
        ratio = row["primary_size_ratio"]
        ratio_text = f"{float(ratio):.3f}" if ratio else "N/A"
        table_rows.append(
            [
                row["algorithm"],
                f"L{row['security_level']}" if row["security_level"] else "-",
                *(display_value(row, field) for field in fields),
                ratio_text,
            ]
        )
    table_ax.axis("off")
    table = table_ax.table(
        cellText=table_rows,
        colLabels=["Algorithm", "Level", *labels, ratio_label],
        loc="center",
        cellLoc="right",
        colLoc="center",
    )
    table.auto_set_font_size(False)
    table.set_fontsize(7.2 if len(rows) > 6 else 8)
    table.scale(1.0, 1.42)
    table.auto_set_column_width(range(len(labels) + 3))
    table_ax.set_title(
        "Absolute values" + (" — median [IQR]" if show_iqr else ""), pad=14
    )

    add_footer(fig, footer)
    fig.tight_layout(rect=(0, 0.055, 1, 1))
    fig.savefig(output_path, dpi=180)
    plt.close(fig)
    print(f"wrote {output_path}")


def linear_kem_public_keys(
    rows: list[dict[str, str]], output_path: str, footer: str
) -> None:
    names = [row["algorithm"] for row in rows]
    public_keys = [int(row["public_key_bytes"]) for row in rows]
    colors = []
    for row in rows:
        if row["family"] == "Classical":
            colors.append("#777777")
        elif row["family"] == "Hybrid":
            colors.append("#54a24b")
        elif row["security_level"] == "3":
            colors.append("#4c78a8")
        else:
            colors.append("#f58518")

    fig, ax = plt.subplots(figsize=(17, 8))
    bars = ax.bar(range(len(rows)), public_keys, color=colors)
    ax.set_title("KEM public-key sizes — linear scale")
    ax.set_ylabel("public key (bytes)")
    ax.set_xticks(range(len(rows)))
    ax.set_xticklabels(names, rotation=25, ha="right", fontsize=8)
    ax.yaxis.set_major_formatter(StrMethodFormatter("{x:,.0f}"))
    ax.grid(axis="y", alpha=0.25)
    ax.bar_label(bars, labels=[f"{value:,}" for value in public_keys], padding=3, fontsize=7)
    for label, color in (
        ("Classical", "#777777"),
        ("NIST level 3", "#4c78a8"),
        ("NIST level 5", "#f58518"),
        ("Hybrid", "#54a24b"),
    ):
        ax.plot([], [], color=color, linewidth=8, label=label)
    ax.legend(fontsize=8)
    add_footer(fig, footer)
    fig.tight_layout(rect=(0, 0.055, 1, 1))
    fig.savefig(output_path, dpi=180)
    plt.close(fig)
    print(f"wrote {output_path}")


def main() -> None:
    rows = load_rows()
    kems = [row for row in rows if row["kind"] == "KEM"]
    signatures = [row for row in rows if row["kind"] == "SIG"]
    footer = machine_footer()
    size_fields = ["public_key_bytes", "secret_key_bytes", "ciphertext_or_sig_bytes"]
    timing_fields = ["keygen_ms_median", "op1_ms_median", "op2_ms_median"]

    log_chart_with_table(
        kems,
        size_fields,
        ["public key (B)", "secret key (B)", "ciphertext (B)"],
        "KEM artefact sizes — classical, PQC, and hybrids",
        "bytes (log scale)",
        "kem_sizes.png",
        True,
        "pk ÷ level ML-KEM",
        footer,
    )
    log_chart_with_table(
        signatures,
        size_fields,
        ["public key (B)", "secret key (B)", "signature (B)"],
        "Signature artefact sizes — classical and PQC",
        "bytes (log scale)",
        "signature_sizes.png",
        True,
        "sig ÷ Ed25519",
        footer,
    )
    log_chart_with_table(
        kems,
        timing_fields,
        ["keygen (ms)", "encaps (ms)", "decaps (ms)"],
        "KEM operation timings — median with IQR",
        "milliseconds (log scale)",
        "kem_timings.png",
        False,
        "pk size ratio",
        footer,
        True,
    )
    log_chart_with_table(
        signatures,
        timing_fields,
        ["keygen (ms)", "sign (ms)", "verify (ms)"],
        "Signature operation timings — median with IQR",
        "milliseconds (log scale)",
        "signature_timings.png",
        False,
        "sig size ratio",
        footer,
        True,
    )
    linear_kem_public_keys(kems, "kem_public_keys_linear.png", footer)


if __name__ == "__main__":
    main()
