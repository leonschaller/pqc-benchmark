#!/usr/bin/env python3
"""Derive the UC1/UC2/UC3 metrics from summary_results.csv."""

from __future__ import annotations

import csv
from pathlib import Path


INPUT_CSV = "summary_results.csv"
UC1_CSV = "uc1_kem_metrics.csv"
UC2_CSV = "uc2_signature_metrics.csv"
UC3_CSV = "uc3_footprint_metrics.csv"
OUTPUT_TABLE = "scenario_tables.txt"

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

def load_summary() -> list[dict[str, str]]:
    with open(INPUT_CSV, newline="", encoding="utf-8") as source:
        rows = list(csv.DictReader(source))
    names = [row["algorithm"] for row in rows]
    if len(rows) != 13 or len(set(names)) != 13 or set(names) != EXPECTED_ALGORITHMS:
        raise ValueError("summary must contain the 13 benchmarked algorithms exactly once")
    return rows


def write_csv(path: str, fields: list[str], rows: list[dict[str, object]]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def ratio(value: float, baseline: float) -> float:
    if value <= 0 or baseline <= 0:
        raise ValueError("scenario ratios require positive values")
    return round(value / baseline, 6)


def derive_uc1(kems: list[dict[str, str]]) -> list[dict[str, object]]:
    baseline = next(row for row in kems if row["algorithm"] == "X25519")
    baseline_values = {
        "wire_ephemeral": int(baseline["public_key_bytes"]) + int(baseline["ciphertext_or_sig_bytes"]),
        "wire_static": int(baseline["ciphertext_or_sig_bytes"]),
        "latency_ephemeral": float(baseline["keygen_ms_median"]) + float(baseline["op1_ms_median"]) + float(baseline["op2_ms_median"]),
        "latency_static": float(baseline["op1_ms_median"]) + float(baseline["op2_ms_median"]),
    }
    output = []
    for row in kems:
        ephemeral_wire = int(row["public_key_bytes"]) + int(row["ciphertext_or_sig_bytes"])
        static_wire = int(row["ciphertext_or_sig_bytes"])
        ephemeral_latency = (
            float(row["keygen_ms_median"])
            + float(row["op1_ms_median"])
            + float(row["op2_ms_median"])
        )
        static_latency = float(row["op1_ms_median"]) + float(row["op2_ms_median"])
        output.append(
            {
                "algorithm": row["algorithm"],
                "security_level": row["security_level"],
                "family": row["family"],
                "ephemeral_wire_bytes": ephemeral_wire,
                "static_wire_bytes": static_wire,
                "preprovisioned_public_key_bytes": int(row["public_key_bytes"]),
                "ephemeral_crypto_latency_ms": round(ephemeral_latency, 6),
                "static_crypto_latency_ms": round(static_latency, 6),
                "ephemeral_wire_ratio_vs_x25519": ratio(ephemeral_wire, baseline_values["wire_ephemeral"]),
                "static_wire_ratio_vs_x25519": ratio(static_wire, baseline_values["wire_static"]),
                "ephemeral_latency_ratio_vs_x25519": ratio(ephemeral_latency, baseline_values["latency_ephemeral"]),
                "static_latency_ratio_vs_x25519": ratio(static_latency, baseline_values["latency_static"]),
                "latency_scope": "cryptographic component only; excludes RTT, transport, and authentication",
            }
        )
    return output


def derive_uc2(signatures: list[dict[str, str]]) -> list[dict[str, object]]:
    baseline = next(row for row in signatures if row["algorithm"] == "Ed25519")
    output = []
    for row in signatures:
        output.append(
            {
                "algorithm": row["algorithm"],
                "security_level": row["security_level"],
                "family": row["family"],
                "signature_bytes": int(row["ciphertext_or_sig_bytes"]),
                "verify_ms": float(row["op2_ms_median"]),
                "public_key_provisioning_bytes": int(row["public_key_bytes"]),
                "sign_ms_secondary": float(row["op1_ms_median"]),
                "signature_size_ratio_vs_ed25519": ratio(
                    int(row["ciphertext_or_sig_bytes"]),
                    int(baseline["ciphertext_or_sig_bytes"]),
                ),
                "verify_time_ratio_vs_ed25519": ratio(
                    float(row["op2_ms_median"]), float(baseline["op2_ms_median"])
                ),
                "public_key_ratio_vs_ed25519": ratio(
                    int(row["public_key_bytes"]), int(baseline["public_key_bytes"])
                ),
                "note": "bytes and milliseconds remain separate; signing time is secondary",
            }
        )
    return output


def derive_uc3(kems: list[dict[str, str]]) -> list[dict[str, object]]:
    baseline = next(row for row in kems if row["algorithm"] == "X25519")
    baseline_footprint = int(baseline["public_key_bytes"]) + int(baseline["secret_key_bytes"])
    output = []
    for row in kems:
        footprint = int(row["public_key_bytes"]) + int(row["secret_key_bytes"])
        output.append(
            {
                "algorithm": row["algorithm"],
                "security_level": row["security_level"],
                "family": row["family"],
                "key_material_footprint_bytes": footprint,
                "peak_keygen_process_rss_kb": row["peak_ram_keygen_kb"],
                "peak_encaps_process_rss_kb": row["peak_ram_op1_kb"],
                "peak_decaps_process_rss_kb": row["peak_ram_op2_kb"],
                "footprint_ratio_vs_x25519": ratio(footprint, baseline_footprint),
                "timing_representativeness": "desktop timings are not representative for UC3",
                "ram_note": "fresh-process peak RSS is best-effort and kept separate from exact key footprint",
            }
        )
    return output


def text_table(rows: list[dict[str, object]], headers: list[str]) -> str:
    rendered = [[str(row[header]) for header in headers] for row in rows]
    widths = [
        max(len(header), *(len(row[index]) for row in rendered))
        for index, header in enumerate(headers)
    ]

    def line(values: list[str]) -> str:
        return "  ".join(value.ljust(widths[index]) for index, value in enumerate(values))

    return "\n".join(
        [line(headers), line(["-" * width for width in widths]), *(line(row) for row in rendered)]
    )


def main() -> None:
    summary = load_summary()
    kems = [row for row in summary if row["kind"] == "KEM"]
    signatures = [row for row in summary if row["kind"] == "SIG"]
    uc1 = derive_uc1(kems)
    uc2 = derive_uc2(signatures)
    uc3 = derive_uc3(kems)

    write_csv(UC1_CSV, list(uc1[0]), uc1)
    write_csv(UC2_CSV, list(uc2[0]), uc2)
    write_csv(UC3_CSV, list(uc3[0]), uc3)

    content = (
        "SCENARIO TABLES\n\n"
        "Assumptions:\n"
        "  UC1 ephemeral wire = pk + ct; latency = keygen + encaps + decaps.\n"
        "  UC1 static wire = ct; latency = encaps + decaps; pk is pre-provisioned.\n"
        "  UC2 keeps bytes and milliseconds separate. No composite score is invented.\n"
        "  UC3 primary footprint = pk + sk; desktop timings are not representative.\n\n"
        "UC1 KEM METRICS\n"
        + text_table(
            uc1,
            [
                "algorithm",
                "ephemeral_wire_bytes",
                "static_wire_bytes",
                "ephemeral_crypto_latency_ms",
                "static_crypto_latency_ms",
            ],
        )
        + "\n\nUC2 SIGNATURE METRICS\n"
        + text_table(
            uc2,
            [
                "algorithm",
                "signature_bytes",
                "verify_ms",
                "public_key_provisioning_bytes",
                "sign_ms_secondary",
            ],
        )
        + "\n\nUC3 KEY FOOTPRINT\n"
        + text_table(
            uc3,
            [
                "algorithm",
                "key_material_footprint_bytes",
                "footprint_ratio_vs_x25519",
            ],
        )
        + "\n"
    )
    Path(OUTPUT_TABLE).write_text(content, encoding="utf-8")
    print(f"wrote {UC1_CSV}, {UC2_CSV}, {UC3_CSV}, {OUTPUT_TABLE}")


if __name__ == "__main__":
    main()
