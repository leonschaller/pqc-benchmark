#!/usr/bin/env python3
"""Validate the PQC benchmark data set.

The verifier intentionally uses only Python's standard library.  It checks the
raw measurements against the summary instead of trusting the generated tables,
and then checks that the three use-case CSVs were derived from that summary.
It exits non-zero if any check fails.
"""

from __future__ import annotations

import argparse
import csv
import math
import re
import statistics
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class AlgorithmSpec:
    kind: str
    public_key_bytes: int
    secret_key_bytes: int
    ciphertext_or_sig_bytes: int
    shared_secret_bytes: int | None


# These are the exact sizes for the implementations used in this benchmark.
# In particular, the HQC values are the installed liboqs 0.16.0 values rather
# than sizes copied from a different HQC/liboqs release.
ALGORITHMS = {
    "X25519": AlgorithmSpec("KEM", 32, 32, 32, 32),
    "ML-KEM-768": AlgorithmSpec("KEM", 1184, 2400, 1088, 32),
    "Classic-McEliece-460896": AlgorithmSpec("KEM", 524160, 13608, 156, 32),
    "HQC-192": AlgorithmSpec("KEM", 4514, 4602, 8978, 32),
    "Hybrid-X25519-ML-KEM-768": AlgorithmSpec("KEM", 1216, 2432, 1120, 64),
    "ML-KEM-1024": AlgorithmSpec("KEM", 1568, 3168, 1568, 32),
    "Classic-McEliece-6960119": AlgorithmSpec("KEM", 1047319, 13948, 194, 32),
    "HQC-256": AlgorithmSpec("KEM", 7237, 7333, 14421, 32),
    "Hybrid-X25519-ML-KEM-1024": AlgorithmSpec("KEM", 1600, 3200, 1600, 64),
    "Ed25519": AlgorithmSpec("SIG", 32, 64, 64, None),
    "ML-DSA-87": AlgorithmSpec("SIG", 2592, 4896, 4627, None),
    "SLH-DSA-SHA2-256s": AlgorithmSpec("SIG", 64, 128, 29792, None),
    "SLH-DSA-SHA2-256f": AlgorithmSpec("SIG", 64, 128, 49856, None),
}

KEMS = {name for name, spec in ALGORITHMS.items() if spec.kind == "KEM"}
SIGNATURES = {name for name, spec in ALGORITHMS.items() if spec.kind == "SIG"}

SUMMARY_REQUIRED = {
    "run_id",
    "kind",
    "algorithm",
    "public_key_bytes",
    "secret_key_bytes",
    "ciphertext_or_sig_bytes",
    "shared_secret_bytes",
    "keygen_ms_median",
    "keygen_ms_q1",
    "keygen_ms_q3",
    "keygen_ms_iqr",
    "keygen_ms_stddev",
    "op1_ms_median",
    "op1_ms_q1",
    "op1_ms_q3",
    "op1_ms_iqr",
    "op1_ms_stddev",
    "op2_ms_median",
    "op2_ms_q1",
    "op2_ms_q3",
    "op2_ms_iqr",
    "op2_ms_stddev",
    "keygen_iterations",
    "op1_iterations",
    "op2_iterations",
    "warmups",
    "peak_ram_keygen_kb",
    "peak_ram_op1_kb",
    "peak_ram_op2_kb",
    "peak_ram_method",
    "size_check",
}

RAW_REQUIRED = {
    "run_id",
    "kind",
    "algorithm",
    "operation",
    "sample_index",
    "elapsed_ns",
    "elapsed_ms",
    "success",
    "cpu_core",
    "public_key_bytes",
    "secret_key_bytes",
    "ciphertext_or_sig_bytes",
    "shared_secret_bytes",
}

MEMORY_REQUIRED = {
    "run_id",
    "algorithm",
    "operation",
    "trial",
    "pid",
    "baseline_rss_kb",
    "baseline_hwm_kb",
    "after_rss_kb",
    "peak_rss_kb",
    "incremental_hwm_kb",
    "method",
    "scope",
}

UC1_REQUIRED = {
    "algorithm",
    "ephemeral_wire_bytes",
    "static_wire_bytes",
    "preprovisioned_public_key_bytes",
    "ephemeral_crypto_latency_ms",
    "static_crypto_latency_ms",
    "ephemeral_wire_ratio_vs_x25519",
    "static_wire_ratio_vs_x25519",
    "ephemeral_latency_ratio_vs_x25519",
    "static_latency_ratio_vs_x25519",
}

UC2_REQUIRED = {
    "algorithm",
    "signature_bytes",
    "verify_ms",
    "public_key_provisioning_bytes",
    "sign_ms_secondary",
    "signature_size_ratio_vs_ed25519",
    "verify_time_ratio_vs_ed25519",
    "public_key_ratio_vs_ed25519",
}

UC3_REQUIRED = {
    "algorithm",
    "key_material_footprint_bytes",
    "peak_keygen_process_rss_kb",
    "peak_encaps_process_rss_kb",
    "peak_decaps_process_rss_kb",
    "footprint_ratio_vs_x25519",
}


class Checks:
    def __init__(self) -> None:
        self.errors: list[str] = []

    def require(self, condition: bool, message: str) -> None:
        if not condition:
            self.errors.append(message)

    def integer(
        self,
        row: dict[str, str],
        field: str,
        where: str,
        *,
        minimum: int | None = None,
    ) -> int | None:
        value = row.get(field, "").strip()
        if not re.fullmatch(r"[+-]?\d+", value):
            self.errors.append(f"{where}: {field} is not an integer: {value!r}")
            return None
        parsed = int(value)
        if minimum is not None and parsed < minimum:
            self.errors.append(
                f"{where}: {field} is {parsed}, expected at least {minimum}"
            )
        return parsed

    def number(
        self,
        row: dict[str, str],
        field: str,
        where: str,
        *,
        minimum: float | None = None,
    ) -> float | None:
        value = row.get(field, "").strip()
        try:
            parsed = float(value)
        except ValueError:
            self.errors.append(f"{where}: {field} is not numeric: {value!r}")
            return None
        if not math.isfinite(parsed):
            self.errors.append(f"{where}: {field} is not finite: {value!r}")
            return None
        if minimum is not None and parsed < minimum:
            self.errors.append(
                f"{where}: {field} is {parsed}, expected at least {minimum}"
            )
        return parsed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary-csv", default="summary_results.csv")
    parser.add_argument("--raw-csv", default="raw_results.csv")
    parser.add_argument("--memory-csv", default="memory_results.csv")
    parser.add_argument("--uc1-csv", default="uc1_kem_metrics.csv")
    parser.add_argument("--uc2-csv", default="uc2_signature_metrics.csv")
    parser.add_argument("--uc3-csv", default="uc3_footprint_metrics.csv")
    return parser.parse_args()


def read_csv(
    path_text: str, required: set[str], label: str, checks: Checks
) -> list[dict[str, str]]:
    path = Path(path_text)
    if not path.is_file():
        checks.errors.append(f"{label}: file does not exist: {path}")
        return []
    try:
        with path.open(newline="", encoding="utf-8-sig") as source:
            reader = csv.DictReader(source)
            fields = reader.fieldnames
            if fields is None:
                checks.errors.append(f"{label}: CSV has no header")
                return []
            duplicates = sorted({field for field in fields if fields.count(field) > 1})
            checks.require(not duplicates, f"{label}: duplicate header fields: {duplicates}")
            missing = sorted(required - set(fields))
            checks.require(not missing, f"{label}: missing required fields: {missing}")
            rows = list(reader)
    except (OSError, UnicodeError, csv.Error) as error:
        checks.errors.append(f"{label}: cannot read CSV: {error}")
        return []

    for index, row in enumerate(rows, 2):
        if None in row:
            checks.errors.append(f"{label}: row {index} has values beyond the header")
        if not any((value or "").strip() for key, value in row.items() if key is not None):
            checks.errors.append(f"{label}: row {index} is empty")
    checks.require(bool(rows), f"{label}: CSV contains no data rows")
    return rows


def unique_index(
    rows: Iterable[dict[str, str]],
    expected_names: set[str],
    label: str,
    checks: Checks,
) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    names: list[str] = []
    for row in rows:
        name = row.get("algorithm", "").strip()
        names.append(name)
        if name in result:
            checks.errors.append(f"{label}: duplicate algorithm row: {name!r}")
        else:
            result[name] = row
    checks.require(
        set(names) == expected_names,
        f"{label}: algorithm set differs; missing={sorted(expected_names - set(names))}, "
        f"unexpected={sorted(set(names) - expected_names)}",
    )
    checks.require(
        len(rows) == len(expected_names),
        f"{label}: expected {len(expected_names)} rows, found {len(rows)}",
    )
    return result


def rounded_equal(actual: float, expected: float, digits: int = 6) -> bool:
    """Return true when values are identical at the published precision."""
    return round(actual, digits) == round(expected, digits)


def expect_int(
    row: dict[str, str], field: str, expected: int, where: str, checks: Checks
) -> None:
    actual = checks.integer(row, field, where)
    if actual is not None:
        checks.require(
            actual == expected,
            f"{where}: {field}={actual}, expected {expected}",
        )


def expect_number(
    row: dict[str, str], field: str, expected: float, where: str, checks: Checks
) -> None:
    actual = checks.number(row, field, where)
    if actual is not None:
        checks.require(
            rounded_equal(actual, expected),
            f"{where}: {field}={actual}, expected {round(expected, 6)}",
        )


def validate_summary(
    rows: list[dict[str, str]], checks: Checks
) -> dict[str, dict[str, str]]:
    by_name = unique_index(rows, set(ALGORITHMS), "summary", checks)
    kinds = [row.get("kind", "").strip() for row in rows]
    checks.require(kinds.count("KEM") == 9, f"summary: expected 9 KEM rows, found {kinds.count('KEM')}")
    checks.require(kinds.count("SIG") == 4, f"summary: expected 4 SIG rows, found {kinds.count('SIG')}")

    run_ids = {row.get("run_id", "").strip() for row in rows}
    checks.require("" not in run_ids, "summary: run_id must not be blank")
    checks.require(len(run_ids) == 1, f"summary: expected one run_id, found {sorted(run_ids)}")

    for name, spec in ALGORITHMS.items():
        row = by_name.get(name)
        if row is None:
            continue
        where = f"summary/{name}"
        checks.require(row.get("kind", "").strip() == spec.kind, f"{where}: wrong kind")
        expect_int(row, "public_key_bytes", spec.public_key_bytes, where, checks)
        expect_int(row, "secret_key_bytes", spec.secret_key_bytes, where, checks)
        expect_int(
            row,
            "ciphertext_or_sig_bytes",
            spec.ciphertext_or_sig_bytes,
            where,
            checks,
        )
        if spec.shared_secret_bytes is None:
            checks.require(
                row.get("shared_secret_bytes", "").strip() == "",
                f"{where}: signatures must have a blank shared_secret_bytes",
            )
        else:
            expect_int(
                row,
                "shared_secret_bytes",
                spec.shared_secret_bytes,
                where,
                checks,
            )
        for field in ("keygen_iterations", "op1_iterations", "op2_iterations"):
            checks.integer(row, field, where, minimum=1)
        checks.integer(row, "warmups", where, minimum=0)
        for prefix in ("keygen", "op1", "op2"):
            for stat in ("median", "q1", "q3"):
                checks.number(row, f"{prefix}_ms_{stat}", where, minimum=0.0)
            for stat in ("iqr", "stddev"):
                checks.number(row, f"{prefix}_ms_{stat}", where, minimum=0.0)
        checks.require(
            row.get("size_check", "").strip().startswith("PASS"),
            f"{where}: size_check does not report PASS",
        )
    return by_name


def operations_for(name: str) -> tuple[str, str, str]:
    return ("keygen", "encaps", "decaps") if name in KEMS else ("keygen", "sign", "verify")


def summary_prefix(operation: str) -> str:
    return {
        "keygen": "keygen",
        "encaps": "op1",
        "sign": "op1",
        "decaps": "op2",
        "verify": "op2",
    }[operation]


def recompute_stats(samples_ns: list[int]) -> dict[str, float]:
    if len(samples_ns) == 1:
        q1_ns = q3_ns = float(samples_ns[0])
    else:
        quartiles = statistics.quantiles(samples_ns, n=4, method="inclusive")
        q1_ns, q3_ns = quartiles[0], quartiles[2]
    median_ns = float(statistics.median(samples_ns))
    stddev_ns = float(statistics.pstdev(samples_ns))
    return {
        "median": median_ns / 1_000_000,
        "q1": q1_ns / 1_000_000,
        "q3": q3_ns / 1_000_000,
        "iqr": (q3_ns - q1_ns) / 1_000_000,
        "stddev": stddev_ns / 1_000_000,
    }


def validate_raw(
    rows: list[dict[str, str]],
    summary: dict[str, dict[str, str]],
    checks: Checks,
) -> None:
    seen_keys: set[tuple[str, str, str, int]] = set()
    groups: dict[tuple[str, str], list[tuple[int, int]]] = {}
    raw_names = {row.get("algorithm", "").strip() for row in rows}
    checks.require(
        raw_names == set(ALGORITHMS),
        f"raw: algorithm set differs; missing={sorted(set(ALGORITHMS) - raw_names)}, "
        f"unexpected={sorted(raw_names - set(ALGORITHMS))}",
    )

    raw_run_ids = {row.get("run_id", "").strip() for row in rows}
    summary_run_ids = {row.get("run_id", "").strip() for row in summary.values()}
    checks.require("" not in raw_run_ids, "raw: run_id must not be blank")
    checks.require(len(raw_run_ids) == 1, f"raw: expected one run_id, found {sorted(raw_run_ids)}")
    checks.require(raw_run_ids == summary_run_ids, "raw: run_id does not match summary")

    cores = {row.get("cpu_core", "").strip() for row in rows}
    checks.require("" not in cores, "raw: cpu_core must not be blank")
    checks.require(len(cores) == 1, f"raw: measurements used multiple core labels: {sorted(cores)}")
    if len(cores) == 1:
        core = next(iter(cores))
        checks.require(
            bool(re.fullmatch(r"\d+", core)),
            f"raw: expected one pinned numeric CPU core, found {core!r}",
        )

    for row_number, row in enumerate(rows, 2):
        name = row.get("algorithm", "").strip()
        if name not in ALGORITHMS:
            continue
        spec = ALGORITHMS[name]
        where = f"raw row {row_number}/{name}"
        run_id = row.get("run_id", "").strip()
        operation = row.get("operation", "").strip()
        checks.require(row.get("kind", "").strip() == spec.kind, f"{where}: wrong kind")
        checks.require(
            operation in operations_for(name),
            f"{where}: invalid operation {operation!r}",
        )
        sample_index = checks.integer(row, "sample_index", where, minimum=1)
        elapsed_text = row.get("elapsed_ns", "").strip()
        if not re.fullmatch(r"[1-9]\d*", elapsed_text):
            checks.errors.append(f"{where}: elapsed_ns must be a positive integer, got {elapsed_text!r}")
            elapsed_ns = None
        else:
            elapsed_ns = int(elapsed_text)
        elapsed_ms = checks.number(row, "elapsed_ms", where, minimum=0.0)
        if elapsed_ns is not None and elapsed_ms is not None:
            checks.require(
                rounded_equal(elapsed_ms, elapsed_ns / 1_000_000),
                f"{where}: elapsed_ms does not equal elapsed_ns converted and rounded to 6 decimals",
            )
        checks.require(
            row.get("success", "").strip().lower() in {"true", "1", "yes", "pass"},
            f"{where}: success is not true",
        )
        expect_int(row, "public_key_bytes", spec.public_key_bytes, where, checks)
        expect_int(row, "secret_key_bytes", spec.secret_key_bytes, where, checks)
        expect_int(
            row,
            "ciphertext_or_sig_bytes",
            spec.ciphertext_or_sig_bytes,
            where,
            checks,
        )
        if spec.shared_secret_bytes is None:
            checks.require(
                row.get("shared_secret_bytes", "").strip() == "",
                f"{where}: signature row has a shared-secret size",
            )
        else:
            expect_int(
                row,
                "shared_secret_bytes",
                spec.shared_secret_bytes,
                where,
                checks,
            )
        if sample_index is not None and operation in operations_for(name):
            key = (run_id, name, operation, sample_index)
            checks.require(key not in seen_keys, f"raw: duplicate sample key {key}")
            seen_keys.add(key)
            if elapsed_ns is not None:
                groups.setdefault((name, operation), []).append((sample_index, elapsed_ns))

    for name in ALGORITHMS:
        summary_row = summary.get(name)
        if summary_row is None:
            continue
        for operation in operations_for(name):
            prefix = summary_prefix(operation)
            where = f"raw/{name}/{operation}"
            expected_count = checks.integer(
                summary_row, f"{prefix}_iterations", f"summary/{name}", minimum=1
            )
            samples = groups.get((name, operation), [])
            if expected_count is not None:
                checks.require(
                    len(samples) == expected_count,
                    f"{where}: found {len(samples)} samples, summary says {expected_count}",
                )
                indices = sorted(index for index, _ in samples)
                checks.require(
                    indices == list(range(1, expected_count + 1)),
                    f"{where}: sample_index values are not exactly 1..{expected_count}",
                )
            if not samples:
                continue
            stats = recompute_stats([elapsed for _, elapsed in samples])
            for stat, expected in stats.items():
                field = f"{prefix}_ms_{stat}"
                actual = checks.number(summary_row, field, f"summary/{name}")
                if actual is not None:
                    checks.require(
                        rounded_equal(actual, expected),
                        f"summary/{name}: {field}={actual}, raw recomputes to {round(expected, 6)}",
                    )


def validate_memory(
    rows: list[dict[str, str]],
    summary: dict[str, dict[str, str]],
    checks: Checks,
) -> None:
    names = {row.get("algorithm", "").strip() for row in rows}
    checks.require(
        names == set(ALGORITHMS),
        f"memory: algorithm set differs; missing={sorted(set(ALGORITHMS) - names)}, "
        f"unexpected={sorted(names - set(ALGORITHMS))}",
    )
    memory_runs = {row.get("run_id", "").strip() for row in rows}
    summary_runs = {row.get("run_id", "").strip() for row in summary.values()}
    checks.require("" not in memory_runs, "memory: run_id must not be blank")
    checks.require(len(memory_runs) == 1, f"memory: expected one run_id, found {sorted(memory_runs)}")
    checks.require(memory_runs == summary_runs, "memory: run_id does not match summary")

    declared_runs: set[int] = set()
    for name, row in summary.items():
        method = row.get("peak_ram_method", "").strip()
        match = re.search(r"max of (\d+) fresh-process", method)
        if not match:
            checks.errors.append(
                f"summary/{name}: peak_ram_method does not declare fresh-process repetition count"
            )
        else:
            declared_runs.add(int(match.group(1)))
    checks.require(
        len(declared_runs) == 1,
        f"summary: memory repetition counts are not one consistent value: {sorted(declared_runs)}",
    )
    repetition_count = next(iter(declared_runs)) if len(declared_runs) == 1 else None
    if repetition_count is not None:
        checks.require(repetition_count > 0, "summary: memory repetition count must be positive")
        checks.require(
            len(rows) == len(ALGORITHMS) * 3 * repetition_count,
            f"memory: expected {len(ALGORITHMS) * 3 * repetition_count} rows, found {len(rows)}",
        )

    seen_keys: set[tuple[str, str, str, int]] = set()
    seen_pids: set[int] = set()
    groups: dict[tuple[str, str], list[tuple[int, int]]] = {}
    for row_number, row in enumerate(rows, 2):
        name = row.get("algorithm", "").strip()
        if name not in ALGORITHMS:
            continue
        operation = row.get("operation", "").strip()
        where = f"memory row {row_number}/{name}"
        checks.require(
            operation in operations_for(name),
            f"{where}: invalid operation {operation!r}",
        )
        trial = checks.integer(row, "trial", where, minimum=1)
        pid = checks.integer(row, "pid", where, minimum=1)
        baseline_rss = checks.integer(row, "baseline_rss_kb", where, minimum=1)
        baseline_hwm = checks.integer(row, "baseline_hwm_kb", where, minimum=1)
        after_rss = checks.integer(row, "after_rss_kb", where, minimum=1)
        peak = checks.integer(row, "peak_rss_kb", where, minimum=1)
        incremental = checks.integer(row, "incremental_hwm_kb", where, minimum=0)
        if baseline_rss is not None and baseline_hwm is not None:
            checks.require(
                baseline_hwm >= baseline_rss,
                f"{where}: baseline HWM is below baseline RSS",
            )
        if peak is not None and baseline_hwm is not None:
            checks.require(peak >= baseline_hwm, f"{where}: peak HWM is below baseline HWM")
        if peak is not None and after_rss is not None:
            checks.require(peak >= after_rss, f"{where}: peak HWM is below after-operation RSS")
        if peak is not None and baseline_hwm is not None and incremental is not None:
            checks.require(
                incremental == max(0, peak - baseline_hwm),
                f"{where}: incremental_hwm_kb is inconsistent with peak and baseline HWM",
            )
        checks.require(bool(row.get("method", "").strip()), f"{where}: method is blank")
        checks.require(
            "fresh process" in row.get("scope", "").strip().lower(),
            f"{where}: scope does not identify a fresh process",
        )
        if pid is not None:
            checks.require(pid not in seen_pids, f"memory: PID {pid} is reused; expected one fresh PID per row")
            seen_pids.add(pid)
        if trial is not None and operation in operations_for(name):
            key = (row.get("run_id", "").strip(), name, operation, trial)
            checks.require(key not in seen_keys, f"memory: duplicate measurement key {key}")
            seen_keys.add(key)
            if peak is not None:
                groups.setdefault((name, operation), []).append((trial, peak))

    for name in ALGORITHMS:
        summary_row = summary.get(name)
        if summary_row is None:
            continue
        for operation in operations_for(name):
            group = groups.get((name, operation), [])
            where = f"memory/{name}/{operation}"
            if repetition_count is not None:
                checks.require(
                    len(group) == repetition_count,
                    f"{where}: expected {repetition_count} rows, found {len(group)}",
                )
                checks.require(
                    sorted(trial for trial, _ in group) == list(range(1, repetition_count + 1)),
                    f"{where}: trials are not exactly 1..{repetition_count}",
                )
            if group:
                prefix = summary_prefix(operation)
                summary_peak = checks.integer(
                    summary_row, f"peak_ram_{prefix}_kb", f"summary/{name}", minimum=1
                )
                expected_peak = max(peak for _, peak in group)
                if summary_peak is not None:
                    checks.require(
                        summary_peak == expected_peak,
                        f"summary/{name}: peak_ram_{prefix}_kb={summary_peak}, "
                        f"memory rows give {expected_peak}",
                    )


def validate_uc1(
    rows: list[dict[str, str]],
    summary: dict[str, dict[str, str]],
    checks: Checks,
) -> None:
    by_name = unique_index(rows, KEMS, "UC1", checks)
    baseline = summary.get("X25519")
    if baseline is None:
        return
    baseline_ephemeral_wire = 64
    baseline_static_wire = 32
    baseline_ephemeral_latency = sum(
        float(baseline[field])
        for field in ("keygen_ms_median", "op1_ms_median", "op2_ms_median")
    )
    baseline_static_latency = sum(
        float(baseline[field]) for field in ("op1_ms_median", "op2_ms_median")
    )
    for name in KEMS:
        row = by_name.get(name)
        source = summary.get(name)
        if row is None or source is None:
            continue
        where = f"UC1/{name}"
        pk = ALGORITHMS[name].public_key_bytes
        ct = ALGORITHMS[name].ciphertext_or_sig_bytes
        ephemeral_wire = pk + ct
        ephemeral_latency = sum(
            float(source[field])
            for field in ("keygen_ms_median", "op1_ms_median", "op2_ms_median")
        )
        static_latency = sum(
            float(source[field]) for field in ("op1_ms_median", "op2_ms_median")
        )
        expect_int(row, "ephemeral_wire_bytes", ephemeral_wire, where, checks)
        expect_int(row, "static_wire_bytes", ct, where, checks)
        expect_int(row, "preprovisioned_public_key_bytes", pk, where, checks)
        expect_number(row, "ephemeral_crypto_latency_ms", ephemeral_latency, where, checks)
        expect_number(row, "static_crypto_latency_ms", static_latency, where, checks)
        expect_number(
            row,
            "ephemeral_wire_ratio_vs_x25519",
            ephemeral_wire / baseline_ephemeral_wire,
            where,
            checks,
        )
        expect_number(
            row,
            "static_wire_ratio_vs_x25519",
            ct / baseline_static_wire,
            where,
            checks,
        )
        expect_number(
            row,
            "ephemeral_latency_ratio_vs_x25519",
            ephemeral_latency / baseline_ephemeral_latency,
            where,
            checks,
        )
        expect_number(
            row,
            "static_latency_ratio_vs_x25519",
            static_latency / baseline_static_latency,
            where,
            checks,
        )

    # Fixed expected values guard the hybrid concatenation accounting.
    for name, values in {
        "Hybrid-X25519-ML-KEM-768": (2336, 1120, 1216),
        "Hybrid-X25519-ML-KEM-1024": (3200, 1600, 1600),
    }.items():
        row = by_name.get(name)
        if row is not None:
            expect_int(row, "ephemeral_wire_bytes", values[0], f"UC1 golden/{name}", checks)
            expect_int(row, "static_wire_bytes", values[1], f"UC1 golden/{name}", checks)
            expect_int(
                row,
                "preprovisioned_public_key_bytes",
                values[2],
                f"UC1 golden/{name}",
                checks,
            )


def validate_uc2(
    rows: list[dict[str, str]],
    summary: dict[str, dict[str, str]],
    checks: Checks,
) -> None:
    by_name = unique_index(rows, SIGNATURES, "UC2", checks)
    baseline = summary.get("Ed25519")
    if baseline is None:
        return
    baseline_verify = float(baseline["op2_ms_median"])
    for name in SIGNATURES:
        row = by_name.get(name)
        source = summary.get(name)
        if row is None or source is None:
            continue
        where = f"UC2/{name}"
        spec = ALGORITHMS[name]
        verify = float(source["op2_ms_median"])
        sign = float(source["op1_ms_median"])
        expect_int(row, "signature_bytes", spec.ciphertext_or_sig_bytes, where, checks)
        expect_number(row, "verify_ms", verify, where, checks)
        expect_int(row, "public_key_provisioning_bytes", spec.public_key_bytes, where, checks)
        expect_number(row, "sign_ms_secondary", sign, where, checks)
        expect_number(
            row,
            "signature_size_ratio_vs_ed25519",
            spec.ciphertext_or_sig_bytes / 64,
            where,
            checks,
        )
        expect_number(
            row,
            "verify_time_ratio_vs_ed25519",
            verify / baseline_verify,
            where,
            checks,
        )
        expect_number(
            row,
            "public_key_ratio_vs_ed25519",
            spec.public_key_bytes / 32,
            where,
            checks,
        )


def validate_uc3(
    rows: list[dict[str, str]],
    summary: dict[str, dict[str, str]],
    checks: Checks,
) -> None:
    by_name = unique_index(rows, KEMS, "UC3", checks)
    baseline_footprint = 64
    for name in KEMS:
        row = by_name.get(name)
        source = summary.get(name)
        if row is None or source is None:
            continue
        where = f"UC3/{name}"
        spec = ALGORITHMS[name]
        footprint = spec.public_key_bytes + spec.secret_key_bytes
        expect_int(row, "key_material_footprint_bytes", footprint, where, checks)
        expect_number(row, "footprint_ratio_vs_x25519", footprint / baseline_footprint, where, checks)
        for scenario_field, summary_field in (
            ("peak_keygen_process_rss_kb", "peak_ram_keygen_kb"),
            ("peak_encaps_process_rss_kb", "peak_ram_op1_kb"),
            ("peak_decaps_process_rss_kb", "peak_ram_op2_kb"),
        ):
            expected = checks.integer(source, summary_field, f"summary/{name}", minimum=1)
            if expected is not None:
                expect_int(row, scenario_field, expected, where, checks)

    for name, footprint in {
        "Hybrid-X25519-ML-KEM-768": 3648,
        "Hybrid-X25519-ML-KEM-1024": 4800,
    }.items():
        row = by_name.get(name)
        if row is not None:
            expect_int(
                row,
                "key_material_footprint_bytes",
                footprint,
                f"UC3 golden/{name}",
                checks,
            )


def main() -> int:
    args = parse_args()
    checks = Checks()
    summary_rows = read_csv(args.summary_csv, SUMMARY_REQUIRED, "summary", checks)
    raw_rows = read_csv(args.raw_csv, RAW_REQUIRED, "raw", checks)
    memory_rows = read_csv(args.memory_csv, MEMORY_REQUIRED, "memory", checks)
    uc1_rows = read_csv(args.uc1_csv, UC1_REQUIRED, "UC1", checks)
    uc2_rows = read_csv(args.uc2_csv, UC2_REQUIRED, "UC2", checks)
    uc3_rows = read_csv(args.uc3_csv, UC3_REQUIRED, "UC3", checks)

    summary = validate_summary(summary_rows, checks) if summary_rows else {}
    if raw_rows and summary:
        validate_raw(raw_rows, summary, checks)
    if memory_rows and summary:
        validate_memory(memory_rows, summary, checks)
    if uc1_rows and summary:
        validate_uc1(uc1_rows, summary, checks)
    if uc2_rows and summary:
        validate_uc2(uc2_rows, summary, checks)
    if uc3_rows and summary:
        validate_uc3(uc3_rows, summary, checks)

    if checks.errors:
        print(f"FAIL: {len(checks.errors)} validation error(s)", file=sys.stderr)
        for index, error in enumerate(checks.errors, 1):
            print(f"  {index}. {error}", file=sys.stderr)
        return 1

    print(
        "PASS: results are internally consistent "
        f"(13 algorithms, {len(raw_rows)} raw timings, {len(memory_rows)} memory trials)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
