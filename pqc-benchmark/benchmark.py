#!/usr/bin/env python3
"""PQC benchmark harness.

The harness measures six core PQ KEMs, X25519, two real sequential hybrids,
three PQ signatures, and Ed25519. It writes raw per-run timings, summary
statistics, best-effort fresh-process peak RSS, absolute tables, and a full
reproducibility record. Cryptographic operations come from liboqs or PyNaCl.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

import nacl
import nacl.bindings as sodium
import oqs
import psutil


@dataclass(frozen=True)
class Algorithm:
    kind: str
    display_name: str
    identifiers: tuple[str, ...]
    level: int | None
    family: str
    backend: str
    hybrid_component: str | None = None


@dataclass(frozen=True)
class ResolvedAlgorithm:
    spec: Algorithm
    identifier: str
    implementation_version: str
    sizes: tuple[int, int, int]
    shared_secret_bytes: int | None
    size_check: str


# Display order keeps the classical baseline beside the level-matched groups.
KEMS = [
    Algorithm("KEM", "X25519", (), None, "Classical", "x25519"),
    Algorithm("KEM", "ML-KEM-768", ("ML-KEM-768",), 3, "Lattice", "oqs_kem"),
    Algorithm("KEM", "Classic-McEliece-460896", ("Classic-McEliece-460896",), 3, "Code (Goppa)", "oqs_kem"),
    Algorithm("KEM", "HQC-192", ("HQC-192", "HQC-3"), 3, "Code (QC)", "oqs_kem"),
    Algorithm("KEM", "Hybrid-X25519-ML-KEM-768", (), 3, "Hybrid", "hybrid", "ML-KEM-768"),
    Algorithm("KEM", "ML-KEM-1024", ("ML-KEM-1024",), 5, "Lattice", "oqs_kem"),
    Algorithm("KEM", "Classic-McEliece-6960119", ("Classic-McEliece-6960119",), 5, "Code (Goppa)", "oqs_kem"),
    Algorithm("KEM", "HQC-256", ("HQC-256", "HQC-5"), 5, "Code (QC)", "oqs_kem"),
    Algorithm("KEM", "Hybrid-X25519-ML-KEM-1024", (), 5, "Hybrid", "hybrid", "ML-KEM-1024"),
]

SIGS = [
    Algorithm("SIG", "Ed25519", (), None, "Classical", "ed25519"),
    Algorithm("SIG", "ML-DSA-87", ("ML-DSA-87",), 5, "Lattice", "oqs_sig"),
    Algorithm("SIG", "SLH-DSA-SHA2-256s", ("SLH-DSA-SHA2-256s", "SLH_DSA_PURE_SHA2_256S"), 5, "Hash-based", "oqs_sig"),
    Algorithm("SIG", "SLH-DSA-SHA2-256f", ("SLH-DSA-SHA2-256f", "SLH_DSA_PURE_SHA2_256F"), 5, "Hash-based", "oqs_sig"),
]

ITERATIONS = 1000
MCELIECE_KEYGEN_ITERATIONS = 30
WARMUPS = 5
MEMORY_RUNS = 3
MESSAGE = b"benchmark-test-message" * 100
BUILD_TYPE = os.environ.get(
    "LIBOQS_BUILD_TYPE",
    "optimised Release distribution build (runtime dispatch; HQC reference)",
)
SODIUM_VERSION = "bundled libsodium 1.0.20-stable (2025-12-31 build)"

SUMMARY_CSV = "summary_results.csv"
COMPATIBILITY_CSV = "results.csv"
RAW_CSV = "raw_results.csv"
MEMORY_CSV = "memory_results.csv"
OUTPUT_TABLE = "results_table.txt"
OUTPUT_ENVIRONMENT = "environment.txt"

# HQC is excluded because its sizes are explicitly version-dependent.
REFERENCE_SIZES = {
    "X25519": (32, 32, 32),
    "ML-KEM-768": (1184, 2400, 1088),
    "Classic-McEliece-460896": (524160, 13608, 156),
    "Hybrid-X25519-ML-KEM-768": (1216, 2432, 1120),
    "ML-KEM-1024": (1568, 3168, 1568),
    "Classic-McEliece-6960119": (1047319, 13948, 194),
    "Hybrid-X25519-ML-KEM-1024": (1600, 3200, 1600),
    "Ed25519": (32, 64, 64),
    "ML-DSA-87": (2592, 4896, 4627),
    "SLH-DSA-SHA2-256s": (64, 128, 29792),
    "SLH-DSA-SHA2-256f": (64, 128, 49856),
}

SUMMARY_FIELDS = [
    "run_id",
    "stage_added",
    "kind",
    "algorithm",
    "backend",
    "components",
    "library_identifier",
    "implementation_version",
    "security_level",
    "family",
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
    "ratio_baseline",
    "primary_size_ratio",
    "primary_size_ratio_metric",
    "size_check",
]

RAW_FIELDS = [
    "run_id",
    "run_scope",
    "stage_added",
    "kind",
    "algorithm",
    "backend",
    "components",
    "library_identifier",
    "implementation_version",
    "security_level",
    "family",
    "measurement_scope",
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
    "message_bytes",
]

MEMORY_FIELDS = [
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
]


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def nonnegative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return parsed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=positive_int, default=ITERATIONS)
    parser.add_argument(
        "--mceliece-keygen-iterations",
        type=positive_int,
        default=MCELIECE_KEYGEN_ITERATIONS,
    )
    parser.add_argument("--warmups", type=nonnegative_int, default=WARMUPS)
    parser.add_argument("--memory-runs", type=positive_int, default=MEMORY_RUNS)
    parser.add_argument("--skip-memory", action="store_true")
    parser.add_argument("--check-sizes", action="store_true")
    parser.add_argument("--summary-csv", default=SUMMARY_CSV)
    parser.add_argument("--compatibility-csv", default=COMPATIBILITY_CSV)
    parser.add_argument("--raw-csv", default=RAW_CSV)
    parser.add_argument("--memory-csv", default=MEMORY_CSV)
    parser.add_argument("--output-table", default=OUTPUT_TABLE)
    parser.add_argument("--environment-file", default=OUTPUT_ENVIRONMENT)
    return parser.parse_args()


def time_ns(func: Callable, *args):
    start = time.perf_counter_ns()
    result = func(*args)
    end = time.perf_counter_ns()
    return result, end - start


def pin_to_one_core() -> None:
    if not hasattr(os, "sched_getaffinity") or not hasattr(os, "sched_setaffinity"):
        raise RuntimeError("CPU affinity requires Linux/WSL; use taskset on this platform")
    available = sorted(os.sched_getaffinity(0))
    if not available:
        raise RuntimeError("no CPU cores are available")
    os.sched_setaffinity(0, {available[0]})


def affinity_label() -> str:
    if hasattr(os, "sched_getaffinity"):
        return ",".join(str(core) for core in sorted(os.sched_getaffinity(0)))
    return "not reported"


def read_cpu() -> tuple[str, str]:
    model = platform.processor().strip() or "unknown CPU"
    mhz = None
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        for line in cpuinfo.read_text(errors="replace").splitlines():
            if line.startswith("model name"):
                model = line.split(":", 1)[1].strip()
            elif line.startswith("cpu MHz") and mhz is None:
                mhz = float(line.split(":", 1)[1].strip())
            if model != "unknown CPU" and mhz is not None:
                break
    return model, f"{mhz / 1000:.2f} GHz" if mhz is not None else "clock unknown"


def machine_header() -> str:
    cpu, clock = read_cpu()
    return (
        f"Machine: {cpu} @ {clock} | liboqs {oqs.oqs_version()} | "
        f"bindings {oqs.oqs_python_version()} | PyNaCl {nacl.__version__} | "
        f"build: {BUILD_TYPE} | CPU affinity: {affinity_label()}"
    )


def resolve_oqs_identifier(choices: Iterable[str], enabled: set[str]) -> str:
    identifier = next((choice for choice in choices if choice in enabled), None)
    if identifier is None:
        raise RuntimeError(f"none of these liboqs identifiers is enabled: {tuple(choices)}")
    return identifier


def oqs_details(kind: str, identifier: str) -> dict[str, object]:
    constructor = oqs.KeyEncapsulation if kind == "KEM" else oqs.Signature
    with constructor(identifier) as instance:
        return dict(instance.details)


def validate_size(spec: Algorithm, sizes: tuple[int, int, int]) -> str:
    if any(size <= 0 for size in sizes):
        raise RuntimeError(f"{spec.display_name} reported invalid sizes: {sizes}")
    expected = REFERENCE_SIZES.get(spec.display_name)
    if expected is None:
        return f"PASS_VERSION_DEPENDENT_LIBOQS_{oqs.oqs_version()}"
    if sizes != expected:
        raise RuntimeError(
            f"size check failed for {spec.display_name}: got {sizes}, expected {expected}"
        )
    return "PASS_EXACT"


def resolve_algorithms() -> list[ResolvedAlgorithm]:
    enabled_kems = set(oqs.get_enabled_kem_mechanisms())
    enabled_sigs = set(oqs.get_enabled_sig_mechanisms())
    resolved = []
    for spec in [*KEMS, *SIGS]:
        if spec.backend == "oqs_kem":
            identifier = resolve_oqs_identifier(spec.identifiers, enabled_kems)
            details = oqs_details("KEM", identifier)
            sizes = (
                int(details["length_public_key"]),
                int(details["length_secret_key"]),
                int(details["length_ciphertext"]),
            )
            shared_secret = int(details["length_shared_secret"])
            version = str(details.get("version", "not reported by liboqs"))
        elif spec.backend == "oqs_sig":
            identifier = resolve_oqs_identifier(spec.identifiers, enabled_sigs)
            details = oqs_details("SIG", identifier)
            sizes = (
                int(details["length_public_key"]),
                int(details["length_secret_key"]),
                int(details["length_signature"]),
            )
            shared_secret = None
            version = str(details.get("version", "not reported by liboqs"))
        elif spec.backend == "x25519":
            identifier = "PyNaCl crypto_kx_keypair + crypto_scalarmult"
            sizes = (32, 32, 32)
            shared_secret = 32
            version = f"PyNaCl {nacl.__version__}; {SODIUM_VERSION}"
        elif spec.backend == "ed25519":
            identifier = "PyNaCl crypto_sign"
            sizes = (32, 64, 64)
            shared_secret = None
            version = f"PyNaCl {nacl.__version__}; {SODIUM_VERSION}"
        elif spec.backend == "hybrid":
            component = str(spec.hybrid_component)
            identifier = resolve_oqs_identifier((component,), enabled_kems)
            details = oqs_details("KEM", identifier)
            sizes = (
                32 + int(details["length_public_key"]),
                32 + int(details["length_secret_key"]),
                32 + int(details["length_ciphertext"]),
            )
            shared_secret = 32 + int(details["length_shared_secret"])
            version = (
                f"PyNaCl {nacl.__version__} ({SODIUM_VERSION}) + "
                f"{details.get('version', 'liboqs version not reported')}"
            )
            identifier = f"X25519 + {identifier}"
        else:
            raise RuntimeError(f"unknown backend: {spec.backend}")
        resolved.append(
            ResolvedAlgorithm(
                spec,
                identifier,
                version,
                sizes,
                shared_secret,
                validate_size(spec, sizes),
            )
        )
    return resolved


def pq_identifier(algorithm: ResolvedAlgorithm) -> str:
    if algorithm.spec.backend == "hybrid":
        return algorithm.identifier.split(" + ", 1)[1]
    return algorithm.identifier


def x25519_keygen() -> tuple[bytes, bytes]:
    return sodium.crypto_kx_keypair()


def x25519_encapsulate(receiver_public_key: bytes) -> tuple[bytes, bytes]:
    ephemeral_public, ephemeral_secret = x25519_keygen()
    shared_secret = sodium.crypto_scalarmult(ephemeral_secret, receiver_public_key)
    return ephemeral_public, shared_secret


def x25519_decapsulate(receiver_secret_key: bytes, ciphertext: bytes) -> bytes:
    return sodium.crypto_scalarmult(receiver_secret_key, ciphertext)


class HybridKEM:
    """Benchmark-only X25519 || ML-KEM wrapper with exact aggregate fields.

    Keys, ciphertexts and shared secrets are concatenated in X25519 || ML-KEM
    order. The 64-byte shared output is not application key material; production
    protocols must pass both component secrets through a domain-separated
    combiner/KDF.
    """

    def __init__(self, pq_identifier: str, secret_key: bytes | None = None) -> None:
        self.pq_identifier = pq_identifier
        if secret_key is None:
            self.pq = oqs.KeyEncapsulation(pq_identifier)
            self.x_secret: bytes | None = None
            self.x_public: bytes | None = None
        else:
            probe = oqs.KeyEncapsulation(pq_identifier)
            pq_secret_bytes = int(probe.details["length_secret_key"])
            probe.free()
            if len(secret_key) != 32 + pq_secret_bytes:
                raise ValueError(
                    f"invalid hybrid secret-key length: expected {32 + pq_secret_bytes}, "
                    f"got {len(secret_key)}"
                )
            self.x_secret = secret_key[:32]
            self.x_public = sodium.crypto_scalarmult_base(self.x_secret)
            self.pq = oqs.KeyEncapsulation(pq_identifier, secret_key=secret_key[32:])

        self.pq_public_bytes = int(self.pq.details["length_public_key"])
        self.pq_secret_bytes = int(self.pq.details["length_secret_key"])
        self.pq_ciphertext_bytes = int(self.pq.details["length_ciphertext"])
        self.pq_shared_secret_bytes = int(self.pq.details["length_shared_secret"])

    def __enter__(self) -> "HybridKEM":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.pq.free()

    def generate_keypair(self) -> bytes:
        self.x_public, self.x_secret = x25519_keygen()
        pq_public = self.pq.generate_keypair()
        if len(pq_public) != self.pq_public_bytes:
            raise RuntimeError("unexpected ML-KEM public-key length")
        return self.x_public + pq_public

    def export_secret_key(self) -> bytes:
        if self.x_secret is None:
            raise RuntimeError("generate or import a hybrid keypair first")
        pq_secret = self.pq.export_secret_key()
        if len(pq_secret) != self.pq_secret_bytes:
            raise RuntimeError("unexpected ML-KEM secret-key length")
        return self.x_secret + pq_secret

    def encap_secret(self, receiver_public_key: bytes) -> tuple[bytes, bytes]:
        expected = 32 + self.pq_public_bytes
        if len(receiver_public_key) != expected:
            raise ValueError(
                f"invalid hybrid public-key length: expected {expected}, "
                f"got {len(receiver_public_key)}"
            )
        x_ciphertext, x_shared = x25519_encapsulate(receiver_public_key[:32])
        pq_ciphertext, pq_shared = self.pq.encap_secret(receiver_public_key[32:])
        return x_ciphertext + pq_ciphertext, x_shared + pq_shared

    def decap_secret(self, ciphertext: bytes) -> bytes:
        if self.x_secret is None:
            raise RuntimeError("generate or import a hybrid keypair first")
        expected = 32 + self.pq_ciphertext_bytes
        if len(ciphertext) != expected:
            raise ValueError(
                f"invalid hybrid ciphertext length: expected {expected}, got {len(ciphertext)}"
            )
        x_shared = x25519_decapsulate(self.x_secret, ciphertext[:32])
        pq_shared = self.pq.decap_secret(ciphertext[32:])
        combined = x_shared + pq_shared
        if len(combined) != 32 + self.pq_shared_secret_bytes:
            raise RuntimeError("unexpected hybrid shared-secret length")
        return combined


def warmup_kem(algorithm: ResolvedAlgorithm, count: int) -> None:
    backend = algorithm.spec.backend
    for _ in range(count):
        if backend == "oqs_kem":
            with oqs.KeyEncapsulation(algorithm.identifier) as client, oqs.KeyEncapsulation(algorithm.identifier) as server:
                public_key = client.generate_keypair()
                ciphertext, server_secret = server.encap_secret(public_key)
                client_secret = client.decap_secret(ciphertext)
        elif backend == "x25519":
            public_key, secret_key = x25519_keygen()
            ciphertext, server_secret = x25519_encapsulate(public_key)
            client_secret = x25519_decapsulate(secret_key, ciphertext)
        else:
            identifier = pq_identifier(algorithm)
            with HybridKEM(identifier) as client, HybridKEM(identifier) as server:
                public_key = client.generate_keypair()
                if len(client.export_secret_key()) != algorithm.sizes[1]:
                    raise RuntimeError("hybrid secret-key size check failed")
                ciphertext, server_secret = server.encap_secret(public_key)
                client_secret = client.decap_secret(ciphertext)
        if client_secret != server_secret:
            raise RuntimeError(f"KEM warm-up failed for {algorithm.spec.display_name}")


def warmup_signature(algorithm: ResolvedAlgorithm, count: int) -> None:
    for _ in range(count):
        if algorithm.spec.backend == "oqs_sig":
            with oqs.Signature(algorithm.identifier) as signer:
                public_key = signer.generate_keypair()
                signature = signer.sign(MESSAGE)
                valid = signer.verify(MESSAGE, signature, public_key)
        else:
            public_key, secret_key = sodium.crypto_sign_keypair()
            signed = sodium.crypto_sign(MESSAGE, secret_key)
            valid = sodium.crypto_sign_open(signed, public_key) == MESSAGE
        if not valid:
            raise RuntimeError(f"signature warm-up failed for {algorithm.spec.display_name}")


def measure_kem(
    algorithm: ResolvedAlgorithm,
    iterations: int,
    mceliece_keygen_iterations: int,
    warmups: int,
) -> dict[str, list[int]]:
    keygen_n = (
        mceliece_keygen_iterations
        if algorithm.spec.display_name.startswith("Classic-McEliece")
        else iterations
    )
    print(
        f"  KEM {algorithm.spec.display_name}: keygen n={keygen_n}, "
        f"encaps/decaps n={iterations} ...",
        flush=True,
    )
    warmup_kem(algorithm, warmups)
    keygen_times: list[int] = []
    backend = algorithm.spec.backend

    for _ in range(keygen_n):
        if backend == "oqs_kem":
            with oqs.KeyEncapsulation(algorithm.identifier) as instance:
                _, elapsed = time_ns(instance.generate_keypair)
        elif backend == "x25519":
            _, elapsed = time_ns(x25519_keygen)
        else:
            with HybridKEM(pq_identifier(algorithm)) as instance:
                public_key, elapsed = time_ns(instance.generate_keypair)
                secret_key = instance.export_secret_key()
                if len(public_key) != algorithm.sizes[0] or len(secret_key) != algorithm.sizes[1]:
                    raise RuntimeError("hybrid keypair size check failed")
        keygen_times.append(elapsed)

    op1_times: list[int] = []
    op2_times: list[int] = []
    if backend == "oqs_kem":
        with oqs.KeyEncapsulation(algorithm.identifier) as client, oqs.KeyEncapsulation(algorithm.identifier) as server:
            public_key = client.generate_keypair()
            for _ in range(iterations):
                (ciphertext, server_secret), elapsed = time_ns(server.encap_secret, public_key)
                op1_times.append(elapsed)
                client_secret, elapsed = time_ns(client.decap_secret, ciphertext)
                op2_times.append(elapsed)
                verify_kem_result(algorithm, ciphertext, client_secret, server_secret)
    elif backend == "x25519":
        public_key, secret_key = x25519_keygen()
        for _ in range(iterations):
            (ciphertext, server_secret), elapsed = time_ns(x25519_encapsulate, public_key)
            op1_times.append(elapsed)
            client_secret, elapsed = time_ns(x25519_decapsulate, secret_key, ciphertext)
            op2_times.append(elapsed)
            verify_kem_result(algorithm, ciphertext, client_secret, server_secret)
    else:
        identifier = pq_identifier(algorithm)
        with HybridKEM(identifier) as client, HybridKEM(identifier) as server:
            public_key = client.generate_keypair()
            for _ in range(iterations):
                (ciphertext, server_secret), elapsed = time_ns(server.encap_secret, public_key)
                op1_times.append(elapsed)
                client_secret, elapsed = time_ns(client.decap_secret, ciphertext)
                op2_times.append(elapsed)
                verify_kem_result(algorithm, ciphertext, client_secret, server_secret)
    return {"keygen": keygen_times, "op1": op1_times, "op2": op2_times}


def verify_kem_result(
    algorithm: ResolvedAlgorithm,
    ciphertext: bytes,
    client_secret: bytes,
    server_secret: bytes,
) -> None:
    if client_secret != server_secret:
        raise RuntimeError(f"shared secrets differ for {algorithm.spec.display_name}")
    if len(ciphertext) != algorithm.sizes[2]:
        raise RuntimeError(
            f"ciphertext length mismatch for {algorithm.spec.display_name}: {len(ciphertext)}"
        )
    if algorithm.shared_secret_bytes is not None and len(client_secret) != algorithm.shared_secret_bytes:
        raise RuntimeError(
            f"shared-secret length mismatch for {algorithm.spec.display_name}"
        )


def measure_signature(
    algorithm: ResolvedAlgorithm, iterations: int, warmups: int
) -> dict[str, list[int]]:
    print(
        f"  SIG {algorithm.spec.display_name}: keygen/sign/verify n={iterations} ...",
        flush=True,
    )
    warmup_signature(algorithm, warmups)
    keygen_times: list[int] = []
    op1_times: list[int] = []
    op2_times: list[int] = []

    if algorithm.spec.backend == "oqs_sig":
        for _ in range(iterations):
            with oqs.Signature(algorithm.identifier) as instance:
                _, elapsed = time_ns(instance.generate_keypair)
                keygen_times.append(elapsed)
        with oqs.Signature(algorithm.identifier) as signer, oqs.Signature(algorithm.identifier) as verifier:
            public_key = signer.generate_keypair()
            for _ in range(iterations):
                signature, elapsed = time_ns(signer.sign, MESSAGE)
                op1_times.append(elapsed)
                valid, elapsed = time_ns(verifier.verify, MESSAGE, signature, public_key)
                op2_times.append(elapsed)
                if not valid or len(signature) != algorithm.sizes[2]:
                    raise RuntimeError(f"signature check failed for {algorithm.spec.display_name}")
    else:
        for _ in range(iterations):
            _, elapsed = time_ns(sodium.crypto_sign_keypair)
            keygen_times.append(elapsed)
        public_key, secret_key = sodium.crypto_sign_keypair()
        for _ in range(iterations):
            signed, elapsed = time_ns(sodium.crypto_sign, MESSAGE, secret_key)
            op1_times.append(elapsed)
            opened, elapsed = time_ns(sodium.crypto_sign_open, signed, public_key)
            op2_times.append(elapsed)
            if opened != MESSAGE or len(signed) - len(MESSAGE) != algorithm.sizes[2]:
                raise RuntimeError("Ed25519 signature check failed")
    return {"keygen": keygen_times, "op1": op1_times, "op2": op2_times}


def timing_stats(samples: list[int]) -> dict[str, float]:
    if not samples:
        raise RuntimeError("cannot summarize an empty timing list")
    if len(samples) == 1:
        q1 = q3 = samples[0]
    else:
        quartiles = statistics.quantiles(samples, n=4, method="inclusive")
        q1, q3 = quartiles[0], quartiles[2]
    return {
        "median": statistics.median(samples) / 1_000_000.0,
        "q1": q1 / 1_000_000.0,
        "q3": q3 / 1_000_000.0,
        "iqr": (q3 - q1) / 1_000_000.0,
        "stddev": statistics.pstdev(samples) / 1_000_000.0,
    }


def append_raw_rows(
    raw_rows: list[dict[str, object]],
    algorithm: ResolvedAlgorithm,
    timings: dict[str, list[int]],
    run_id: str,
) -> None:
    operation_names = (
        {"keygen": "keygen", "op1": "encaps", "op2": "decaps"}
        if algorithm.spec.kind == "KEM"
        else {"keygen": "keygen", "op1": "sign", "op2": "verify"}
    )
    for key, samples in timings.items():
        for index, elapsed in enumerate(samples, 1):
            raw_rows.append(
                {
                    "run_id": run_id,
                    "run_scope": "Stages 1, 2, and 3 full measurement run",
                    "stage_added": (
                        "Stage 2"
                        if algorithm.spec.backend in {"x25519", "ed25519", "hybrid"}
                        else "Stage 1"
                    ),
                    "kind": algorithm.spec.kind,
                    "algorithm": algorithm.spec.display_name,
                    "backend": algorithm.spec.backend,
                    "components": (
                        f"X25519 + {algorithm.spec.hybrid_component}"
                        if algorithm.spec.backend == "hybrid"
                        else algorithm.spec.display_name
                    ),
                    "library_identifier": algorithm.identifier,
                    "implementation_version": algorithm.implementation_version,
                    "security_level": algorithm.spec.level if algorithm.spec.level is not None else "",
                    "family": algorithm.spec.family,
                    "measurement_scope": (
                        "hybrid_wrapper_total"
                        if algorithm.spec.backend == "hybrid"
                        else "algorithm_total"
                    ),
                    "operation": operation_names[key],
                    "sample_index": index,
                    "elapsed_ns": elapsed,
                    "elapsed_ms": round(elapsed / 1_000_000.0, 6),
                    "success": True,
                    "cpu_core": affinity_label(),
                    "public_key_bytes": algorithm.sizes[0],
                    "secret_key_bytes": algorithm.sizes[1],
                    "ciphertext_or_sig_bytes": algorithm.sizes[2],
                    "shared_secret_bytes": algorithm.shared_secret_bytes if algorithm.shared_secret_bytes is not None else "",
                    "message_bytes": len(MESSAGE) if algorithm.spec.kind == "SIG" else "",
                }
            )


def measure_peak_ram(
    algorithm: ResolvedAlgorithm,
    operation: str,
    runs: int,
    memory_rows: list[dict[str, object]],
    run_id: str,
) -> int:
    worker = Path(__file__).with_name("memory_worker.py")
    peaks = []
    for trial in range(1, runs + 1):
        completed = subprocess.run(
            [
                sys.executable,
                str(worker),
                "--algorithm",
                algorithm.spec.display_name,
                "--operation",
                operation,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=180,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                f"memory worker failed for {algorithm.spec.display_name}/{operation}: "
                f"{completed.stderr.strip()}"
            )
        lines = [line for line in completed.stdout.splitlines() if line.strip()]
        try:
            payload = json.loads(lines[-1])
            peaks.append(int(payload["peak_rss_kb"]))
            memory_rows.append(
                {
                    "run_id": run_id,
                    "algorithm": algorithm.spec.display_name,
                    "operation": operation,
                    "trial": trial,
                    "pid": payload["pid"],
                    "baseline_rss_kb": payload["baseline_rss_kb"],
                    "baseline_hwm_kb": payload["baseline_hwm_kb"],
                    "after_rss_kb": payload["after_rss_kb"],
                    "peak_rss_kb": payload["peak_rss_kb"],
                    "incremental_hwm_kb": payload["incremental_hwm_kb"],
                    "method": "isolated process Linux ru_maxrss",
                    "scope": payload["scope"],
                }
            )
        except (IndexError, KeyError, ValueError, json.JSONDecodeError) as error:
            raise RuntimeError(f"invalid memory-worker output: {completed.stdout}") from error
    return max(peaks)


def make_summary_row(
    algorithm: ResolvedAlgorithm,
    timings: dict[str, list[int]],
    warmups: int,
    peak_ram: dict[str, int | str],
    run_id: str,
) -> dict[str, object]:
    keygen = timing_stats(timings["keygen"])
    op1 = timing_stats(timings["op1"])
    op2 = timing_stats(timings["op2"])
    row: dict[str, object] = {
        "run_id": run_id,
        "stage_added": (
            "Stage 2" if algorithm.spec.backend in {"x25519", "ed25519", "hybrid"} else "Stage 1"
        ),
        "kind": algorithm.spec.kind,
        "algorithm": algorithm.spec.display_name,
        "backend": algorithm.spec.backend,
        "components": (
            f"X25519 + {algorithm.spec.hybrid_component}"
            if algorithm.spec.backend == "hybrid"
            else algorithm.spec.display_name
        ),
        "library_identifier": algorithm.identifier,
        "implementation_version": algorithm.implementation_version,
        "security_level": algorithm.spec.level if algorithm.spec.level is not None else "",
        "family": algorithm.spec.family,
        "public_key_bytes": algorithm.sizes[0],
        "secret_key_bytes": algorithm.sizes[1],
        "ciphertext_or_sig_bytes": algorithm.sizes[2],
        "shared_secret_bytes": algorithm.shared_secret_bytes if algorithm.shared_secret_bytes is not None else "",
        "keygen_iterations": len(timings["keygen"]),
        "op1_iterations": len(timings["op1"]),
        "op2_iterations": len(timings["op2"]),
        "warmups": warmups,
        "peak_ram_keygen_kb": peak_ram.get("keygen", ""),
        "peak_ram_op1_kb": peak_ram.get("op1", ""),
        "peak_ram_op2_kb": peak_ram.get("op2", ""),
        "peak_ram_method": peak_ram.get("method", "not measured"),
        "ratio_baseline": "",
        "primary_size_ratio": "",
        "primary_size_ratio_metric": "",
        "size_check": algorithm.size_check,
    }
    for prefix, stats in (("keygen", keygen), ("op1", op1), ("op2", op2)):
        for name, value in stats.items():
            row[f"{prefix}_ms_{name}"] = round(value, 6)
    return row


def add_primary_size_ratios(rows: list[dict[str, object]]) -> None:
    by_name = {str(row["algorithm"]): row for row in rows}
    for row in rows:
        if row["kind"] == "SIG":
            baseline = by_name.get("Ed25519")
            if baseline is None:
                continue
            row["ratio_baseline"] = "Ed25519"
            row["primary_size_ratio_metric"] = "signature_bytes"
            row["primary_size_ratio"] = round(
                int(row["ciphertext_or_sig_bytes"])
                / int(baseline["ciphertext_or_sig_bytes"]),
                6,
            )
        else:
            level = str(row["security_level"])
            baseline_name = {"3": "ML-KEM-768", "5": "ML-KEM-1024"}.get(level)
            if baseline_name is None or baseline_name not in by_name:
                row["ratio_baseline"] = "N/A (classical baseline)"
                row["primary_size_ratio_metric"] = "public_key_bytes"
                continue
            baseline = by_name[baseline_name]
            row["ratio_baseline"] = baseline_name
            row["primary_size_ratio_metric"] = "public_key_bytes"
            row["primary_size_ratio"] = round(
                int(row["public_key_bytes"]) / int(baseline["public_key_bytes"]),
                6,
            )


def write_csv(path: str, fields: list[str], rows: list[dict[str, object]]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def write_results(
    summary_path: str,
    compatibility_path: str,
    raw_path: str,
    memory_path: str,
    summary_rows: list[dict[str, object]],
    raw_rows: list[dict[str, object]],
    memory_rows: list[dict[str, object]],
) -> None:
    add_primary_size_ratios(summary_rows)
    write_csv(summary_path, SUMMARY_FIELDS, summary_rows)
    if Path(compatibility_path).resolve() != Path(summary_path).resolve():
        write_csv(compatibility_path, SUMMARY_FIELDS, summary_rows)
    write_csv(raw_path, RAW_FIELDS, raw_rows)
    write_csv(memory_path, MEMORY_FIELDS, memory_rows)


def format_table(rows: list[dict[str, object]], kind: str) -> str:
    selected = [row for row in rows if row["kind"] == kind]
    headers = [
        "algorithm",
        "L",
        "pk B",
        "sk B",
        "ct/sig B",
        "ss B",
        "keygen median [IQR] ms",
        "op1 median [IQR] ms",
        "op2 median [IQR] ms",
        "n key/op",
        "peak RSS kg/o1/o2 KB",
        "size ratio",
    ]
    values = []
    for row in selected:
        ratio = row["primary_size_ratio"]
        ratio_text = f"{float(ratio):.3f}" if ratio != "" else "N/A"
        values.append(
            [
                str(row["algorithm"]),
                str(row["security_level"] or "-"),
                f"{int(row['public_key_bytes']):,}",
                f"{int(row['secret_key_bytes']):,}",
                f"{int(row['ciphertext_or_sig_bytes']):,}",
                f"{int(row['shared_secret_bytes']):,}" if row["shared_secret_bytes"] != "" else "-",
                f"{float(row['keygen_ms_median']):.4f} [{float(row['keygen_ms_iqr']):.4f}]",
                f"{float(row['op1_ms_median']):.4f} [{float(row['op1_ms_iqr']):.4f}]",
                f"{float(row['op2_ms_median']):.4f} [{float(row['op2_ms_iqr']):.4f}]",
                f"{row['keygen_iterations']}/{row['op1_iterations']}",
                f"{row['peak_ram_keygen_kb']}/{row['peak_ram_op1_kb']}/{row['peak_ram_op2_kb']}",
                ratio_text,
            ]
        )
    widths = [
        max(len(headers[index]), *(len(line[index]) for line in values))
        for index in range(len(headers))
    ]

    def line(parts: list[str]) -> str:
        return "  ".join(value.ljust(widths[index]) for index, value in enumerate(parts))

    return "\n".join(
        [line(headers), line(["-" * width for width in widths]), *(line(row) for row in values)]
    )


def write_plain_results(
    path: str, header: str, rows: list[dict[str, object]]
) -> None:
    implementations = "\n".join(
        f"  {row['algorithm']}: {row['library_identifier']} | {row['implementation_version']}"
        for row in rows
    )
    content = (
        f"{header}\n\n"
        "Timing notation: median [IQR] milliseconds. Peak RAM is maximum fresh-process RSS.\n"
        "KEM size ratio: public key divided by the same-level ML-KEM.\n"
        "Signature size ratio: signature divided by Ed25519.\n\n"
        f"KEM ABSOLUTE VALUES\n{format_table(rows, 'KEM')}\n\n"
        f"SIGNATURE ABSOLUTE VALUES\n{format_table(rows, 'SIG')}\n\n"
        "HQC note: the labels HQC-192/HQC-256 map to liboqs HQC-3/HQC-5; "
        "their sizes are version-dependent.\n\n"
        f"IMPLEMENTATIONS\n{implementations}\n"
    )
    Path(path).write_text(content, encoding="utf-8")


def command_first_line(command: list[str], cwd: str | None = None) -> str:
    try:
        result = subprocess.run(
            command, cwd=cwd, capture_output=True, text=True, timeout=10, check=False
        )
        return (result.stdout or result.stderr).splitlines()[0].strip()
    except (OSError, subprocess.SubprocessError, IndexError):
        return "not available"


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def portable_path(path: str) -> str:
    """Return *path* relative to the project folder, or with the home folder as ~."""
    absolute = Path(os.path.abspath(path))
    project = Path(os.path.abspath(os.path.dirname(__file__)))
    for base, prefix in ((project, ""), (Path.home(), "~/")):
        try:
            return prefix + absolute.relative_to(base).as_posix()
        except ValueError:
            continue
    return absolute.as_posix()


def write_environment(
    path: str,
    header: str,
    args: argparse.Namespace,
    algorithms: list[ResolvedAlgorithm],
    started: datetime,
    finished: datetime | None,
) -> None:
    workspace = Path(__file__).resolve().parent
    source_dir = workspace / ".liboqs-src"
    liboqs_commit = command_first_line(["git", "rev-parse", "HEAD"], str(source_dir))
    compiler = command_first_line(["cc", "--version"])
    cmake_version = command_first_line(["cmake", "--version"])
    ninja_version = command_first_line(["ninja", "--version"])
    openssl_version = command_first_line(["openssl", "version", "-a"])
    glibc_version = command_first_line(["ldd", "--version"])
    os_release = ""
    os_release_path = Path("/etc/os-release")
    if os_release_path.exists():
        values = {}
        for line in os_release_path.read_text(errors="replace").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value.strip('"')
        os_release = values.get("PRETTY_NAME", "")
    source_files = [
        "benchmark.py",
        "memory_worker.py",
        "scenario_analysis.py",
        "plot.py",
        "crypto_self_test.py",
        "verify_results.py",
        "build_manifest.py",
        "requirements.lock.txt",
    ]
    hashes = []
    hash_map: dict[str, str] = {}
    for name in source_files:
        candidate = workspace / name
        if candidate.exists():
            digest = file_sha256(candidate)
            hashes.append(f"  {name}: {digest}")
            hash_map[name] = digest
    implementation_lines = [
        f"  {item.spec.display_name}: {item.identifier} | {item.implementation_version}"
        for item in algorithms
    ]
    finish_text = finished.isoformat() if finished else "in progress"
    text = (
        "PQC BENCHMARK REPRODUCIBILITY RECORD\n\n"
        f"{header}\n"
        f"Started UTC: {started.isoformat()}\n"
        f"Finished UTC: {finish_text}\n"
        f"OS: {os_release}; {platform.platform()}\n"
        f"Python: {platform.python_version()} ({portable_path(sys.executable)})\n"
        f"Compiler: {compiler}\n"
        f"liboqs: {oqs.oqs_version()}\n"
        f"liboqs-python: {oqs.oqs_python_version()}\n"
        f"Local liboqs source-checkout commit (binary provenance not independently proven): {liboqs_commit}\n"
        f"Build type: {BUILD_TYPE}\n"
        f"CMake: {cmake_version}\n"
        f"Ninja: {ninja_version}\n"
        f"OpenSSL: {openssl_version}\n"
        f"glibc: {glibc_version}\n"
        f"PyNaCl: {nacl.__version__}\n"
        f"libsodium: {SODIUM_VERSION}\n"
        f"psutil: {psutil.__version__}\n"
        f"Measured iterations per operation: {args.iterations}\n"
        f"Classic McEliece keygen iterations: {args.mceliece_keygen_iterations}\n"
        f"Warm-ups: {args.warmups}\n"
        f"Memory repetitions: {0 if args.skip_memory else args.memory_runs}\n"
        "Timing clock: time.perf_counter_ns\n"
        "Spread: inclusive Q1/Q3 and IQR; population standard deviation\n"
        "Peak RAM: maximum Linux ru_maxrss from repeated fresh worker processes, "
        "including runtime and operation setup\n"
        "RNG seed: not fixed; liboqs and PyNaCl use their OS-backed CSPRNGs and do "
        "not expose a safe common deterministic seed for these production APIs\n\n"
        "ALGORITHM IMPLEMENTATIONS\n"
        + "\n".join(implementation_lines)
        + "\n\nSOURCE SHA-256\n"
        + "\n".join(hashes)
        + "\n"
    )
    Path(path).write_text(text, encoding="utf-8")

    cpu, clock = read_cpu()
    liboqs_candidates = [
        Path("/usr/local/lib/liboqs.so.0.16.0"),
        Path("/usr/local/lib/liboqs.so"),
        Path("/usr/lib/liboqs.so"),
    ]
    liboqs_binary = next((item.resolve() for item in liboqs_candidates if item.exists()), None)
    oqsconfig = Path("/usr/local/include/oqs/oqsconfig.h")
    clock_info = time.get_clock_info("perf_counter")
    environment_json = {
        "record_type": "PQC benchmark reproducibility record",
        "started_utc": started.isoformat(),
        "finished_utc": finished.isoformat() if finished else None,
        "run_command": [portable_path(sys.executable), portable_path(sys.argv[0]), *sys.argv[1:]],
        "host": {
            "os_release": os_release,
            "platform": platform.platform(),
            "cpu": cpu,
            "observed_clock": clock,
            "cpu_affinity": sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None,
            "load_average": list(os.getloadavg()) if hasattr(os, "getloadavg") else None,
            "memory_total_bytes": psutil.virtual_memory().total,
            "memory_available_bytes_at_recording": psutil.virtual_memory().available,
        },
        "toolchain": {
            "python_version": platform.python_version(),
            "python_executable": portable_path(sys.executable),
            "compiler": compiler,
            "cmake": cmake_version,
            "ninja": ninja_version,
            "openssl": openssl_version,
            "glibc": glibc_version,
            "liboqs_version": oqs.oqs_version(),
            "liboqs_python_version": oqs.oqs_python_version(),
            "local_liboqs_source_checkout_commit": liboqs_commit,
            "liboqs_binary_provenance_note": "local checkout exists but its relationship to the loaded binary was not independently proven; binary hash is authoritative",
            "liboqs_build_type": BUILD_TYPE,
            "liboqs_binary": str(liboqs_binary) if liboqs_binary else None,
            "liboqs_binary_sha256": file_sha256(liboqs_binary) if liboqs_binary else None,
            "oqsconfig": str(oqsconfig) if oqsconfig.exists() else None,
            "oqsconfig_sha256": file_sha256(oqsconfig) if oqsconfig.exists() else None,
            "pynacl_version": nacl.__version__,
            "libsodium_version": SODIUM_VERSION,
            "psutil_version": psutil.__version__,
        },
        "measurement": {
            "iterations_per_operation": args.iterations,
            "mceliece_keygen_iterations": args.mceliece_keygen_iterations,
            "warmups": args.warmups,
            "memory_repetitions": 0 if args.skip_memory else args.memory_runs,
            "clock": "time.perf_counter_ns",
            "clock_resolution_seconds": clock_info.resolution,
            "clock_monotonic": clock_info.monotonic,
            "clock_adjustable": clock_info.adjustable,
            "statistics": "median, inclusive Q1/Q3/IQR, population standard deviation",
            "outlier_policy": "none; all successful measured samples retained",
            "memory_method": "fresh-process Linux ru_maxrss; setup included; best-effort conservative process peak",
            "message_bytes": len(MESSAGE),
            "message_sha256": hashlib.sha256(MESSAGE).hexdigest(),
            "rng_policy": "system-backed CSPRNG; no common fixed deterministic seed is exposed by these production APIs",
            "hybrid_warning": "raw X25519 and concatenated component secrets are benchmark-only; production protocols require a domain-separated KDF",
            "ed25519_scope": "libsodium combined crypto_sign mode; message-buffer copying is included",
            "hybrid_key_export_scope": "key generation is timed; secret-key export/serialization is checked outside the timed interval",
        },
        "algorithms": [
            {
                "display_name": item.spec.display_name,
                "kind": item.spec.kind,
                "stage_added": "Stage 2" if item.spec.backend in {"x25519", "ed25519", "hybrid"} else "Stage 1",
                "backend": item.spec.backend,
                "identifier": item.identifier,
                "implementation_version": item.implementation_version,
                "security_level": item.spec.level,
                "public_key_bytes": item.sizes[0],
                "secret_key_bytes": item.sizes[1],
                "ciphertext_or_signature_bytes": item.sizes[2],
                "shared_secret_bytes": item.shared_secret_bytes,
            }
            for item in algorithms
        ],
        "source_sha256": hash_map,
    }
    json_path = Path(path).with_suffix(".json")
    json_path.write_text(json.dumps(environment_json, indent=2) + "\n", encoding="utf-8")


def exercise_operation(algorithm: ResolvedAlgorithm, operation: str) -> None:
    """Perform one operation for isolated-process peak-RSS measurement."""
    backend = algorithm.spec.backend
    if algorithm.spec.kind == "KEM":
        if operation == "keygen":
            if backend == "oqs_kem":
                with oqs.KeyEncapsulation(algorithm.identifier) as instance:
                    instance.generate_keypair()
            elif backend == "x25519":
                x25519_keygen()
            else:
                with HybridKEM(pq_identifier(algorithm)) as instance:
                    instance.generate_keypair()
                    if len(instance.export_secret_key()) != algorithm.sizes[1]:
                        raise RuntimeError("hybrid secret-key size check failed")
            return
        if backend == "oqs_kem":
            with oqs.KeyEncapsulation(algorithm.identifier) as client, oqs.KeyEncapsulation(algorithm.identifier) as server:
                public_key = client.generate_keypair()
                ciphertext, _ = server.encap_secret(public_key)
                if operation == "decaps":
                    client.decap_secret(ciphertext)
        elif backend == "x25519":
            public_key, secret_key = x25519_keygen()
            ciphertext, _ = x25519_encapsulate(public_key)
            if operation == "decaps":
                x25519_decapsulate(secret_key, ciphertext)
        else:
            identifier = pq_identifier(algorithm)
            with HybridKEM(identifier) as client, HybridKEM(identifier) as server:
                public_key = client.generate_keypair()
                ciphertext, server_secret = server.encap_secret(public_key)
                if operation == "decaps":
                    client_secret = client.decap_secret(ciphertext)
                    if client_secret != server_secret:
                        raise RuntimeError("hybrid memory-probe correctness check failed")
        return

    if operation == "keygen":
        if backend == "oqs_sig":
            with oqs.Signature(algorithm.identifier) as signer:
                signer.generate_keypair()
        else:
            sodium.crypto_sign_keypair()
        return
    if backend == "oqs_sig":
        with oqs.Signature(algorithm.identifier) as signer:
            public_key = signer.generate_keypair()
            signature = signer.sign(MESSAGE)
            if operation == "verify":
                signer.verify(MESSAGE, signature, public_key)
    else:
        public_key, secret_key = sodium.crypto_sign_keypair()
        signed = sodium.crypto_sign(MESSAGE, secret_key)
        if operation == "verify":
            sodium.crypto_sign_open(signed, public_key)


def main() -> None:
    args = parse_args()
    pin_to_one_core()
    header = machine_header()
    algorithms = resolve_algorithms()
    print(header)
    print(
        f"operation n={args.iterations}; McEliece keygen n={args.mceliece_keygen_iterations}; "
        f"warm-ups={args.warmups}; memory runs={0 if args.skip_memory else args.memory_runs}\n"
    )
    print("Validating sizes before timing:")
    for algorithm in algorithms:
        mapping = (
            ""
            if algorithm.identifier == algorithm.spec.display_name
            else f" [{algorithm.identifier}]"
        )
        print(
            f"  {algorithm.spec.display_name}{mapping}: pk={algorithm.sizes[0]:,}, "
            f"sk={algorithm.sizes[1]:,}, ct/sig={algorithm.sizes[2]:,} "
            f"ss={algorithm.shared_secret_bytes if algorithm.shared_secret_bytes is not None else '-'} "
            f"{algorithm.size_check}"
        )
    if args.check_sizes:
        print("\nAll size checks passed; timings were not run.")
        return

    started = datetime.now(timezone.utc)
    run_id = started.strftime("pqc-%Y%m%dT%H%M%S%fZ")
    write_environment(args.environment_file, header, args, algorithms, started, None)
    summary_rows: list[dict[str, object]] = []
    raw_rows: list[dict[str, object]] = []
    memory_rows: list[dict[str, object]] = []

    for algorithm in algorithms:
        if algorithm.spec.kind == "KEM":
            timings = measure_kem(
                algorithm,
                args.iterations,
                args.mceliece_keygen_iterations,
                args.warmups,
            )
            memory_operations = ("keygen", "encaps", "decaps")
        else:
            timings = measure_signature(algorithm, args.iterations, args.warmups)
            memory_operations = ("keygen", "sign", "verify")
        append_raw_rows(raw_rows, algorithm, timings, run_id)

        if args.skip_memory:
            peak_ram: dict[str, int | str] = {"method": "not measured"}
        else:
            print(f"    measuring fresh-process peak RSS x{args.memory_runs} ...", flush=True)
            peak_ram = {
                "keygen": measure_peak_ram(
                    algorithm, memory_operations[0], args.memory_runs, memory_rows, run_id
                ),
                "op1": measure_peak_ram(
                    algorithm, memory_operations[1], args.memory_runs, memory_rows, run_id
                ),
                "op2": measure_peak_ram(
                    algorithm, memory_operations[2], args.memory_runs, memory_rows, run_id
                ),
                "method": f"max of {args.memory_runs} fresh-process ru_maxrss measurements",
            }
        summary_rows.append(
            make_summary_row(algorithm, timings, args.warmups, peak_ram, run_id)
        )
        write_results(
            f"{args.summary_csv}.partial",
            f"{args.compatibility_csv}.partial",
            f"{args.raw_csv}.partial",
            f"{args.memory_csv}.partial",
            summary_rows,
            raw_rows,
            memory_rows,
        )

    write_results(
        args.summary_csv,
        args.compatibility_csv,
        args.raw_csv,
        args.memory_csv,
        summary_rows,
        raw_rows,
        memory_rows,
    )
    for partial in (
        f"{args.summary_csv}.partial",
        f"{args.compatibility_csv}.partial",
        f"{args.raw_csv}.partial",
        f"{args.memory_csv}.partial",
    ):
        Path(partial).unlink(missing_ok=True)

    write_plain_results(args.output_table, header, summary_rows)
    finished = datetime.now(timezone.utc)
    write_environment(args.environment_file, header, args, algorithms, started, finished)
    print(
        f"\nWrote {args.summary_csv}, {args.compatibility_csv}, {args.raw_csv}, "
        f"{args.memory_csv}, "
        f"{args.output_table}, {args.environment_file}, and "
        f"{Path(args.environment_file).with_suffix('.json')}\n"
    )
    print("KEM ABSOLUTE VALUES")
    print(format_table(summary_rows, "KEM"))
    print("\nSIGNATURE ABSOLUTE VALUES")
    print(format_table(summary_rows, "SIG"))


if __name__ == "__main__":
    main()
