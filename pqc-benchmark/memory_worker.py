#!/usr/bin/env python3
"""Fresh-process worker used for best-effort peak RSS measurements."""

from __future__ import annotations

import argparse
import gc
import json
import os
import resource

import psutil

from benchmark import exercise_operation, pin_to_one_core, resolve_algorithms


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--algorithm", required=True)
    parser.add_argument(
        "--operation",
        required=True,
        choices=("keygen", "encaps", "decaps", "sign", "verify"),
    )
    args = parser.parse_args()
    pin_to_one_core()
    algorithms = {
        item.spec.display_name: item for item in resolve_algorithms()
    }
    if args.algorithm not in algorithms:
        raise SystemExit(f"unknown algorithm: {args.algorithm}")
    gc.collect()
    process = psutil.Process()
    baseline_rss_kb = process.memory_info().rss // 1024
    baseline_hwm_kb = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    exercise_operation(algorithms[args.algorithm], args.operation)
    after_rss_kb = process.memory_info().rss // 1024
    peak_rss_kb = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    print(
        json.dumps(
            {
                "algorithm": args.algorithm,
                "operation": args.operation,
                "pid": os.getpid(),
                "baseline_rss_kb": baseline_rss_kb,
                "baseline_hwm_kb": baseline_hwm_kb,
                "after_rss_kb": after_rss_kb,
                "peak_rss_kb": peak_rss_kb,
                "incremental_hwm_kb": max(0, peak_rss_kb - baseline_hwm_kb),
                "scope": "fresh process; HWM delta includes operation fixtures and operation",
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
