#!/usr/bin/env python3
"""95 per cent confidence interval of each median, read from the sorted samples.

The interval bounds are order statistics chosen with the binomial distribution
(p = 0.5), so no assumption about the shape of the timing distribution is made.
half_width_pct = (upper - lower) / 2 / median * 100.
"""

import csv
import math
import statistics
from collections import defaultdict

INPUT_CSV = "raw_results.csv"
OUTPUT_CSV = "median_ci.csv"


def ci_ranks(n, level=0.95):
    """Return 1-based ranks (j, n + 1 - j) of the narrowest interval with coverage >= level."""
    pmf = [math.comb(n, k) / 2 ** n for k in range(n + 1)]
    ranks = None
    for j in range(1, n // 2 + 1):
        if sum(pmf[j:n + 1 - j]) >= level:
            ranks = (j, n + 1 - j)
    return ranks


def main():
    samples = defaultdict(list)
    with open(INPUT_CSV, newline="", encoding="utf-8") as source:
        for row in csv.DictReader(source):
            samples[row["algorithm"], row["operation"]].append(int(row["elapsed_ns"]))

    rows = []
    for (algorithm, operation), values in samples.items():
        values.sort()
        n = len(values)
        j, k = ci_ranks(n)
        median = statistics.median(values)
        lower, upper = values[j - 1], values[k - 1]
        rows.append({
            "algorithm": algorithm,
            "operation": operation,
            "n": n,
            "median_ms": round(median / 1e6, 6),
            "ci_lower_ms": round(lower / 1e6, 6),
            "ci_upper_ms": round(upper / 1e6, 6),
            "half_width_pct": round((upper - lower) / 2 / median * 100, 2),
        })

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {OUTPUT_CSV} ({len(rows)} operations)")


if __name__ == "__main__":
    main()
