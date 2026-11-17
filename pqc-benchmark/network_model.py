#!/usr/bin/env python3
"""Model the duration of one UC1 key establishment on three link profiles.

duration = round-trip time + wire bytes * 8 / data rate + cryptographic latency

Ephemeral: wire = public key + ciphertext; latency = keygen + encaps + decaps.
Static:    wire = ciphertext;              latency = encaps + decaps.

Hybrids of X25519 with Classic McEliece and HQC were not measured. Their rows
are derived: sizes are exact (32 bytes are added to public key and ciphertext),
times are the sum of the two components.
"""

import csv

INPUT_CSV = "summary_results.csv"
OUTPUT_CSV = "uc1_network_time.csv"

# Illustrative link profiles set by the author: (data rate in bit/s, RTT in ms).
PROFILES = {
    "office": (100_000_000, 20.0),
    "industrial": (2_000_000, 50.0),
    "field": (64_000, 600.0),
}

DERIVED_HYBRIDS = [
    "Classic-McEliece-460896",
    "HQC-192",
    "Classic-McEliece-6960119",
    "HQC-256",
]


def load_kems():
    with open(INPUT_CSV, newline="", encoding="utf-8") as source:
        rows = [row for row in csv.DictReader(source) if row["kind"] == "KEM"]
    kems = {}
    for row in rows:
        kems[row["algorithm"]] = {
            "pk": int(row["public_key_bytes"]),
            "ct": int(row["ciphertext_or_sig_bytes"]),
            "keygen": float(row["keygen_ms_median"]),
            "encaps": float(row["op1_ms_median"]),
            "decaps": float(row["op2_ms_median"]),
            "derived": False,
        }
    x25519 = kems["X25519"]
    for name in DERIVED_HYBRIDS:
        component = kems[name]
        kems[f"Hybrid-X25519-{name}"] = {
            "pk": x25519["pk"] + component["pk"],
            "ct": x25519["ct"] + component["ct"],
            "keygen": x25519["keygen"] + component["keygen"],
            "encaps": x25519["encaps"] + component["encaps"],
            "decaps": x25519["decaps"] + component["decaps"],
            "derived": True,
        }
    return kems


def wire_and_crypto(kem, variant):
    if variant == "ephemeral":
        return kem["pk"] + kem["ct"], kem["keygen"] + kem["encaps"] + kem["decaps"]
    return kem["ct"], kem["encaps"] + kem["decaps"]


def duration_ms(kem, variant, profile):
    rate, rtt = PROFILES[profile]
    wire, crypto = wire_and_crypto(kem, variant)
    transmission = wire * 8 / rate * 1000
    return rtt, transmission, crypto, rtt + transmission + crypto


def main():
    kems = load_kems()
    rows = []
    for variant in ("ephemeral", "static"):
        for profile, (rate, rtt) in PROFILES.items():
            baseline = duration_ms(kems["X25519"], variant, profile)[3]
            for name, kem in kems.items():
                wire, _ = wire_and_crypto(kem, variant)
                _, transmission, crypto, total = duration_ms(kem, variant, profile)
                rows.append({
                    "algorithm": name,
                    "derived": "yes" if kem["derived"] else "no",
                    "variant": variant,
                    "profile": profile,
                    "data_rate_bps": rate,
                    "rtt_ms": rtt,
                    "wire_bytes": wire,
                    "transmission_ms": round(transmission, 6),
                    "crypto_latency_ms": round(crypto, 6),
                    "total_ms": round(total, 6),
                    "ratio_vs_x25519": round(total / baseline, 6),
                })
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {OUTPUT_CSV} ({len(rows)} rows)")


if __name__ == "__main__":
    main()
