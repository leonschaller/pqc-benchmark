# PQC benchmark methodology notes

All 13 algorithms were measured in one pinned-core session, so every comparison
uses one machine, library build, timing method, and run ID.

## Use-case metrics

The derived files use these definitions:

- UC1 ephemeral wire bytes = public key + ciphertext; cryptographic latency =
  key generation + encapsulation + decapsulation.
- UC1 static wire bytes = ciphertext; cryptographic latency = encapsulation +
  decapsulation; public-key provisioning remains a separate field.
- UC2 reports signature bytes, verification milliseconds, and public-key
  provisioning bytes as separate quantities. Bytes and milliseconds are never
  added into an artificial value.
- UC3 leads with the exact public-key + secret-key footprint. Desktop timings
  and process RAM are retained but explicitly marked non-representative for a
  constrained target.
- UC1 is also modelled on three illustrative link profiles (office 100 Mbit/s and
  20 ms RTT, industrial 2 Mbit/s and 50 ms, field 64 kbit/s and 600 ms):
  duration = RTT + wire bytes * 8 / data rate + cryptographic latency. The model
  leaves out headers, packet loss and TCP slow start (`network_model.py`).
- The overhead ratio is reported per profile and not aggregated across profiles,
  because the interviews gave no profile weights.

## Deliberate scope exclusions

These are deliberate study boundaries rather than accidental omissions:

- No code-based signatures are included. The signature comparison is
  lattice-based ML-DSA versus stateless hash-based SLH-DSA; the two distinct
  code-based families are covered on the KEM side by Classic McEliece and HQC.
- Signatures are measured at NIST level 5 only because the defence/long-lived
  firmware context is anchored by ML-DSA-87. ML-DSA-65 and SLH-DSA-192s would
  be optional extensions only if full parameter-level symmetry were required.
- FrodoKEM is excluded because the selected study axis is structured-lattice
  ML-KEM versus code-based Classic McEliece/HQC; adding an unstructured-lattice
  family would broaden rather than sharpen that comparison.
- UC1 measures key establishment only. Signature authentication from a full TLS
  handshake is treated separately under the UC2 signing analysis.
- Stateful LMS/XMSS signatures are excluded because their state-management
  obligations are unsuitable for the target supplier workflow; SLH-DSA is the
  stateless hash-based alternative used here.

## Cryptographic constructions

X25519 uses a fresh ephemeral keypair plus raw `crypto_scalarmult` for each
encapsulation. Ed25519 uses libsodium's 64-byte secret-key representation and
combined `crypto_sign` API, so its sign/verify timings include message-buffer
copying. The hybrids are reusable wrappers that call both X25519 and ML-KEM,
export the complete concatenated secret key, validate aggregate input lengths,
and concatenate in fixed X25519 || ML-KEM order.

These raw shared outputs are benchmark constructions only. Production key
exchange must use an analysed, domain-separated hybrid combiner/KDF.

## Identifier and version disclosure

This liboqs 0.16.0 build does not expose literal `HQC-192` or `HQC-256`
identifiers. It exposes `HQC-3` and `HQC-5`, whose implementation metadata
reports the corresponding level-3 and level-5 HQC revision. HQC-192 and HQC-256
are kept as display labels, while the actual library identifiers, revisions, and
version-dependent sizes are preserved in every summary/environment artefact.

## Measurement limits

- All 37,060 successful timing samples are retained as integer nanoseconds.
  Summary values are derived from those samples with no outlier deletion.
- Q1 and Q3 use inclusive quartiles; IQR is Q3 - Q1; standard deviation is the
  population standard deviation.
- Native liboqs allocations are not visible to Python allocation tracers. Peak
  RAM therefore uses three isolated Linux processes per algorithm/operation and
  records absolute `ru_maxrss`, baseline HWM/RSS, post-operation RSS, and the
  incremental HWM. Setup/import cost is included, so absolute process peaks are
  conservative and may be identical when runtime startup dominates.
- A uniform deterministic RNG seed is unavailable across ML-KEM, McEliece, HQC,
  signatures, PyNaCl, and the production liboqs APIs. The run records the use of
  their OS-backed CSPRNGs instead of changing the measured operations.
- The local liboqs source checkout commit is recorded but is not claimed as
  independently proven binary provenance; the loaded library path and SHA-256
  hash in `environment.json` are authoritative.

`crypto_self_test.py` covers sizes, round trips, signature tamper rejection,
X25519 ephemeral freshness, hybrid secret-key import/restoration, malformed
aggregate input rejection, and hybrid tampering. `verify_results.py`
independently recomputes timing statistics and checks sample counts, affinity,
RAM trials, sizes, and UC1/UC2/UC3 formulas.
