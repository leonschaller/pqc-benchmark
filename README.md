# pqc-benchmark

Code and data of the benchmark in the master's thesis *Post-Quantum Cryptography in Defence Supply Chains: A Strategic and Technical Evaluation for Industrial Suppliers* (Leon Schaller, University of St.Gallen, 2026). The thesis sets out the method in Section 5.3, reports the results in Chapter 7 and documents the run in Appendix C.

The ZIP file attached to release v1.0 is the digital appendix submitted with the thesis (SHA-256 `8165ffcac2b03c8c0b90b9c20baac5d769e2a556a3bc9b70c6580d1a454f1d5b`). This repository holds the same 31 files plus this README.

## What was measured

Sizes, computation time and memory of 13 configurations:

| Type | Classical baseline | Post-quantum | Hybrid |
|---|---|---|---|
| Key establishment | X25519 | ML-KEM-768, ML-KEM-1024, Classic-McEliece-460896, Classic-McEliece-6960119, HQC-192, HQC-256 | X25519 + ML-KEM-768, X25519 + ML-KEM-1024 |
| Signatures | Ed25519 | ML-DSA-87, SLH-DSA-SHA2-256s, SLH-DSA-SHA2-256f | – |

The post-quantum schemes come from liboqs 0.16.0, the baselines from libsodium 1.0.20 through PyNaCl. All values in the thesis come from one run (`pqc-20260820T181749928614Z`, 20 August 2026) with 37,060 timing samples and 117 memory trials.

## Files

- **Code:** `benchmark.py` (harness), `memory_worker.py`, `crypto_self_test.py`, `scenario_analysis.py`, `network_model.py`, `median_ci.py`, `verify_results.py`, `plot.py`, `build_manifest.py`
- **Data of the run:** `raw_results.csv` (all timing samples in nanoseconds), `summary_results.csv` (one row per scheme; `results.csv` is an identical copy), `memory_results.csv`
- **Derived values:** `uc1_kem_metrics.csv`, `uc2_signature_metrics.csv`, `uc3_footprint_metrics.csv`, `uc1_network_time.csv`, `median_ci.csv`, `results_table.txt`, `scenario_tables.txt` and five PNG figures
- **Record of the environment:** `environment.txt`, `environment.json`, `requirements.lock.txt`, `setup.txt`, `methodology_notes.md`, `SHA256SUMS`

## Checking the results

Python 3 is enough, since these scripts only read the CSV files:

```
sha256sum -c SHA256SUMS
python verify_results.py
python scenario_analysis.py
python network_model.py
python median_ci.py
```

The first command confirms that no file was changed. `verify_results.py` recomputes every median, quartile and use-case value from the raw samples, and the other three rebuild the derived files.

## Repeating the measurement

A new run needs Linux or WSL2 and liboqs 0.16.0 as a shared library:

```
git clone --branch 0.16.0 https://github.com/open-quantum-safe/liboqs
cmake -S liboqs -B liboqs/build -GNinja -DBUILD_SHARED_LIBS=ON \
      -DCMAKE_BUILD_TYPE=Release -DOQS_DIST_BUILD=ON
ninja -C liboqs/build install
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.lock.txt
python crypto_self_test.py
python benchmark.py
```

The full run takes about 26 minutes and overwrites the result files, so start it in a copy of the folder. The option `--iterations` shortens it for a test. Artefact sizes are the same on every machine, while timings depend on processor, build and system load.

## Limits

liboqs is a library for research and prototyping. The measured code is not a validated cryptographic module, and the hybrid wrappers concatenate raw outputs without a key derivation function, so they are not production key material.

## Citation

Schaller, L. (2026). *Post-quantum cryptography in defence supply chains: A strategic and technical evaluation for industrial suppliers* [Master's thesis, University of St.Gallen].
