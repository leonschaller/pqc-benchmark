#!/usr/bin/env python3
"""Correctness self-test for the PQC benchmark constructions.

The test deliberately prints only algorithm names, sizes, and PASS/FAIL status;
public keys, secret keys, ciphertexts, signatures, and shared secrets are never
written to disk or printed.
"""

from __future__ import annotations

import sys
from collections.abc import Callable

import nacl.bindings as sodium
from nacl.exceptions import BadSignatureError
import oqs

import benchmark


class SelfTestFailure(AssertionError):
    """Raised when a cryptographic invariant does not hold."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SelfTestFailure(message)


def flip_byte(value: bytes, index: int = 0) -> bytes:
    require(bool(value), "cannot tamper with an empty value")
    changed = bytearray(value)
    changed[index] ^= 0x01
    return bytes(changed)


def expect_value_error(action: Callable[[], object], description: str) -> None:
    try:
        action()
    except ValueError:
        return
    raise SelfTestFailure(f"{description} was not rejected")


def test_oqs_kem(algorithm: benchmark.ResolvedAlgorithm) -> None:
    with oqs.KeyEncapsulation(algorithm.identifier) as receiver, oqs.KeyEncapsulation(
        algorithm.identifier
    ) as sender:
        public_key = receiver.generate_keypair()
        secret_key = receiver.export_secret_key()
        ciphertext, sender_secret = sender.encap_secret(public_key)
        receiver_secret = receiver.decap_secret(ciphertext)

    expected_pk, expected_sk, expected_ct = algorithm.sizes
    require(len(public_key) == expected_pk, f"{algorithm.spec.display_name}: public-key size")
    require(len(secret_key) == expected_sk, f"{algorithm.spec.display_name}: secret-key size")
    require(len(ciphertext) == expected_ct, f"{algorithm.spec.display_name}: ciphertext size")
    require(
        len(sender_secret) == algorithm.shared_secret_bytes,
        f"{algorithm.spec.display_name}: shared-secret size",
    )
    require(receiver_secret == sender_secret, f"{algorithm.spec.display_name}: secret mismatch")


def test_x25519(algorithm: benchmark.ResolvedAlgorithm) -> None:
    public_key, secret_key = benchmark.x25519_keygen()
    ciphertext, sender_secret = benchmark.x25519_encapsulate(public_key)
    receiver_secret = benchmark.x25519_decapsulate(secret_key, ciphertext)

    expected_pk, expected_sk, expected_ct = algorithm.sizes
    require(len(public_key) == expected_pk, "X25519: public-key size")
    require(len(secret_key) == expected_sk, "X25519: secret-key size")
    require(len(ciphertext) == expected_ct, "X25519: ciphertext size")
    require(len(sender_secret) == algorithm.shared_secret_bytes, "X25519: shared-secret size")
    require(receiver_secret == sender_secret, "X25519: secret mismatch")


def test_hybrid(algorithm: benchmark.ResolvedAlgorithm) -> None:
    identifier = benchmark.pq_identifier(algorithm)
    expected_pk, expected_sk, expected_ct = algorithm.sizes
    expected_ss = algorithm.shared_secret_bytes
    require(expected_ss is not None, f"{algorithm.spec.display_name}: missing shared-secret size")

    with benchmark.HybridKEM(identifier) as receiver, benchmark.HybridKEM(identifier) as sender:
        public_key = receiver.generate_keypair()
        secret_key = receiver.export_secret_key()
        ciphertext, sender_secret = sender.encap_secret(public_key)
        receiver_secret = receiver.decap_secret(ciphertext)

        require(len(public_key) == expected_pk, f"{algorithm.spec.display_name}: public-key size")
        require(len(secret_key) == expected_sk, f"{algorithm.spec.display_name}: secret-key size")
        require(len(ciphertext) == expected_ct, f"{algorithm.spec.display_name}: ciphertext size")
        require(len(sender_secret) == expected_ss, f"{algorithm.spec.display_name}: shared-secret size")
        require(receiver_secret == sender_secret, f"{algorithm.spec.display_name}: secret mismatch")

        expect_value_error(
            lambda: sender.encap_secret(public_key[:-1]),
            f"{algorithm.spec.display_name}: short aggregate public key",
        )
        expect_value_error(
            lambda: sender.encap_secret(public_key + b"\x00"),
            f"{algorithm.spec.display_name}: long aggregate public key",
        )
        expect_value_error(
            lambda: receiver.decap_secret(ciphertext[:-1]),
            f"{algorithm.spec.display_name}: short aggregate ciphertext",
        )
        expect_value_error(
            lambda: receiver.decap_secret(ciphertext + b"\x00"),
            f"{algorithm.spec.display_name}: long aggregate ciphertext",
        )

    # Importing the aggregate secret key must restore decapsulation capability.
    with benchmark.HybridKEM(identifier, secret_key=secret_key) as restored, benchmark.HybridKEM(
        identifier
    ) as sender:
        require(
            restored.export_secret_key() == secret_key,
            f"{algorithm.spec.display_name}: secret-key export/import round trip",
        )
        ciphertext, sender_secret = sender.encap_secret(public_key)
        require(
            restored.decap_secret(ciphertext) == sender_secret,
            f"{algorithm.spec.display_name}: restored key cannot decapsulate",
        )

        # ML-KEM uses implicit rejection for a same-length corrupt ciphertext.
        # An exception is also acceptable, but successful decapsulation must not
        # reproduce the authentic combined secret.
        tampered_ciphertext = flip_byte(ciphertext, len(ciphertext) - 1)
        try:
            tampered_secret = restored.decap_secret(tampered_ciphertext)
        except Exception:
            pass
        else:
            require(
                tampered_secret != sender_secret,
                f"{algorithm.spec.display_name}: tampered ciphertext reproduced the secret",
            )


def test_oqs_signature(algorithm: benchmark.ResolvedAlgorithm) -> None:
    with oqs.Signature(algorithm.identifier) as signer:
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()
        signature = signer.sign(benchmark.MESSAGE)
        verified = signer.verify(benchmark.MESSAGE, signature, public_key)

    expected_pk, expected_sk, expected_signature = algorithm.sizes
    require(len(public_key) == expected_pk, f"{algorithm.spec.display_name}: public-key size")
    require(len(secret_key) == expected_sk, f"{algorithm.spec.display_name}: secret-key size")
    require(
        len(signature) == expected_signature,
        f"{algorithm.spec.display_name}: signature size",
    )
    require(verified, f"{algorithm.spec.display_name}: signature verification")


def test_ed25519(algorithm: benchmark.ResolvedAlgorithm) -> None:
    public_key, secret_key = sodium.crypto_sign_keypair()
    signed = sodium.crypto_sign(benchmark.MESSAGE, secret_key)
    signature = signed[: sodium.crypto_sign_BYTES]

    expected_pk, expected_sk, expected_signature = algorithm.sizes
    require(len(public_key) == expected_pk, "Ed25519: public-key size")
    require(len(secret_key) == expected_sk, "Ed25519: secret-key size")
    require(len(signature) == expected_signature, "Ed25519: signature size")
    require(sodium.crypto_sign_open(signed, public_key) == benchmark.MESSAGE, "Ed25519: verify")

    tampered_message = benchmark.MESSAGE[:-1] + bytes([benchmark.MESSAGE[-1] ^ 0x01])
    for description, invalid_signed in (
        ("tampered message", signature + tampered_message),
        ("tampered signature", flip_byte(signature) + benchmark.MESSAGE),
    ):
        try:
            sodium.crypto_sign_open(invalid_signed, public_key)
        except BadSignatureError:
            continue
        raise SelfTestFailure(f"Ed25519: {description} was accepted")


def test_x25519_ephemeral_freshness(samples: int = 100) -> None:
    receiver_public, _ = benchmark.x25519_keygen()
    ephemeral_public_keys = {
        benchmark.x25519_encapsulate(receiver_public)[0] for _ in range(samples)
    }
    require(
        len(ephemeral_public_keys) == samples,
        f"X25519: only {len(ephemeral_public_keys)}/{samples} ephemeral public keys were unique",
    )


def main() -> int:
    try:
        algorithms = benchmark.resolve_algorithms()
        require(len(algorithms) == 13, f"resolved {len(algorithms)} algorithms, expected 13")
        require(
            len({algorithm.spec.display_name for algorithm in algorithms}) == 13,
            "resolved algorithm names are not unique",
        )
        print("PASS resolved algorithms: 13")

        oqs_kems = 0
        oqs_signatures = 0
        hybrids = 0
        for algorithm in algorithms:
            backend = algorithm.spec.backend
            if backend == "oqs_kem":
                test_oqs_kem(algorithm)
                oqs_kems += 1
            elif backend == "x25519":
                test_x25519(algorithm)
            elif backend == "hybrid":
                test_hybrid(algorithm)
                hybrids += 1
            elif backend == "oqs_sig":
                test_oqs_signature(algorithm)
                oqs_signatures += 1
            elif backend == "ed25519":
                test_ed25519(algorithm)
            else:
                raise SelfTestFailure(f"unsupported backend: {backend}")
            print(f"PASS {algorithm.spec.display_name}: sizes and round trip")

        require(oqs_kems > 0, "no ordinary liboqs KEM was exercised")
        require(oqs_signatures > 0, "no ordinary liboqs signature was exercised")
        require(hybrids == 2, f"exercised {hybrids} hybrids, expected 2")
        print(f"PASS ordinary liboqs coverage: {oqs_kems} KEMs, {oqs_signatures} signatures")
        print(f"PASS hybrid negative/import tests: {hybrids} constructions")

        test_x25519_ephemeral_freshness(100)
        print("PASS X25519 ephemeral freshness: 100/100 unique public keys")
        print("PASS Ed25519 rejection: tampered message and signature")
        print("PASS all cryptographic self-tests")
        return 0
    except Exception as error:
        print(f"FAIL {type(error).__name__}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
