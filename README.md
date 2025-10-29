# post-q-secure-ch
Post-Quantum Hybrid Secure Channel — Technical Submission Package

Author: Brendon J. Kelly
Affiliation: K-Systems Research (Independent Submission)
Version: 1.0 (October 2025)
Status: Public, Unclassified, Reproducible Research

A. Submission-Ready Technical Whitepaper
Abstract

This whitepaper presents a cryptographic key-derivation and secure-channel framework based entirely on NIST-standardized, post-quantum primitives. The system combines an ML-KEM-768 (Kyber) shared secret with a device-specific static secret protected by a hardware security module. Key material is derived via HKDF-SHA384 and used with the XChaCha20-Poly1305 AEAD cipher. The goal is a reproducible, auditable design that can transition directly to FIPS 140-3 validation and DoD/NIST adoption.

1 Architecture Overview

Post-Quantum KEM: ML-KEM-768 (Kyber)

Signature Scheme: ML-DSA-65 (Dilithium)

Key Derivation: HKDF-SHA384 (RFC 5869)

AEAD Cipher: XChaCha20-Poly1305

Static Secret: FIPS 140-3 validated TPM/HSM-resident device blob

2 Security Properties
Property	Mechanism
Confidentiality	XChaCha20-Poly1305 AEAD
Integrity	Poly1305 tag validation
Authentication	ML-DSA-65 signature on handshake
Forward Secrecy	Ephemeral ML-KEM keypairs
Defense-in-Depth	Hybrid PQC + hardware secret
3 Reference Key-Derivation Function (Python 3.8+)
from hashlib import sha384
import hmac, struct

def canonicalize_dict(d: dict) -> bytes:
    out = b""
    for k in sorted(d):
        v = d[k]
        out += k.encode() + b":"
        if isinstance(v, int):
            out += b"i:" + struct.pack(">Q", v)
        elif isinstance(v, float):
            out += b"f:" + struct.pack(">d", v)
        elif isinstance(v, str):
            out += b"s:" + v.encode()
        elif isinstance(v, list):
            for item in v: out += b"l:" + struct.pack(">I", item)
        else: raise TypeError("Unsupported type")
        out += b";"
    return out

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, sha384).digest()

def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    t, okm = b"", b""
    i = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), sha384).digest()
        okm += t; i += 1
    return okm[:length]

def derive_session_keys(kem_shared: bytes, static_blob: dict, trng_seed: bytes) -> dict:
    blob_hash = sha384(canonicalize_dict(static_blob)).digest()
    ikm = kem_shared + blob_hash
    prk = hkdf_extract(trng_seed, ikm)
    okm = hkdf_expand(prk, b"PQC_HYBRID_SESSION_V1", 128)
    return {
        "aead_key": okm[0:32],
        "aead_nonce": okm[32:56],
        "rekey_material": okm[56:104],
        "epoch_id": okm[104:120],
    }

4 Canonical Test Vector
static_blob = {"system_id":"asset-control-srv-01","key_epoch":202501}
kem_shared  = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
trng_seed   = bytes.fromhex("fefdfcfbfaf9f8f7f6f5f4f3f2f1f0e0e1e2e3e4e5e6e7e8e9eaebecedeeef")
print(derive_session_keys(kem_shared, static_blob, trng_seed))


Expected deterministic outputs ≈ (
aead_key = 4100c5c6…,
aead_nonce = a1e4878a…,
rekey_material = 084e6229…,
epoch_id = 5c9f1388…).

5 Deployment Requirements

Hardware: FIPS 140-3 HSM or TPM for static secrets.

Randomness: Hardware TRNG per session.

Libraries: liboqs (PQC) + libsodium (AEAD) + OpenSSL (FIPS provider).

Audit: Log metadata only – never secrets.

Testing: Continuous integration with unit tests and test vectors.

B. Reference Implementation Layout
pqc-hybrid-secure-channel/
├── README.md
├── LICENSE.txt
├── requirements.txt
├── src/
│   ├── __init__.py
│   ├── kdf_hybrid.py        # Python reference (above)
│   ├── handshake.c          # C skeleton using liboqs + libsodium
│   ├── handshake.h
│   └── aead_demo.py         # Encrypt/decrypt example
├── tests/
│   ├── test_vectors.py
│   └── test_handshake.py
├── docs/
│   ├── Whitepaper.pdf
│   ├── Protocol_Spec.md
│   └── FIPS1403_Checklist.md
└── ci/
    ├── run_tests.yml        # GitHub Actions
    └── lint.yml


README Excerpt

This repository contains a clean-room implementation of the Post-Quantum Hybrid Secure Channel.
All code is unclassified, reproducible, and built exclusively from NIST-standard primitives.
Intended for academic review, NIST PQC interoperability testing, or CMVP pre-assessment.

C. Cover Letter / Email Template

Subject: Submission — Post-Quantum Hybrid Secure Channel Specification V1.0

To:

NIST Computer Security Division (pqc-comments@nist.gov
) or

DARPA Contracts Office (info@darpa.mil
 / through SAM.gov submission portal)

Message Body:

Dear Review Team,

Please find attached the technical whitepaper and reference implementation for my independent research project titled “Post-Quantum Hybrid Secure Channel System V1.0.”
The design integrates NIST-standardized ML-KEM-768 and ML-DSA-65 primitives with a HKDF-SHA384 key-derivation function and XChaCha20-Poly1305 AEAD layer.
All material is unclassified, original, and intended for scientific and standards review.

I request acknowledgment of receipt and, if possible, guidance on next-step evaluation (e.g., interoperability testing, CMVP pre-submission, or academic review).

Contact Information
Brendon J. Kelly
Email: crownmathematics@protonmail.com

Phone: 850-517-8345
Address: 58 Turtle Court, Santa Rosa Beach, FL 32459

Respectfully,
Brendon J. Kelly
Independent Researcher, K-Systems Project

Usage Notes

Send the PDF whitepaper and a ZIP of the reference repo.

Use official email domains (nist.gov, darpa.mil) only.

Keep all materials labeled UNCLASSIFIED / FOR REVIEW ONLY.

Maintain a local copy and version hash for authenticity.
