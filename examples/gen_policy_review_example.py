#!/usr/bin/env python3
"""Regenerate examples/policy_review_request.json from freshly built PKI.

The bundle carries four independent roots so one request demonstrates every
policy outcome (check_time fixed at 2030-01-01, certificate windows
2024-2035 so the example stays reproducible for years):

1. api.example.com        role=server, fully compliant current (Old Root ->
   leaf) and target (New Root -> New Intermediate -> leaf) chains; the
   eligible target chain is ready to hand to /plans.
2. role-mismatch.example  role=server, but its leaf carries only
   id-kp-clientAuth -> eku_missing (role/EKU conflict example).
3. pathlen.example        Shallow Root asserts pathLenConstraint=0 yet a
   non-self-issued intermediate sits below it ->
   path_len_constraint_violated (path-length conflict example).
4. ext-conflict.example   its intermediate carries an unrecognized *critical*
   extension (OID 1.2.3.4.5.6.7.8) -> unknown_critical_extension
   (critical-extension conflict example).
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import UnrecognizedExtension
from cryptography.x509.oid import NameOID

NOT_BEFORE = datetime(2024, 1, 1, tzinfo=timezone.utc)
NOT_AFTER = datetime(2035, 1, 1, tzinfo=timezone.utc)
CHECK_TIME = datetime(2030, 1, 1, tzinfo=timezone.utc)

SERVER_AUTH = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.1")
CLIENT_AUTH = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.2")


def dn(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def key():
    return ec.generate_private_key(ec.SECP256R1())


def _ku(**bits):
    defaults = dict(
        digital_signature=False, content_commitment=False,
        key_encipherment=False, data_encipherment=False,
        key_agreement=False, key_cert_sign=False, crl_sign=False,
        encipher_only=False, decipher_only=False,
    )
    defaults.update(bits)
    return x509.KeyUsage(**defaults)


CA_KU = _ku(key_cert_sign=True, crl_sign=True)


def issue(subject_cn, issuer_name, issuer_key, subject_key, *, is_ca,
          path_len=None, key_usage=None, eku=None, sans=(),
          critical_unknown=()):
    builder = (
        x509.CertificateBuilder()
        .subject_name(dn(subject_cn))
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=path_len),
                       critical=True)
    )
    if key_usage is not None:
        builder = builder.add_extension(key_usage, critical=True)
    if eku is not None:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(eku), critical=False)
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(n) for n in sans]), critical=False)
    for oid in critical_unknown:
        builder = builder.add_extension(
            UnrecognizedExtension(x509.ObjectIdentifier(oid),
                                  b"\x04\x01\x00"),
            critical=True)
    return builder.sign(issuer_key, hashes.SHA256())


def pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def fingerprint(cert) -> str:
    return hashlib.sha256(
        cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def main() -> None:
    certs = {}

    # -- 1. compliant rotation: Old Root -> leaf ; New Root -> inter -> leaf --
    old_root_key = key()
    old_root = issue("Old Root CA", dn("Old Root CA"), old_root_key,
                     old_root_key, is_ca=True, key_usage=CA_KU)
    current_leaf = issue(
        "api.example.com", dn("Old Root CA"), old_root_key, key(),
        is_ca=False,
        key_usage=_ku(digital_signature=True, key_encipherment=True),
        eku=[SERVER_AUTH], sans=["api.example.com"])

    new_root_key = key()
    new_root = issue("New Root CA", dn("New Root CA"), new_root_key,
                     new_root_key, is_ca=True, key_usage=CA_KU)
    inter_key = key()
    new_inter = issue("New Intermediate CA", dn("New Root CA"), new_root_key,
                      inter_key, is_ca=True, key_usage=CA_KU)
    target_leaf = issue(
        "api.example.com", dn("New Intermediate CA"), inter_key, key(),
        is_ca=False,
        key_usage=_ku(digital_signature=True, key_encipherment=True),
        eku=[SERVER_AUTH], sans=["api.example.com"])

    # -- 2. role / EKU conflict: server endpoint, clientAuth-only leaf --------
    role_bad_leaf = issue(
        "role-mismatch.example", dn("New Intermediate CA"), inter_key, key(),
        is_ca=False,
        key_usage=_ku(digital_signature=True),
        eku=[CLIENT_AUTH], sans=["role-mismatch.example"])

    # -- 3. path length conflict: root pathLen=0 + one intermediate -----------
    shallow_root_key = key()
    shallow_root = issue("Shallow Root CA", dn("Shallow Root CA"),
                         shallow_root_key, shallow_root_key, is_ca=True,
                         path_len=0, key_usage=CA_KU)
    shallow_inter_key = key()
    shallow_inter = issue("Shallow Intermediate CA", dn("Shallow Root CA"),
                          shallow_root_key, shallow_inter_key, is_ca=True,
                          key_usage=CA_KU)
    pathlen_leaf = issue(
        "pathlen.example", dn("Shallow Intermediate CA"), shallow_inter_key,
        key(), is_ca=False,
        key_usage=_ku(digital_signature=True, key_encipherment=True),
        eku=[SERVER_AUTH], sans=["pathlen.example"])

    # -- 4. unknown critical extension on the intermediate --------------------
    ux_root_key = key()
    ux_root = issue("UX Root CA", dn("UX Root CA"), ux_root_key,
                    ux_root_key, is_ca=True, key_usage=CA_KU)
    ux_inter_key = key()
    ux_inter = issue(
        "UX Intermediate CA", dn("UX Root CA"), ux_root_key, ux_inter_key,
        is_ca=True, key_usage=CA_KU,
        critical_unknown=("1.2.3.4.5.6.7.8",))
    ux_leaf = issue(
        "ext-conflict.example", dn("UX Intermediate CA"), ux_inter_key,
        key(), is_ca=False,
        key_usage=_ku(digital_signature=True, key_encipherment=True),
        eku=[SERVER_AUTH], sans=["ext-conflict.example"])

    # Shuffled bundle, order deliberately meaningless.
    bundle = [
        pem(target_leaf), pem(ux_inter), pem(old_root), pem(pathlen_leaf),
        pem(shallow_root), pem(current_leaf), pem(new_inter), pem(ux_leaf),
        pem(new_root), pem(role_bad_leaf), pem(shallow_inter), pem(ux_root),
    ]

    payload = {
        "pem_certificates": bundle,
        "trust_roots": [
            fingerprint(old_root), fingerprint(new_root),
            fingerprint(shallow_root), fingerprint(ux_root),
        ],
        "check_time": CHECK_TIME.isoformat().replace("+00:00", "Z"),
        "max_skew_seconds": 0,
        "endpoints": [
            {
                "endpoint_id": "api.example.com",
                "current_leaf_fingerprint": fingerprint(current_leaf),
                "target_leaf_fingerprint": fingerprint(target_leaf),
                "role": "server",
                "required_eku": [],
            },
            {
                "endpoint_id": "role-mismatch.example",
                "current_leaf_fingerprint": fingerprint(role_bad_leaf),
                "target_leaf_fingerprint": fingerprint(role_bad_leaf),
                "role": "server",
                "required_eku": [],
            },
            {
                "endpoint_id": "pathlen.example",
                "current_leaf_fingerprint": fingerprint(pathlen_leaf),
                "target_leaf_fingerprint": fingerprint(pathlen_leaf),
                "role": "server",
                "required_eku": [],
            },
            {
                "endpoint_id": "ext-conflict.example",
                "current_leaf_fingerprint": fingerprint(ux_leaf),
                "target_leaf_fingerprint": fingerprint(ux_leaf),
                "role": "server",
                "required_eku": [],
            },
        ],
    }

    out = Path(__file__).with_name("policy_review_request.json")
    out.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
