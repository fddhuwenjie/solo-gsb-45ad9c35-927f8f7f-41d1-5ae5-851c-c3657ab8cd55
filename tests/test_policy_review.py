"""Tests for POST /deployments/policy-review.

Certificate purpose (CA/keyCertSign/keyUsage/EKU) and path-length
(basicConstraints pathLenConstraint) review of both the current and target
chains at one fixed check_time, plus fail-closed handling of unrecognized
critical extensions and the shared normalize-style 422 contract.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import UnrecognizedExtension
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app.main import app
from app.policy import _decode_oid, _raw_extensions

CHECK = datetime(2030, 6, 1, tzinfo=timezone.utc)

client = TestClient(app)


# ---------------------------------------------------------------------------
# PKI factory
# ---------------------------------------------------------------------------


def _key():
    return ec.generate_private_key(ec.SECP256R1())


def _dn(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _ku(**bits):
    """KeyUsage with encipher/decipher defaulting to False unless overridden."""
    defaults = dict(
        digital_signature=False, content_commitment=False,
        key_encipherment=False, data_encipherment=False,
        key_agreement=False, key_cert_sign=False, crl_sign=False,
        encipher_only=False, decipher_only=False,
    )
    defaults.update(bits)
    return x509.KeyUsage(**defaults)


SERVER_AUTH = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.1")
CLIENT_AUTH = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.2")
ANY_EKU = x509.ObjectIdentifier("2.5.29.37.0")


def _cert(subject_cn, issuer_cn, issuer_key, *, subject_key=None, ca=False,
          path_len=None, key_usage=None, eku=None, sans=(),
          critical_unknown=(), not_before=None, not_after=None,
          omit_basic_constraints=False):
    subject_key = subject_key or _key()
    builder = (
        x509.CertificateBuilder()
        .subject_name(_dn(subject_cn))
        .issuer_name(_dn(issuer_cn))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or CHECK - timedelta(days=365))
        .not_valid_after(not_after or CHECK + timedelta(days=3650))
    )
    if not omit_basic_constraints:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=ca, path_length=path_len), critical=True
        )
    if key_usage is not None:
        builder = builder.add_extension(key_usage, critical=True)
    if eku is not None:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(eku), critical=False
        )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(n) for n in sans]
            ), critical=True
        )
    for oid in critical_unknown:
        builder = builder.add_extension(
            UnrecognizedExtension(x509.ObjectIdentifier(oid),
                                  b"\x04\x01\x00"),
            critical=True,
        )
    return builder.sign(issuer_key, hashes.SHA256()), subject_key


def _root(cn, **kw):
    key = _key()
    cert, _ = _cert(cn, cn, key, subject_key=key, ca=True, **kw)
    return cert, key


def pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def fp(cert) -> str:
    return hashlib.sha256(
        cert.public_bytes(serialization.Encoding.DER)
    ).hexdigest()


def _good_server_leaf(issuer_cn, issuer_key, *, eku=(SERVER_AUTH,),
                      key_usage=None, **kw):
    return _cert(
        "svc.example", issuer_cn, issuer_key, ca=False,
        key_usage=key_usage or _ku(digital_signature=True,
                                  key_encipherment=True),
        eku=list(eku), sans=("svc.example",), **kw,
    )


def _good_client_leaf(issuer_cn, issuer_key, *, eku=(CLIENT_AUTH,), **kw):
    return _cert(
        "gw.example", issuer_cn, issuer_key, ca=False,
        key_usage=_ku(digital_signature=True, key_agreement=True),
        eku=list(eku), sans=("gw.example",), **kw,
    )


def _review(bundle, roots, endpoints, *, check_time=CHECK, skew=0):
    return client.post("/deployments/policy-review", json={
        "pem_certificates": [pem(c) for c in bundle],
        "trust_roots": [fp(r) for r in roots],
        "check_time": check_time.isoformat(),
        "max_skew_seconds": skew,
        "endpoints": endpoints,
    })


def _ep(endpoint_id, current_leaf, target_leaf, *, role="server",
        required_eku=None):
    return {
        "endpoint_id": endpoint_id,
        "current_leaf_fingerprint": fp(current_leaf),
        "target_leaf_fingerprint": fp(target_leaf),
        "role": role,
        "required_eku": required_eku or [],
    }


def _good_pki():
    """root -> intermediate -> server/client leaves, all policy-compliant."""
    root, root_key = _root("Root CA")
    inter, inter_key = _cert("Inter CA", "Root CA", root_key, ca=True)
    s_leaf, _ = _good_server_leaf("Inter CA", inter_key)
    c_leaf, _ = _good_client_leaf("Inter CA", inter_key)
    return root, root_key, inter, inter_key, s_leaf, c_leaf


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestHappyPath:
    def test_eligible_server_endpoint(self):
        root, rk, inter, ik, s_leaf, _ = _good_pki()
        r = _review([root, inter, s_leaf], [root],
                    [_ep("svc.example", s_leaf, s_leaf)])
        assert r.status_code == 200, r.text
        res = r.json()["results"][0]
        assert res["eligible"] is True
        assert res["reason"] == "ok"
        assert res["violating_chain"] is None
        assert res["role"] == "server"
        assert res["required_eku"] == ["1.3.6.1.5.5.7.3.1"]
        for chain in (res["current_chain"], res["target_chain"]):
            assert chain["eligible"] is True
            assert chain["reason"] == "ok"
            assert chain["chain"] == [fp(s_leaf), fp(inter), fp(root)]
            assert chain["violations"] == []

    def test_eligible_client_endpoint(self):
        root, rk, inter, ik, _, c_leaf = _good_pki()
        r = _review([root, inter, c_leaf], [root],
                    [_ep("gw.example", c_leaf, c_leaf, role="client")])
        assert r.status_code == 200
        res = r.json()["results"][0]
        assert res["eligible"] is True
        assert res["required_eku"] == ["1.3.6.1.5.5.7.3.2"]

    def test_two_level_intermediate_path(self):
        root, root_key = _root("Root CA")
        i1, i1_key = _cert("Inter 1", "Root CA", root_key, ca=True,
                           path_len=1)
        i2, i2_key = _cert("Inter 2", "Inter 1", i1_key, ca=True)
        leaf, _ = _good_server_leaf("Inter 2", i2_key)
        r = _review([root, i1, i2, leaf], [root],
                    [_ep("svc.example", leaf, leaf)])
        assert r.status_code == 200
        assert r.json()["results"][0]["eligible"] is True

    def test_results_sorted_by_endpoint_id(self):
        root, rk, inter, ik, s_leaf, _ = _good_pki()
        eps = [
            _ep("z.example", s_leaf, s_leaf),
            _ep("a.example", s_leaf, s_leaf),
            _ep("m.example", s_leaf, s_leaf),
        ]
        r = _review([root, inter, s_leaf], [root], eps)
        assert [x["endpoint_id"] for x in r.json()["results"]] == [
            "a.example", "m.example", "z.example"]

    def test_any_extended_key_usage_satisfies_required(self):
        root, rk, inter, ik, s_leaf, _ = _good_pki()
        leaf, _ = _good_server_leaf("Inter CA", ik, eku=(ANY_EKU,))
        r = _review([root, inter, leaf], [root],
                    [_ep("svc.example", leaf, leaf,
                         required_eku=["1.2.3.4.5.6.7"])])
        assert r.status_code == 200
        assert r.json()["results"][0]["eligible"] is True

    def test_eku_alias_normalization(self):
        root, rk, inter, ik, s_leaf, _ = _good_pki()
        r = _review([root, inter, s_leaf], [root],
                    [_ep("svc.example", s_leaf, s_leaf,
                         required_eku=["serverAuth"])])
        assert r.status_code == 200
        assert r.json()["results"][0]["eligible"] is True

    def test_absent_leaf_key_usage_is_unrestricted(self):
        root, rk, inter, ik, _, _ = _good_pki()
        leaf, _ = _cert("svc.example", "Inter CA", ik, ca=False,
                        key_usage=None, eku=[SERVER_AUTH],
                        sans=("svc.example",))
        r = _review([root, inter, leaf], [root],
                    [_ep("svc.example", leaf, leaf)])
        assert r.status_code == 200
        res = r.json()["results"][0]
        assert res["eligible"] is True
        v = res["current_chain"]
        assert v["violations"] == []


# ---------------------------------------------------------------------------
# Validity at check_time
# ---------------------------------------------------------------------------


class TestValidity:
    def test_expired_current_leaf_blocks_endpoint(self):
        root, rk, inter, ik, s_leaf, _ = _good_pki()
        expired, _ = _good_server_leaf(
            "Inter CA", ik,
            not_before=CHECK - timedelta(days=2000),
            not_after=CHECK - timedelta(days=1))
        r = _review([root, inter, s_leaf, expired], [root],
                    [_ep("svc.example", expired, s_leaf)])
        res = r.json()["results"][0]
        assert r.status_code == 200
        assert res["eligible"] is False
        assert res["violating_chain"] == "current"
        assert res["reason"] == "certificate_expired"
        v = res["current_chain"]["violations"]
        assert len(v) == 1
        assert v[0]["position"] == 0
        assert v[0]["reason"] == "certificate_expired"

    def test_not_yet_valid_target_leaf_blocks_endpoint(self):
        root, rk, inter, ik, s_leaf, _ = _good_pki()
        future, _ = _good_server_leaf(
            "Inter CA", ik,
            not_before=CHECK + timedelta(days=2),
            not_after=CHECK + timedelta(days=3000))
        r = _review([root, inter, s_leaf, future], [root],
                    [_ep("svc.example", s_leaf, future)])
        res = r.json()["results"][0]
        assert res["eligible"] is False
        assert res["violating_chain"] == "target"
        assert res["reason"] == "certificate_not_yet_valid"
        assert res["current_chain"]["eligible"] is True
        assert res["target_chain"]["eligible"] is False

    def test_expired_intermediate_reported_at_its_position(self):
        root, root_key = _root("Root CA")
        ik = _key()
        inter, _ = _cert(
            "Inter CA", "Root CA", root_key, subject_key=ik, ca=True,
            not_before=CHECK - timedelta(days=4000),
            not_after=CHECK - timedelta(days=10))
        leaf, _ = _good_server_leaf("Inter CA", ik)
        r = _review([root, inter, leaf], [root],
                    [_ep("svc.example", leaf, leaf)])
        res = r.json()["results"][0]
        assert res["eligible"] is False
        v = res["current_chain"]["violations"]
        assert v[0]["position"] == 1
        assert v[0]["reason"] == "certificate_expired"

    def test_expired_trust_anchor_blocks(self):
        # The anchor itself is checked at check_time (its own validity is a
        # deployment precondition).
        rk = _key()
        root, _ = _cert("Root CA", "Root CA", rk, subject_key=rk, ca=True,
                        not_before=CHECK - timedelta(days=6000),
                        not_after=CHECK - timedelta(days=30))
        inter, ik = _cert("Inter CA", "Root CA", rk, ca=True)
        leaf, _ = _good_server_leaf("Inter CA", ik)
        r = _review([root, inter, leaf], [root],
                    [_ep("svc.example", leaf, leaf)])
        res = r.json()["results"][0]
        assert res["eligible"] is False
        positions = {(v["position"], v["reason"])
                     for v in res["current_chain"]["violations"]}
        assert (2, "certificate_expired") in positions

    def test_skew_widens_validity_window(self):
        root, rk, inter, ik, s_leaf, _ = _good_pki()
        expired, _ = _good_server_leaf(
            "Inter CA", ik,
            not_before=CHECK - timedelta(days=2000),
            not_after=CHECK - timedelta(seconds=10))
        # 10s outside the window: a 5s skew still rejects, a 60s skew admits.
        r_tight = _review([root, inter, expired], [root],
                          [_ep("svc.example", expired, expired)], skew=5)
        assert r_tight.json()["results"][0]["reason"] == "certificate_expired"
        r_wide = _review([root, inter, expired], [root],
                         [_ep("svc.example", expired, expired)], skew=60)
        assert r_wide.json()["results"][0]["eligible"] is True


# ---------------------------------------------------------------------------
# BasicConstraints / path length
# ---------------------------------------------------------------------------


class TestBasicConstraints:
    def test_leaf_ca_true_is_leaf_is_ca(self):
        root, rk, inter, ik, _, _ = _good_pki()
        bad_leaf, _ = _cert("svc.example", "Inter CA", ik, ca=True,
                            eku=[SERVER_AUTH], sans=("svc.example",))
        r = _review([root, inter, bad_leaf], [root],
                    [_ep("svc.example", bad_leaf, bad_leaf)])
        res = r.json()["results"][0]
        assert res["eligible"] is False
        assert res["reason"] == "leaf_is_ca"
        v = res["current_chain"]["violations"][0]
        assert v["position"] == 0 and v["reason"] == "leaf_is_ca"
        assert v["is_ca"] is True

    def test_intermediate_ca_false_is_not_a_ca(self):
        root, root_key = _root("Root CA")
        ik = _key()
        inter, _ = _cert("Inter CA", "Root CA", root_key, subject_key=ik,
                         ca=False)
        leaf, _ = _good_server_leaf("Inter CA", ik)
        r = _review([root, inter, leaf], [root],
                    [_ep("svc.example", leaf, leaf)])
        res = r.json()["results"][0]
        assert res["reason"] == "not_a_ca"
        v = res["current_chain"]["violations"]
        assert v[0]["position"] == 1 and v[0]["reason"] == "not_a_ca"

    def test_intermediate_without_basic_constraints_missing(self):
        root, root_key = _root("Root CA")
        ik = _key()
        inter, _ = _cert("Inter CA", "Root CA", root_key, subject_key=ik,
                         omit_basic_constraints=True)
        leaf, _ = _good_server_leaf("Inter CA", ik)
        r = _review([root, inter, leaf], [root],
                    [_ep("svc.example", leaf, leaf)])
        res = r.json()["results"][0]
        assert res["reason"] == "basic_constraints_missing"
        v = res["current_chain"]["violations"][0]
        assert v["position"] == 1 and v["is_ca"] is None

    def test_root_path_len_zero_rejects_one_intermediate(self):
        rk = _key()
        root, _ = _cert("Root CA", "Root CA", rk, subject_key=rk, ca=True,
                        path_len=0)
        inter, ik = _cert("Inter CA", "Root CA", rk, ca=True)
        leaf, _ = _good_server_leaf("Inter CA", ik)
        r = _review([root, inter, leaf], [root],
                    [_ep("svc.example", leaf, leaf)])
        res = r.json()["results"][0]
        assert res["reason"] == "path_len_constraint_violated"
        v = res["current_chain"]["violations"][0]
        assert v["position"] == 2 and v["path_len"] == 0

    def test_intermediate_path_len_zero_rejects_second_intermediate(self):
        root, root_key = _root("Root CA")
        i1, i1_key = _cert("Inter 1", "Root CA", root_key, ca=True,
                           path_len=0)
        i2, i2_key = _cert("Inter 2", "Inter 1", i1_key, ca=True)
        leaf, _ = _good_server_leaf("Inter 2", i2_key)
        r = _review([root, i1, i2, leaf], [root],
                    [_ep("svc.example", leaf, leaf)])
        res = r.json()["results"][0]
        # chain is [leaf, i2, i1, root]; i1 at position 2 has pathLen=0 but
        # one non-self-issued intermediate (i2) sits below it.
        v = res["current_chain"]["violations"]
        assert any(x["position"] == 2
                   and x["reason"] == "path_len_constraint_violated"
                   and x["path_len"] == 0 for x in v)

    def test_path_len_exactly_fitting_chain_is_ok(self):
        root, root_key = _root("Root CA")
        # root pathLen=1 allows exactly one non-self-issued intermediate.
        root2, _ = _cert("Root CA", "Root CA", root_key,
                         subject_key=root_key, ca=True, path_len=1)
        inter, ik = _cert("Inter CA", "Root CA", root_key, ca=True,
                          path_len=0)
        leaf, _ = _good_server_leaf("Inter CA", ik)
        r = _review([root2, inter, leaf], [root2],
                    [_ep("svc.example", leaf, leaf)])
        assert r.json()["results"][0]["eligible"] is True

    def test_self_issued_intermediate_does_not_consume_path_len(self):
        # root(pathLen=0) -> self-issued bridge (subject == issuer DN) -> leaf:
        # the bridge does not count against pathLen (RFC 5280 §4.2.1.9).
        rk = _key()
        root, _ = _cert("Root CA", "Root CA", rk, subject_key=rk, ca=True,
                        path_len=0)
        bk = _key()
        bridge, _ = _cert("Root CA", "Root CA", rk, subject_key=bk, ca=True)
        leaf, _ = _good_server_leaf("Root CA", bk)
        r = _review([root, bridge, leaf], [root],
                    [_ep("svc.example", leaf, leaf)])
        assert r.json()["results"][0]["eligible"] is True

    def test_ca_key_usage_without_key_cert_sign_rejected(self):
        root, root_key = _root("Root CA")
        ik = _key()
        inter, _ = _cert(
            "Inter CA", "Root CA", root_key, subject_key=ik, ca=True,
            key_usage=_ku(crl_sign=True))  # CA but no keyCertSign
        leaf, _ = _good_server_leaf("Inter CA", ik)
        r = _review([root, inter, leaf], [root],
                    [_ep("svc.example", leaf, leaf)])
        res = r.json()["results"][0]
        assert res["reason"] == "ca_missing_key_cert_sign"
        v = res["current_chain"]["violations"][0]
        assert v["position"] == 1 and v["key_usage"] == ["crl_sign"]

    def test_ca_without_key_usage_extension_is_accepted(self):
        # KeyUsage absent -> no keyCertSign requirement to enforce.
        root, root_key = _root("Root CA")
        inter, ik = _cert("Inter CA", "Root CA", root_key, ca=True,
                          key_usage=None)
        leaf, _ = _good_server_leaf("Inter CA", ik)
        r = _review([root, inter, leaf], [root],
                    [_ep("svc.example", leaf, leaf)])
        assert r.json()["results"][0]["eligible"] is True


# ---------------------------------------------------------------------------
# Leaf KeyUsage / EKU
# ---------------------------------------------------------------------------


class TestLeafPurpose:
    def test_server_leaf_keyusage_neither_ds_nor_ke_rejected(self):
        root, rk, inter, ik, _, _ = _good_pki()
        leaf, _ = _cert(
            "svc.example", "Inter CA", ik, ca=False,
            key_usage=_ku(data_encipherment=True), eku=[SERVER_AUTH],
            sans=("svc.example",))
        r = _review([root, inter, leaf], [root],
                    [_ep("svc.example", leaf, leaf)])
        res = r.json()["results"][0]
        assert res["reason"] == "leaf_key_usage_invalid"
        v = res["current_chain"]["violations"][0]
        assert v["position"] == 0

    def test_server_leaf_key_agreement_only_rejected(self):
        root, rk, inter, ik, _, _ = _good_pki()
        leaf, _ = _cert(
            "svc.example", "Inter CA", ik, ca=False,
            key_usage=_ku(key_agreement=True), eku=[SERVER_AUTH],
            sans=("svc.example",))
        r = _review([root, inter, leaf], [root],
                    [_ep("svc.example", leaf, leaf)])
        assert r.json()["results"][0]["reason"] == \
            "leaf_key_usage_invalid"

    def test_client_leaf_requires_ds_or_key_agreement(self):
        root, rk, inter, ik, _, _ = _good_pki()
        leaf, _ = _cert(
            "gw.example", "Inter CA", ik, ca=False,
            key_usage=_ku(key_encipherment=True), eku=[CLIENT_AUTH],
            sans=("gw.example",))
        r = _review([root, inter, leaf], [root],
                    [_ep("gw.example", leaf, leaf, role="client")])
        assert r.json()["results"][0]["reason"] == \
            "leaf_key_usage_invalid"

    def test_client_leaf_key_agreement_accepted(self):
        root, rk, inter, ik, _, _ = _good_pki()
        leaf, _ = _cert(
            "gw.example", "Inter CA", ik, ca=False,
            key_usage=_ku(key_agreement=True), eku=[CLIENT_AUTH],
            sans=("gw.example",))
        r = _review([root, inter, leaf], [root],
                    [_ep("gw.example", leaf, leaf, role="client")])
        assert r.json()["results"][0]["eligible"] is True

    def test_wrong_role_eku_rejected(self):
        root, rk, inter, ik, _, _ = _good_pki()
        # server endpoint, leaf only certifies clientAuth.
        leaf, _ = _cert(
            "svc.example", "Inter CA", ik, ca=False,
            key_usage=_ku(digital_signature=True, key_encipherment=True),
            eku=[CLIENT_AUTH], sans=("svc.example",))
        r = _review([root, inter, leaf], [root],
                    [_ep("svc.example", leaf, leaf, role="server")])
        res = r.json()["results"][0]
        assert res["eligible"] is False
        assert res["reason"] == "eku_missing"
        v = res["current_chain"]["violations"][0]
        assert v["required_eku"] == ["1.3.6.1.5.5.7.3.1"]
        assert v["eku"] == ["1.3.6.1.5.5.7.3.2"]

    def test_caller_required_eku_missing(self):
        root, rk, inter, ik, s_leaf, _ = _good_pki()
        r = _review([root, inter, s_leaf], [root],
                    [_ep("svc.example", s_leaf, s_leaf,
                         required_eku=["1.3.6.1.5.5.7.3.4"])])
        res = r.json()["results"][0]
        assert res["eligible"] is False
        assert res["reason"] == "eku_missing"
        v = res["current_chain"]["violations"][0]
        assert v["required_eku"] == [
            "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.4"]

    def test_absent_eku_extension_fails_purpose(self):
        root, rk, inter, ik, _, _ = _good_pki()
        leaf, _ = _cert(
            "svc.example", "Inter CA", ik, ca=False,
            key_usage=_ku(digital_signature=True, key_encipherment=True),
            eku=None, sans=("svc.example",))
        r = _review([root, inter, leaf], [root],
                    [_ep("svc.example", leaf, leaf)])
        res = r.json()["results"][0]
        assert res["reason"] == "eku_missing"
        assert res["current_chain"]["violations"][0]["eku"] is None


# ---------------------------------------------------------------------------
# Unknown critical extensions
# ---------------------------------------------------------------------------


class TestUnknownCriticalExtensions:
    def test_unknown_critical_on_leaf_rejected(self):
        root, rk, inter, ik, _, _ = _good_pki()
        leaf, _ = _good_server_leaf(
            "Inter CA", ik, critical_unknown=("1.2.3.4.5.6.7",))
        r = _review([root, inter, leaf], [root],
                    [_ep("svc.example", leaf, leaf)])
        res = r.json()["results"][0]
        assert res["reason"] == "unknown_critical_extension"
        v = res["current_chain"]["violations"][0]
        assert v["position"] == 0
        assert v["extension_oid"] == "1.2.3.4.5.6.7"

    def test_unknown_critical_on_intermediate_rejected(self):
        root, root_key = _root("Root CA")
        inter, ik = _cert(
            "Inter CA", "Root CA", root_key, ca=True,
            critical_unknown=("1.2.3.4.5.6.8",))
        leaf, _ = _good_server_leaf("Inter CA", ik)
        r = _review([root, inter, leaf], [root],
                    [_ep("svc.example", leaf, leaf)])
        res = r.json()["results"][0]
        assert res["reason"] == "unknown_critical_extension"
        v = res["current_chain"]["violations"][0]
        assert v["position"] == 1 and v["extension_oid"] == "1.2.3.4.5.6.8"

    def test_unknown_critical_on_trust_anchor_exempt(self):
        # Anchor extensions are not chain constraints per RFC 5280 path
        # processing; a critical unknown extension on the root must not
        # disqualify an otherwise valid chain.
        rk = _key()
        root, _ = _cert("Root CA", "Root CA", rk, subject_key=rk, ca=True,
                        critical_unknown=("1.2.3.4.5.6.99",))
        inter, ik = _cert("Inter CA", "Root CA", rk, ca=True)
        leaf, _ = _good_server_leaf("Inter CA", ik)
        r = _review([root, inter, leaf], [root],
                    [_ep("svc.example", leaf, leaf)])
        assert r.status_code == 200
        assert r.json()["results"][0]["eligible"] is True

    def test_non_critical_unknown_extension_ignored(self):
        # Build via raw extension add with critical=False.
        root, root_key = _root("Root CA")
        ik = _key()
        builder = (
            x509.CertificateBuilder()
            .subject_name(_dn("Inter CA"))
            .issuer_name(_dn("Root CA"))
            .public_key(ik.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(CHECK - timedelta(days=365))
            .not_valid_after(CHECK + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                           critical=True)
            .add_extension(
                UnrecognizedExtension(x509.ObjectIdentifier("1.2.3.4.5.6.9"),
                                      b"\x04\x01\x00"),
                critical=False)
        )
        inter = builder.sign(root_key, hashes.SHA256())
        leaf, _ = _good_server_leaf("Inter CA", ik)
        r = _review([root, inter, leaf], [root],
                    [_ep("svc.example", leaf, leaf)])
        assert r.json()["results"][0]["eligible"] is True

    def test_known_critical_san_recognized(self):
        # A critical subjectAltName must be recognized, not rejected.
        root, root_key = _root("Root CA")
        inter, ik = _cert("Inter CA", "Root CA", root_key, ca=True)
        leaf, _ = _cert(
            "svc.example", "Inter CA", ik, ca=False,
            key_usage=_ku(digital_signature=True, key_encipherment=True),
            eku=[SERVER_AUTH], sans=("svc.example",))
        # sans extension is added critical=True in the factory.
        raw = dict(_raw_extensions(leaf))
        assert raw.get("2.5.29.17") is True
        r = _review([root, inter, leaf], [root],
                    [_ep("svc.example", leaf, leaf)])
        assert r.json()["results"][0]["eligible"] is True


# ---------------------------------------------------------------------------
# Both chains must pass + first-conflict stability
# ---------------------------------------------------------------------------


class TestBothChainsAndStability:
    def test_current_and_target_both_listed_with_shared_certificates(self):
        root, rk, inter, ik, s_leaf, _ = _good_pki()
        target, _ = _good_server_leaf("Inter CA", ik)
        bad_current, _ = _cert(
            "svc.example", "Inter CA", ik, ca=True,
            key_usage=_ku(digital_signature=True, key_encipherment=True,
                          key_cert_sign=True),
            eku=[SERVER_AUTH], sans=("svc.example",))
        r = _review([root, inter, s_leaf, target, bad_current], [root],
                    [_ep("svc.example", bad_current, target)])
        res = r.json()["results"][0]
        assert res["eligible"] is False
        assert res["violating_chain"] == "current"
        assert res["current_chain"]["eligible"] is False
        assert res["target_chain"]["eligible"] is True
        # participating certificates are listed on both chains
        assert res["current_chain"]["chain"] == [
            fp(bad_current), fp(inter), fp(root)]
        assert res["target_chain"]["chain"] == [
            fp(target), fp(inter), fp(root)]

    def test_current_precedence_over_target_for_first_reason(self):
        root, rk, inter, ik, _, _ = _good_pki()
        bad_current, _ = _good_server_leaf(
            "Inter CA", ik, eku=(CLIENT_AUTH,))  # eku_missing
        # target has a CA leaf (would be leaf_is_ca, lower precedence number?
        # leaf_is_ca=6 > eku_missing=8, so on its own it'd win, but current
        # chain is always inspected first).
        bad_target, _ = _cert(
            "svc2.example", "Inter CA", ik, ca=True,
            key_usage=_ku(digital_signature=True, key_encipherment=True),
            eku=[SERVER_AUTH], sans=("svc2.example",))
        r = _review([root, inter, bad_current, bad_target], [root],
                    [_ep("svc.example", bad_current, bad_target)])
        res = r.json()["results"][0]
        assert res["violating_chain"] == "current"
        assert res["reason"] == "eku_missing"

    def test_position_order_picks_leaf_before_intermediate(self):
        # Leaf expired (position 0) and intermediate not a CA (position 1):
        # position 0 wins regardless of reason precedence.
        root, root_key = _root("Root CA")
        ik = _key()
        inter, _ = _cert("Inter CA", "Root CA", root_key, subject_key=ik,
                         ca=False)
        leaf, _ = _good_server_leaf(
            "Inter CA", ik,
            not_before=CHECK + timedelta(days=5),
            not_after=CHECK + timedelta(days=3000))
        r = _review([root, inter, leaf], [root],
                    [_ep("svc.example", leaf, leaf)])
        res = r.json()["results"][0]
        assert res["reason"] == "certificate_not_yet_valid"
        assert res["current_chain"]["violations"][0]["position"] == 0
        # all conflicts are still enumerated
        reasons = {(v["position"], v["reason"])
                   for v in res["current_chain"]["violations"]}
        assert (1, "not_a_ca") in reasons

    def test_multiple_endpoints_independent(self):
        root, rk, inter, ik, s_leaf, c_leaf = _good_pki()
        bad, _ = _good_server_leaf("Inter CA", ik, eku=(CLIENT_AUTH,))
        eps = [
            _ep("ok.example", s_leaf, s_leaf),
            _ep("bad.example", bad, bad),
        ]
        r = _review([root, inter, s_leaf, bad], [root], eps)
        by_id = {x["endpoint_id"]: x for x in r.json()["results"]}
        assert by_id["ok.example"]["eligible"] is True
        assert by_id["bad.example"]["eligible"] is False
        assert by_id["bad.example"]["reason"] == "eku_missing"


# ---------------------------------------------------------------------------
# 422 contract (shared normalization diagnostics)
# ---------------------------------------------------------------------------


class Test422:
    def test_no_trust_path(self):
        # Declared root missing from the bundle -> unknown_fingerprint 422.
        root, rk, inter, ik, s_leaf, _ = _good_pki()
        r = _review([inter, s_leaf], [root],
                    [_ep("svc.example", s_leaf, s_leaf)])
        assert r.status_code == 422
        detail = r.json()["detail"]
        assert detail["error"] == "unknown_fingerprint"

    def test_chain_not_resolvable_to_root(self):
        # leaf + inter present but root not in trust list and bundle lacks
        # a verified path to any declared root:
        other_root, _ = _root("Other Root CA")
        root, rk, inter, ik, s_leaf, _ = _good_pki()
        r = _review([other_root, inter, s_leaf], [other_root],
                    [_ep("svc.example", s_leaf, s_leaf)])
        assert r.status_code == 422
        detail = r.json()["detail"]
        assert detail["error"] == "no_trust_path"
        issue = detail["chain_issues"][0]
        assert issue["leaf"] == fp(s_leaf)
        assert issue["candidate_issuers"] == [fp(inter)]

    def test_ambiguous_chain_422(self):
        root_a_key, root_b_key = _key(), _key()
        root_a, _ = _cert("Root A", "Root A", root_a_key,
                          subject_key=root_a_key, ca=True)
        root_b, _ = _cert("Root B", "Root B", root_b_key,
                          subject_key=root_b_key, ca=True)
        inter_key = _key()
        inter_a, _ = _cert("Shared Inter", "Root A", root_a_key,
                           subject_key=inter_key, ca=True)
        inter_b, _ = _cert("Shared Inter", "Root B", root_b_key,
                           subject_key=inter_key, ca=True)
        leaf, _ = _good_server_leaf("Shared Inter", inter_key)
        r = _review([leaf, inter_a, inter_b, root_a, root_b],
                    [root_a, root_b],
                    [_ep("svc.example", leaf, leaf)])
        assert r.status_code == 422
        detail = r.json()["detail"]
        assert detail["error"] == "ambiguous_chain"
        paths = {tuple(p) for p in detail["chain_issues"][0]["candidate_paths"]}
        assert (fp(leaf), fp(inter_a), fp(root_a)) in paths
        assert (fp(leaf), fp(inter_b), fp(root_b)) in paths

    def test_invalid_fingerprint(self):
        root, rk, inter, ik, s_leaf, _ = _good_pki()
        ep = _ep("svc.example", s_leaf, s_leaf)
        ep["target_leaf_fingerprint"] = "ZZ" + "0" * 62
        r = _review([root, inter, s_leaf], [root], [ep])
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_fingerprint"

    def test_invalid_pem(self):
        root, rk, inter, ik, s_leaf, _ = _good_pki()
        r = client.post("/deployments/policy-review", json={
            "pem_certificates": ["not a pem"],
            "trust_roots": [fp(root)],
            "check_time": CHECK.isoformat(),
            "endpoints": [_ep("svc.example", s_leaf, s_leaf)],
        })
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_pem"

    def test_trust_root_not_self_signed(self):
        root, root_key = _root("Root CA")
        fake_root, _ = _cert("Fake Root", "Root CA", root_key, ca=True)
        inter, ik = _cert("Inter CA", "Root CA", root_key, ca=True)
        leaf, _ = _good_server_leaf("Inter CA", ik)
        r = _review([root, fake_root, inter, leaf], [fake_root],
                    [_ep("svc.example", leaf, leaf)])
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "trust_root_not_self_signed"

    def test_invalid_eku_422(self):
        root, rk, inter, ik, s_leaf, _ = _good_pki()
        r = _review([root, inter, s_leaf], [root],
                    [_ep("svc.example", s_leaf, s_leaf,
                         required_eku=["nonsense"])])
        assert r.status_code == 422
        detail = r.json()["detail"]
        assert detail["error"] == "invalid_eku"
        issue = detail["policy_issues"][0]
        assert issue["endpoint_id"] == "svc.example"
        assert issue["index"] == 0
        assert issue["eku"] == "nonsense"

    def test_duplicate_endpoint_id_422(self):
        root, rk, inter, ik, s_leaf, _ = _good_pki()
        r = _review([root, inter, s_leaf], [root],
                    [_ep("svc.example", s_leaf, s_leaf),
                     _ep("svc.example", s_leaf, s_leaf)])
        assert r.status_code == 422

    def test_skew_over_cap_422(self):
        root, rk, inter, ik, s_leaf, _ = _good_pki()
        r = _review([root, inter, s_leaf], [root],
                    [_ep("svc.example", s_leaf, s_leaf)], skew=301)
        assert r.status_code == 422


# ---------------------------------------------------------------------------
# DER walking helpers
# ---------------------------------------------------------------------------


def _encode_oid_arcs(arcs: list[int]) -> bytes:
    """Minimal DER encoding of OID arc values into the content octets."""
    first = 40 * arcs[0] + arcs[1]
    out = bytes([first])
    for arc in arcs[2:]:
        stack = [arc & 0x7F]
        arc >>= 7
        while arc:
            stack.append(0x80 | (arc & 0x7F))
            arc >>= 7
        out += bytes(reversed(stack))
    return out


def test_decode_oid_arcs():
    assert _decode_oid(_encode_oid_arcs([1, 2, 840, 113549, 1, 1, 11])) \
        == "1.2.840.113549.1.1.11"
    # second arc >= 40 under first arc 2
    assert _decode_oid(_encode_oid_arcs([2, 100, 3])) == "2.100.3"
    # large arc forces multi-byte base-128 continuation
    assert _decode_oid(_encode_oid_arcs([1, 2, 0x4800])) == "1.2.18432"
