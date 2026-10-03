"""Certificate purpose and path-strategy review for rotation chains.

Given the same unordered PEM bag used by ``/scenarios/normalize``, declared
trust roots and, per endpoint, the fingerprints of its *current* and *target*
leaves plus the endpoint's TLS role (``server``/``client``) and the extended
key usages the leaf must carry, this module reconstructs **both** chains with
the normalizer's exact signature-verified, zero/unique/ambiguous path verdict
and then audits every participating certificate of each chain at one fixed
validation instant ``check_time``.

For each chain the rules are:

* **Validity at check_time** for *every* certificate, trust anchor included:
  ``check_time`` must lie in ``[notBefore − skew, notAfter + skew]``; an
  unfresh certificate is ``certificate_not_yet_valid`` / ``certificate_expired``.
* **BasicConstraints at every level.** A leaf must not assert ``cA:TRUE``
  (``leaf_is_ca``); an absent basicConstraints on a leaf means "not a CA" per
  RFC 5280 and is accepted. Every intermediate must carry basicConstraints
  with ``cA:TRUE`` — a missing extension is ``basic_constraints_missing`` and
  a present ``cA:FALSE`` is ``not_a_ca``. The trust anchor must be a CA as
  well (it is declared as a root of trust for these chains).
* **pathLenConstraint at every CA level.** A CA's ``pathLenConstraint`` must
  be at least the number of non-self-issued intermediate CAs *below* it in
  this chain (self-issued certificates, ``subject == issuer``, do not count,
  matching RFC 5280 §4.2.1.9); otherwise ``path_len_constraint_violated``.
* **CA KeyUsage.** When an issuer carries a KeyUsage extension it must assert
  ``keyCertSign``; otherwise ``ca_missing_key_cert_sign``.
* **Leaf KeyUsage for the declared TLS role.** An absent KeyUsage imposes no
  restriction; a server leaf must assert ``digitalSignature`` or
  ``keyEncipherment``, a client leaf ``digitalSignature`` or
  ``keyAgreement`` — otherwise ``leaf_key_usage_invalid``.
* **Leaf EKU.** The leaf's extKeyUsage must contain the EKU implied by the
  role (id-kp-serverAuth / id-kp-clientAuth) and every caller-required EKU;
  ``anyExtendedKeyUsage`` satisfies all of them. An absent EKU extension
  certifies no purpose, so it fails a purpose review with ``eku_missing``.
  EKUs on CA certificates are not requirements of this review.
* **Unknown critical extensions.** A critical extension the policy engine
  does not recognize on the leaf or any intermediate fails closed as
  ``unknown_critical_extension`` — a verifier cannot process what it cannot
  identify. The **trust anchor** is exempt: per RFC 5280 path processing the
  anchor's own extensions are not constraints on the validation.

An endpoint is eligible only when **both** its current and its target chain
are compliant ("当前链或目标链不合规时不得放行"); only an eligible endpoint's
target chain may be handed to ``/plans``. Results are stable: per endpoint
(by endpoint_id), the first conflicting rule is chosen in chain order
(current before target) then by (chain position, reason precedence), while
every conflict and every participating certificate fingerprint is listed for
the audit trail.
"""
from __future__ import annotations

import re
from datetime import timedelta
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .models import (
    EKU_ALIASES,
    EndpointPolicyResult,
    POLICY_REASON_ORDER,
    PolicyChainReview,
    PolicyEkuIssue,
    PolicyReviewEndpoint,
    PolicyReviewRequest,
    PolicyReviewResult,
    PolicyViolation,
)
from .normalize import (
    FINGERPRINT_RE,
    NormalizeChainIssue,
    NormalizeError,
    NormalizeFingerprintIssue,
    _build_issuer_edges,
    _dedupe_paths,
    _enumerate_paths,
    _find_trust_path,
    _has_second_trust_path,
    _load_pem_bundle,
    _validity_utc,
    _verify_signature,
)
from .precheck import _der_tlv

# Role -> EKU OID the TLS role requires at the leaf (RFC 5280 §4.2.1.12).
ROLE_EKU = {
    "server": "1.3.6.1.5.5.7.3.1",  # id-kp-serverAuth
    "client": "1.3.6.1.5.5.7.3.2",  # id-kp-clientAuth
}

# anyExtendedKeyUsage: a leaf carrying it asserts every purpose.
ANY_EKU = "2.5.29.37.0"

_OID_ARC_RE = re.compile(r"^[0-2](?:\.[0-9]+)+$")

# Critical-extension OIDs this policy engine understands. A critical extension
# outside this set on a leaf or intermediate fails closed; the set is built
# from the OIDs cryptography models, so a cryptography upgrade that learns a
# new extension widens recognition automatically.
_KNOWN_CRITICAL_OIDS: Optional[frozenset[str]] = None


def _build_known_critical_oids() -> frozenset[str]:
    """Dotted OIDs of every extension type the local cryptography models.

    These are exactly the extension kinds whose semantics the policy engine
    can reason about; a *critical* extension outside this set cannot be
    processed and therefore fails closed.
    """
    global _KNOWN_CRITICAL_OIDS
    if _KNOWN_CRITICAL_OIDS is not None:
        return _KNOWN_CRITICAL_OIDS

    oids: set[str] = set()
    for cls in (
        x509.SubjectAlternativeName,
        x509.IssuerAlternativeName,
        x509.BasicConstraints,
        x509.SubjectKeyIdentifier,
        x509.AuthorityKeyIdentifier,
        x509.NameConstraints,
        x509.CRLDistributionPoints,
        x509.CertificatePolicies,
        x509.PolicyConstraints,
        x509.ExtendedKeyUsage,
        x509.FreshestCRL,
        x509.InhibitAnyPolicy,
        x509.KeyUsage,
        x509.OCSPNoCheck,
        x509.TLSFeature,
        x509.SignedCertificateTimestamps,
        x509.PrecertPoison,
        x509.PrecertificateSignedCertificateTimestamps,
    ):
        oid = getattr(cls, "oid", None)
        if oid is not None:
            oids.add(oid.dotted_string)
    # Explicit safety net for the OIDs RFC 5280 and the CT/TLS ecosystem mark
    # critical on certificates, independent of cryptography's class surface.
    oids.update({
        "2.5.29.14",  # subjectKeyIdentifier
        "2.5.29.15",  # keyUsage
        "2.5.29.17",  # subjectAltName
        "2.5.29.18",  # issuerAltName
        "2.5.29.19",  # basicConstraints
        "2.5.29.30",  # nameConstraints
        "2.5.29.31",  # cRLDistributionPoints
        "2.5.29.32",  # certificatePolicies
        "2.5.29.35",  # authorityKeyIdentifier
        "2.5.29.36",  # policyConstraints
        "2.5.29.37",  # extKeyUsage
        "2.5.29.46",  # freshestCRL
        "2.5.29.54",  # inhibitAnyPolicy
        "1.3.6.1.4.1.11129.2.4.2",   # SCT list
        "1.3.6.1.5.5.7.1.1",        # authorityInfoAccess
        "1.3.6.1.5.5.7.1.11",       # subjectInfoAccess
        "1.3.6.1.5.5.7.1.24",       # TLS feature (status_request)
        "1.3.6.1.5.5.7.1.26",       # status_request_v2
        "1.3.6.1.5.5.7.48.1.5",     # id-pkix-ocsp-nocheck
        "1.3.6.1.4.1.11129.2.4.3",  # precert poison SCT
    })
    _KNOWN_CRITICAL_OIDS = frozenset(oids)
    return _KNOWN_CRITICAL_OIDS


# ---------------------------------------------------------------------------
# Raw DER walking: enumerate (oid, critical) straight from the certificate so
# an extension cryptography cannot decode is still visible (an extension it
# silently drops must not evade a fail-closed critical-extension check).
# ---------------------------------------------------------------------------


def _raw_extensions(
    cert: x509.Certificate,
) -> list[tuple[str, bool]]:
    """Return ``[(oid_dotted, critical), ...]`` in certificate DER order."""
    der = cert.public_bytes(serialization.Encoding.DER)
    out: list[tuple[str, bool]] = []
    try:
        _tag, hs, _cert_end, _c = _der_tlv(der, 0)
        _tag, p, tbs_end, _c = _der_tlv(der, hs)
        for _ in range(7):  # version, serial, sig, issuer, validity, subject, SPKI
            _tag, _cs, p, _c = _der_tlv(der, p)
        while p < tbs_end and der[p] in (0x81, 0x82):  # issuer/Subject UID
            _tag, _cs, p, _c = _der_tlv(der, p)
        if p >= tbs_end or der[p] != 0xA3:
            return out
        _tag, wp, _we, _c = _der_tlv(der, p)     # [3] EXPLICIT extensions
        _tag, sp, se, _c = _der_tlv(der, wp)     # SEQUENCE OF Extension
        while sp < se:
            _tag, ep, ee, _c = _der_tlv(der, sp)  # Extension SEQUENCE
            m = ep
            _tag, om, oe, _c = _der_tlv(der, m)  # OBJECT IDENTIFIER
            oid = _decode_oid(der[om:oe])
            m = oe
            critical = False
            if m < ee and der[m] == 0x01:         # BOOLEAN critical
                _tag, bs, be, _c = _der_tlv(der, m)
                critical = der[bs:be] != b"\x00"
                m = be
            # OCTET STRING extnValue follows; its bytes are irrelevant here.
            out.append((oid, critical))
            sp = ee
    except (IndexError, ValueError):
        return out
    return out


def _decode_oid(content: bytes) -> str:
    """Decode the content bytes of an OBJECT IDENTIFIER TLV to dotted form."""
    if not content:
        return ""
    first = content[0]
    if first < 40:
        arcs = ["0", str(first)]
    elif first < 80:
        arcs = ["1", str(first - 40)]
    else:
        arcs = ["2", str(first - 80)]
    value = 0
    for byte in content[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(str(value))
            value = 0
    return ".".join(arcs)


# ---------------------------------------------------------------------------
# Certificate property extraction
# ---------------------------------------------------------------------------


_KEY_USAGE_BITS = (
    ("digital_signature", "digital_signature"),
    ("content_commitment", "content_commitment"),
    ("key_encipherment", "key_encipherment"),
    ("data_encipherment", "data_encipherment"),
    ("key_agreement", "key_agreement"),
    ("key_cert_sign", "key_cert_sign"),
    ("crl_sign", "crl_sign"),
)


def _key_usage_names(cert: x509.Certificate) -> Optional[list[str]]:
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return None
    except (ValueError, TypeError):
        return None
    names = [name for name, prop in _KEY_USAGE_BITS if getattr(ku, prop, False)]
    # encipher_only / decipher_only only meaningful with key_agreement.
    if ku.key_agreement:
        if getattr(ku, "encipher_only", False):
            names.append("encipher_only")
        if getattr(ku, "decipher_only", False):
            names.append("decipher_only")
    return names


def _eku_oids(cert: x509.Certificate) -> Optional[list[str]]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    except x509.ExtensionNotFound:
        return None
    except (ValueError, TypeError):
        return None
    return sorted(o.dotted_string for o in ext.value)


def _basic_constraints(cert: x509.Certificate) -> tuple[Optional[bool], Optional[int]]:
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        return None, None
    except (ValueError, TypeError):
        return None, None
    return bc.ca, bc.path_length


# ---------------------------------------------------------------------------
# Per-chain evaluation
# ---------------------------------------------------------------------------


def _violation_sort_key(v: PolicyViolation) -> tuple:
    return (
        v.position,
        POLICY_REASON_ORDER[v.reason],
        v.certificate_fingerprint,
        v.extension_oid or "",
        tuple(v.required_eku or ()),
    )


def _make_violation(
    position: int,
    cert_fp: str,
    role: str,
    reason: str,
    message: str,
    cert: x509.Certificate,
    *,
    extension_oid: Optional[str] = None,
    required_eku: Optional[list[str]] = None,
) -> PolicyViolation:
    is_ca, path_len = _basic_constraints(cert)
    return PolicyViolation(
        position=position,
        certificate_fingerprint=cert_fp,
        role=role,  # type: ignore[arg-type]
        reason=reason,  # type: ignore[arg-type]
        message=message,
        not_valid_before=_validity_utc(cert, "not_valid_before"),
        not_valid_after=_validity_utc(cert, "not_valid_after"),
        is_ca=is_ca,
        path_len=path_len,
        key_usage=_key_usage_names(cert),
        eku=_eku_oids(cert),
        extension_oid=extension_oid,
        required_eku=required_eku,
    )


def _leaf_key_usage_ok(role: str, ku: x509.KeyUsage) -> bool:
    """Whether a leaf's KeyUsage permits the declared TLS role."""
    if role == "server":
        # RFC 5280/5246: the server's key is used in a signature
        # (digitalSignature) or in key transport (keyEncipherment).
        return bool(ku.digital_signature or ku.key_encipherment)
    # client: a signature-based key exchange (digitalSignature) or a key
    # agreement one (keyAgreement), as used for TLS client authentication.
    return bool(ku.digital_signature or ku.key_agreement)


def evaluate_chain(
    chain_role: str,
    chain: list[str],
    certs: dict[str, x509.Certificate],
    tls_role: str,
    required_ekus: list[str],
    check_time,
    skew: timedelta,
) -> PolicyChainReview:
    """Audit one reconstructed leaf-first chain."""
    violations: list[PolicyViolation] = []
    last = len(chain) - 1
    required = sorted(required_ekus)

    # Number of non-self-issued intermediate CAs below each CA position is
    # the count of certificates strictly between the leaf and the CA that are
    # not self-issued (subject != issuer DNs).
    def nonselfissued_below(pos: int) -> int:
        count = 0
        for j in range(1, pos):
            c = certs[chain[j]]
            if c.subject != c.issuer:
                count += 1
        return count

    for pos, cert_fp in enumerate(chain):
        cert = certs[cert_fp]
        is_leaf = pos == 0
        is_anchor = pos == last
        cert_role = (
            "leaf" if is_leaf else ("trust_root" if is_anchor else "intermediate")
        )

        def add(reason: str, message: str, **kw) -> None:
            violations.append(_make_violation(
                pos, cert_fp, cert_role, reason, message, cert, **kw
            ))

        # 1. Validity at check_time (every certificate, anchor included).
        not_before = _validity_utc(cert, "not_valid_before")
        not_after = _validity_utc(cert, "not_valid_after")
        if check_time < not_before - skew:
            add(
                "certificate_not_yet_valid",
                f"certificate is not valid before {not_before.isoformat()} "
                f"(check_time {check_time.isoformat()}, skew {int(skew.total_seconds())}s)",
            )
        elif check_time > not_after + skew:
            add(
                "certificate_expired",
                f"certificate expired at {not_after.isoformat()} "
                f"(check_time {check_time.isoformat()}, skew {int(skew.total_seconds())}s)",
            )

        ca_flag, path_len = _basic_constraints(cert)

        if is_leaf:
            # 2a. Leaf must not assert cA:TRUE.
            if ca_flag is True:
                add("leaf_is_ca",
                    "leaf certificate asserts basicConstraints cA=TRUE; a TLS "
                    "end-entity certificate must not be a CA")

            # KeyUsage (when present) must permit the role.
            ku_names = _key_usage_names(cert)
            if ku_names is not None:
                try:
                    ku = cert.extensions.get_extension_for_class(
                        x509.KeyUsage
                    ).value
                    if not _leaf_key_usage_ok(tls_role, ku):
                        need = (
                            "digitalSignature or keyEncipherment"
                            if tls_role == "server"
                            else "digitalSignature or keyAgreement"
                        )
                        add("leaf_key_usage_invalid",
                            f"leaf KeyUsage {ku_names} does not permit the "
                            f"{tls_role} TLS role (requires {need})")
                except (x509.ExtensionNotFound, ValueError, TypeError):
                    add("leaf_key_usage_invalid",
                        "leaf KeyUsage extension could not be decoded")

            # EKU must assert the role EKU and every caller-required EKU.
            ekus = _eku_oids(cert)
            if ekus is None or not (
                ANY_EKU in (ekus or []) or all(r in (ekus or []) for r in required)
            ):
                add("eku_missing",
                    f"leaf EKU {ekus} does not contain every required "
                    f"purpose {required} for TLS role '{tls_role}' "
                    "(absent EKU certifies no purpose)",
                    required_eku=required)

        else:
            # 2b. Intermediate / anchor must be a CA.
            if ca_flag is None:
                add("basic_constraints_missing",
                    f"{cert_role} certificate has no basicConstraints "
                    "extension; a CA certificate must assert cA=TRUE")
            elif ca_flag is False:
                add("not_a_ca",
                    f"{cert_role} certificate asserts basicConstraints "
                    "cA=FALSE; it cannot issue certificates")

            # 3. pathLenConstraint must cover the non-self-issued CAs below.
            if ca_flag is True and path_len is not None:
                below = nonselfissued_below(pos)
                if path_len < below:
                    add("path_len_constraint_violated",
                        f"CA at chain position {pos} sets "
                        f"pathLenConstraint={path_len} but {below} "
                        "non-self-issued intermediate CA(s) sit below it in "
                        "this chain")

            # 4. CA KeyUsage, when present, must include keyCertSign.
            ku_names = _key_usage_names(cert)
            if ku_names is not None and "key_cert_sign" not in ku_names:
                add("ca_missing_key_cert_sign",
                    f"{cert_role} KeyUsage {ku_names} lacks keyCertSign; a "
                    "CA that issues certificates must assert it")

        # 5. Unknown critical extensions. The trust anchor is exempt: per
        #    RFC 5280 path processing its own extensions do not constrain
        #    validation of the chain.
        if not is_anchor:
            known = _build_known_critical_oids()
            for oid, critical in _raw_extensions(cert):
                if critical and oid and oid not in known:
                    add("unknown_critical_extension",
                        f"certificate carries an unrecognized critical "
                        f"extension {oid}; it cannot be processed by this "
                        "policy engine and fails closed",
                        extension_oid=oid)

    violations.sort(key=_violation_sort_key)
    first = violations[0].reason if violations else "ok"
    return PolicyChainReview(
        chain_role=chain_role,  # type: ignore[arg-type]
        eligible=not violations,
        reason=first,  # type: ignore[arg-type]
        chain=list(chain),
        violations=violations,
    )


# ---------------------------------------------------------------------------
# Request-level validation
# ---------------------------------------------------------------------------


def _normalize_eku(endpoint: PolicyReviewEndpoint) -> tuple[list[str], list[PolicyEkuIssue]]:
    issues: list[PolicyEkuIssue] = []
    oids: set[str] = {ROLE_EKU[endpoint.role]}
    seen: set[str] = set()
    for idx, raw in enumerate(endpoint.required_eku):
        value = raw.strip()
        oid = EKU_ALIASES.get(value, value)
        if not _OID_ARC_RE.match(oid):
            issues.append(PolicyEkuIssue(
                endpoint_id=endpoint.endpoint_id, index=idx, eku=raw,
                message=(f"invalid EKU '{raw}': expected a dotted OID (e.g. "
                         "1.3.6.1.5.5.7.3.1) or one of "
                         f"{', '.join(sorted(EKU_ALIASES))})"),
            ))
            continue
        if oid not in seen:
            seen.add(oid)
            oids.add(oid)
    return sorted(oids), issues


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def policy_review(req: PolicyReviewRequest) -> PolicyReviewResult:
    # -- endpoint EKU validation --------------------------------------------
    eku_issues: list[PolicyEkuIssue] = []
    required_by_endpoint: dict[str, list[str]] = {}
    for e in req.endpoints:
        oids, issues = _normalize_eku(e)
        eku_issues += issues
        required_by_endpoint[e.endpoint_id] = oids

    # -- fingerprints --------------------------------------------------------
    fingerprint_issues: list[NormalizeFingerprintIssue] = []
    trust_roots: set[str] = set()
    for raw in req.trust_roots:
        fp = raw.strip().lower()
        if not FINGERPRINT_RE.match(fp):
            fingerprint_issues.append(NormalizeFingerprintIssue(
                fingerprint=raw, referred_by="trust_roots"))
        else:
            trust_roots.add(fp)

    leaves: list[tuple[str, str, str]] = []  # (endpoint_id, role, fp)
    for e in req.endpoints:
        for chain_role, raw in (
            ("current", e.current_leaf_fingerprint),
            ("target", e.target_leaf_fingerprint),
        ):
            fp = raw.strip().lower()
            if not FINGERPRINT_RE.match(fp):
                fingerprint_issues.append(NormalizeFingerprintIssue(
                    fingerprint=raw,
                    referred_by=(f"endpoints['{e.endpoint_id}']."
                                 f"{chain_role}_leaf_fingerprint")))
            leaves.append((e.endpoint_id, chain_role, fp))

    if eku_issues:
        raise NormalizeError(
            "invalid_eku",
            "one or more required EKUs are neither dotted OIDs nor known "
            "EKU aliases",
            fingerprint_issues=fingerprint_issues,
            policy_issues=eku_issues,
        )
    if fingerprint_issues:
        raise NormalizeError(
            "invalid_fingerprint",
            "one or more fingerprints are not 64-character hex SHA-256 values",
            fingerprint_issues=fingerprint_issues,
        )

    # -- PEM parsing ----------------------------------------------------------
    certs, pem_issues = _load_pem_bundle(req.pem_certificates)
    if pem_issues:
        raise NormalizeError(
            "invalid_pem",
            "one or more PEM list elements could not be parsed",
            pem_issues=pem_issues,
        )

    missing: list[NormalizeFingerprintIssue] = []
    for fp in sorted(trust_roots):
        if fp not in certs:
            missing.append(NormalizeFingerprintIssue(
                fingerprint=fp, referred_by="trust_roots"))
    for endpoint_id, chain_role, fp in leaves:
        if fp not in certs:
            missing.append(NormalizeFingerprintIssue(
                fingerprint=fp,
                referred_by=(f"endpoints['{endpoint_id}']."
                             f"{chain_role}_leaf_fingerprint")))
    if missing:
        raise NormalizeError(
            "unknown_fingerprint",
            "some fingerprints do not match any certificate in the PEM bundle",
            fingerprint_issues=missing,
        )

    bad_roots = sorted(
        fp for fp in trust_roots
        if certs[fp].subject != certs[fp].issuer
        or not _verify_signature(certs[fp], certs[fp])
    )
    if bad_roots:
        raise NormalizeError(
            "trust_root_not_self_signed",
            "every declared trust root must be a self-signed certificate "
            "(subject == issuer with a valid self-signature)",
            fingerprint_issues=[
                NormalizeFingerprintIssue(
                    fingerprint=fp, referred_by="trust_roots")
                for fp in bad_roots
            ],
        )

    # -- chain resolution (same exact zero/unique/ambiguous verdict) --------
    edges = _build_issuer_edges(certs)
    roots = frozenset(trust_roots)

    resolved: dict[str, tuple[Optional[list[str]], bool]] = {}
    for _endpoint_id, _chain_role, leaf in leaves:
        if leaf not in resolved:
            first = _find_trust_path(leaf, edges, roots)
            ambiguous = first is not None and _has_second_trust_path(
                first, edges, roots)
            resolved[leaf] = (first, ambiguous)

    chain_issues: list[NormalizeChainIssue] = []
    chosen: dict[str, Optional[list[str]]] = {}
    for endpoint_id, chain_role, leaf in leaves:
        first, ambiguous = resolved[leaf]
        if first is not None and not ambiguous:
            chosen[leaf] = first
            continue
        chosen[leaf] = None
        if not any(i.leaf == leaf for i in chain_issues):
            valid, dead_ends = _enumerate_paths(leaf, edges, roots)
            chain_issues.append(NormalizeChainIssue(
                endpoint_id=endpoint_id,
                leaf_role=chain_role,  # type: ignore[arg-type]
                leaf=leaf,
                candidate_issuers=sorted(edges.get(leaf, [])),
                candidate_paths=_dedupe_paths(valid + dead_ends),
                reason="ambiguous_chain" if ambiguous else "no_trust_path",
            ))
    if chain_issues:
        ambiguous = any(i.reason == "ambiguous_chain" for i in chain_issues)
        raise NormalizeError(
            "ambiguous_chain" if ambiguous else "no_trust_path",
            "cross-signing leaves multiple valid paths to a declared trust "
            "root" if ambiguous
            else "no verified signature path from a leaf to any declared "
                 "trust root",
            chain_issues=chain_issues,
        )

    # -- per-endpoint policy evaluation of BOTH chains -----------------------
    check_time = req.check_time
    skew = timedelta(seconds=req.max_skew_seconds)
    results: list[EndpointPolicyResult] = []
    for e in req.endpoints:
        required = required_by_endpoint[e.endpoint_id]
        cur_fp = e.current_leaf_fingerprint.strip().lower()
        tgt_fp = e.target_leaf_fingerprint.strip().lower()
        current_review = evaluate_chain(
            "current", chosen[cur_fp], certs, e.role, required,
            check_time, skew,  # type: ignore[arg-type]
        )
        target_review = evaluate_chain(
            "target", chosen[tgt_fp], certs, e.role, required,
            check_time, skew,  # type: ignore[arg-type]
        )

        # Endpoint first conflict: current chain wins over target; within a
        # chain the first violation is already (position, precedence) sorted.
        violating_chain: Optional[str] = None
        if not current_review.eligible:
            violating_chain = "current"
            first_reason = current_review.reason
        elif not target_review.eligible:
            violating_chain = "target"
            first_reason = target_review.reason
        else:
            first_reason = "ok"

        results.append(EndpointPolicyResult(
            endpoint_id=e.endpoint_id,
            role=e.role,
            required_eku=required,
            current_leaf_fingerprint=cur_fp,
            target_leaf_fingerprint=tgt_fp,
            eligible=(current_review.eligible and target_review.eligible),
            reason=first_reason,  # type: ignore[arg-type]
            violating_chain=violating_chain,  # type: ignore[arg-type]
            current_chain=current_review,
            target_chain=target_review,
        ))

    results.sort(key=lambda r: r.endpoint_id)
    return PolicyReviewResult(
        check_time=check_time,
        max_skew_seconds=req.max_skew_seconds,
        results=results,
    )
