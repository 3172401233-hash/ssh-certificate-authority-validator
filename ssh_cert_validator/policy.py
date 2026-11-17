"""Validation policy: principals, validity window, options and revocation."""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field

from .ca import CAVerifier
from .certificate import (
    INFINITY,
    MINIMUM_NONCE_BYTES,
    SSH_CERT_TYPE_HOST,
    SSH_CERT_TYPE_USER,
    Certificate,
    Option,
)


class PolicyError(Exception):
    """Base class for certificate policy violations."""


class CertificateExpiredError(PolicyError):
    """The current time is outside the certificate validity window."""


class PrincipalMismatchError(PolicyError):
    """No certificate principal matches the requested identity."""


class CertificateTypeError(PolicyError):
    """A user certificate was presented to a host service or vice versa."""


class RevokedCertificateError(PolicyError):
    """The certificate serial or key id appears on a revocation list."""


class CriticalOptionError(PolicyError):
    """A critical option is unknown or invalid for the session type."""


class SourceAddressError(PolicyError):
    """The peer address is not permitted by a source-address option."""


class WeakNonceError(PolicyError):
    """The certificate nonce is shorter than the required minimum."""


#: Critical options understood by this implementation.
KNOWN_CRITICAL_OPTIONS = frozenset({"force-command", "source-address"})


@dataclass
class RevocationList:
    """Revocation state keyed by certificate serial and key id.

    OpenSSH KRL files support several record shapes; this class models the
    decisions a KRL encodes without parsing the binary KRL container itself.
    """

    serials: set[int] = field(default_factory=set)
    serial_ranges: list[tuple[int, int]] = field(default_factory=list)
    key_ids: set[str] = field(default_factory=set)

    def revoke_serial(self, serial: int) -> None:
        if serial < 0:
            raise ValueError("serial must be non-negative")
        self.serials.add(serial)

    def revoke_serial_range(self, start: int, end: int) -> None:
        if start > end:
            raise ValueError("revocation range start must not exceed end")
        self.serial_ranges.append((start, end))

    def revoke_key_id(self, key_id: str) -> None:
        self.key_ids.add(key_id)

    def is_revoked(self, certificate: Certificate) -> bool:
        if certificate.serial in self.serials or certificate.key_id in self.key_ids:
            return True
        return any(start <= certificate.serial <= end for start, end in self.serial_ranges)


@dataclass(frozen=True)
class ValidationResult:
    """Outcome of a successful validation."""

    certificate: Certificate
    principal: str
    forced_command: str | None


def principal_matches(certificate: Certificate, requested_principal: str) -> bool:
    """Exact-match the requested user or host against certificate principals.

    Matching is deliberately a byte-for-byte equality check: a principal such as
    ``alice`` must never authenticate a request for ``alice-admin`` and vice
    versa.  An empty principal list means the certificate is valid for any
    principal of its type, matching the OpenSSH wildcard semantics.
    """
    if not requested_principal:
        return False
    if not certificate.principals:
        return True
    return requested_principal in certificate.principals


def is_within_validity(certificate: Certificate, now: int | None = None) -> bool:
    """Apply the OpenSSH boundary rule ``valid_after <= now < valid_before``."""
    current = int(time.time()) if now is None else now
    if current < certificate.valid_after:
        return False
    if certificate.valid_before != INFINITY and current >= certificate.valid_before:
        return False
    return True


def source_addresses_permitted(certificate: Certificate, peer_address: str | None) -> bool:
    option = certificate.critical_option("source-address")
    if option is None:
        return True
    if peer_address is None:
        # A bound source-address option cannot be enforced without an address.
        return False
    try:
        peer = ipaddress.ip_address(peer_address)
    except ValueError:
        return False
    raw = option.data.decode("utf-8")
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            raise CriticalOptionError("invalid source-address entry: %r" % entry)
        if peer in network:
            return True
    return False


def forced_command(certificate: Certificate) -> str | None:
    option = certificate.critical_option("force-command")
    if option is None:
        return None
    return option.data.decode("utf-8")


def check_critical_options(certificate: Certificate) -> None:
    """Reject unknown critical options and host misuse of user-only options."""
    for option in certificate.critical_options:
        if option.name not in KNOWN_CRITICAL_OPTIONS:
            raise CriticalOptionError(
                "unrecognised critical option %r must be refused" % option.name
            )
        if certificate.cert_type == SSH_CERT_TYPE_HOST:
            raise CriticalOptionError(
                "critical option %r is only defined for user certificates" % option.name
            )


def validate_certificate(
    certificate: Certificate,
    ca_verifier: CAVerifier,
    *,
    expected_type: int,
    requested_principal: str,
    peer_address: str | None = None,
    now: int | None = None,
    revocation_list: RevocationList | None = None,
) -> ValidationResult:
    """Run every mandatory check and return a structured result.

    Checks are ordered so that cryptographic trust is established before any
    policy decision is made.  The first failure raises a specific exception.
    """
    ca_verifier.verify(certificate)

    if certificate.cert_type != expected_type:
        expected = "user" if expected_type == SSH_CERT_TYPE_USER else "host"
        actual = "user" if certificate.is_user_certificate else "host"
        raise CertificateTypeError(
            "expected a %s certificate but got a %s certificate" % (expected, actual)
        )

    if len(certificate.nonce) < MINIMUM_NONCE_BYTES:
        raise WeakNonceError(
            "nonce is %d bytes; minimum required is %d"
            % (len(certificate.nonce), MINIMUM_NONCE_BYTES)
        )

    if not is_within_validity(certificate, now=now):
        raise CertificateExpiredError(
            "current time outside validity window [%d, %d)"
            % (certificate.valid_after, certificate.valid_before)
        )

    if not principal_matches(certificate, requested_principal):
        raise PrincipalMismatchError(
            "principal %r does not exactly match any of %r"
            % (requested_principal, list(certificate.principals))
        )

    if revocation_list is not None and revocation_list.is_revoked(certificate):
        raise RevokedCertificateError(
            "certificate serial %d (key id %r) is revoked"
            % (certificate.serial, certificate.key_id)
        )

    check_critical_options(certificate)

    if not source_addresses_permitted(certificate, peer_address):
        raise SourceAddressError(
            "peer address %r not permitted by source-address option" % peer_address
        )

    return ValidationResult(
        certificate=certificate,
        principal=requested_principal,
        forced_command=forced_command(certificate),
    )


__all__ = [
    "CertificateExpiredError",
    "CertificateTypeError",
    "CriticalOptionError",
    "PolicyError",
    "PrincipalMismatchError",
    "RevocationList",
    "RevokedCertificateError",
    "SourceAddressError",
    "ValidationResult",
    "WeakNonceError",
    "forced_command",
    "is_within_validity",
    "principal_matches",
    "source_addresses_permitted",
    "validate_certificate",
]
