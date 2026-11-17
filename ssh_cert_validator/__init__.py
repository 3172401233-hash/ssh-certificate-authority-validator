"""Python OpenSSH certificate parsing and CA validation.

The public API groups three concerns:

* :func:`parse_certificate` turns a certificate blob into a structured object.
* :class:`CAVerifier` holds trusted CA keys and checks the CA signature.
* :func:`validate_certificate` enforces type, principal, validity, option and
  revocation policy on top of the cryptographic check.
"""

from .ca import CAVerifier, TrustedCA, VerificationError, load_ca
from .certificate import (
    HOST_CERT_TYPES,
    INFINITY,
    MINIMUM_NONCE_BYTES,
    SSH_CERT_TYPE_HOST,
    SSH_CERT_TYPE_USER,
    Certificate,
    CertificateError,
    Option,
    Signature,
    parse_certificate,
)
from .policy import (
    CertificateExpiredError,
    CertificateTypeError,
    CriticalOptionError,
    PolicyError,
    PrincipalMismatchError,
    RevocationList,
    RevokedCertificateError,
    SourceAddressError,
    ValidationResult,
    WeakNonceError,
    forced_command,
    is_within_validity,
    principal_matches,
    source_addresses_permitted,
    validate_certificate,
)

__version__ = "1.0.0"

__all__ = [
    "CAVerifier",
    "Certificate",
    "CertificateError",
    "CertificateExpiredError",
    "CertificateTypeError",
    "CriticalOptionError",
    "HOST_CERT_TYPES",
    "INFINITY",
    "MINIMUM_NONCE_BYTES",
    "Option",
    "PolicyError",
    "PrincipalMismatchError",
    "RevocationList",
    "RevokedCertificateError",
    "SourceAddressError",
    "SSH_CERT_TYPE_HOST",
    "SSH_CERT_TYPE_USER",
    "Signature",
    "TrustedCA",
    "ValidationResult",
    "VerificationError",
    "WeakNonceError",
    "forced_command",
    "is_within_validity",
    "load_ca",
    "parse_certificate",
    "principal_matches",
    "source_addresses_permitted",
    "validate_certificate",
]
