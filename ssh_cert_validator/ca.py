"""CA trust management and cryptographic signature verification."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import load_ssh_public_key

from .certificate import Certificate


class VerificationError(Exception):
    """Raised when a certificate signature cannot be validated."""


#: Signature algorithms accepted when the CA key is RSA.
RSA_SIGNATURE_ALGORITHMS = {
    "rsa-sha2-512": hashes.SHA512,
    "rsa-sha2-256": hashes.SHA256,
    "ssh-rsa": hashes.SHA1,
}

#: ECDSA signature algorithm name mapped to its curve hash.
ECDSA_SIGNATURE_ALGORITHMS = {
    "ecdsa-sha2-nistp256": hashes.SHA256,
    "ecdsa-sha2-nistp384": hashes.SHA384,
    "ecdsa-sha2-nistp521": hashes.SHA512,
}


def ssh_ecdsa_to_der(ssh_signature: bytes) -> bytes:
    """Rebuild a DER ECDSA signature from the RFC 5656 ``r``/``s`` mpints."""
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    from .wire import WireReader

    reader = WireReader(ssh_signature)
    # RFC 5656 fixed-width unsigned integers.
    r = int.from_bytes(reader.string(), "big", signed=False)
    s = int.from_bytes(reader.string(), "big", signed=False)
    reader.expect_end()
    return encode_dss_signature(r, s)


def ssh_fingerprint(ssh_public_blob: bytes) -> str:
    """Return the SHA256 public-key fingerprint used by OpenSSH."""
    digest = hashlib.sha256(ssh_public_blob).digest()
    return "SHA256:" + base64.b64encode(digest).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class TrustedCA:
    """A trusted CA public key together with its SSH wire blob."""

    ssh_blob: bytes
    public_key: object

    @property
    def fingerprint(self) -> str:
        return ssh_fingerprint(self.ssh_blob)


def load_ca(ssh_public_line: str | bytes) -> TrustedCA:
    """Load a CA from an ``*.pub`` line, raw SSH blob or base64 body."""
    if isinstance(ssh_public_line, str):
        text = ssh_public_line.strip()
        parts = text.split()
        if len(parts) >= 2 and parts[0].startswith(("ssh-", "ecdsa-")):
            ssh_blob = base64.b64decode(parts[1], validate=True)
        else:
            ssh_blob = base64.b64decode(parts[0], validate=True)
    else:
        ssh_blob = bytes(ssh_public_line)
    try:
        public_key = load_ssh_public_key(_serialize_ssh_line(ssh_blob))
    except Exception as exc:  # pragma: no cover - defensive
        raise VerificationError("could not load CA public key") from exc
    return TrustedCA(ssh_blob=ssh_blob, public_key=public_key)


def _serialize_ssh_line(ssh_blob: bytes) -> bytes:
    from .wire import WireReader

    key_type = WireReader(ssh_blob).string()
    return key_type + b" " + base64.b64encode(ssh_blob)


class CAVerifier:
    """Verify certificate signatures against a set of trusted CA keys.

    The verifier first requires the certificate's embedded signature key to
    exactly match one of the trusted CA blobs, then checks the signature with
    the algorithm named inside the signature blob.  Trust is therefore based on
    an exact key match, never on a prefix or comment.
    """

    def __init__(self, trusted: list[TrustedCA] | None = None) -> None:
        self._by_blob: dict[bytes, TrustedCA] = {}
        for ca in trusted or []:
            self.add(ca)

    @classmethod
    def from_public_keys(cls, lines: list[str | bytes]) -> "CAVerifier":
        return cls([load_ca(line) for line in lines])

    def add(self, ca: TrustedCA) -> None:
        self._by_blob[ca.ssh_blob] = ca

    def trusts(self, certificate: Certificate) -> bool:
        return certificate.signature_key in self._by_blob

    def trusted_ca(self, certificate: Certificate) -> TrustedCA:
        ca = self._by_blob.get(certificate.signature_key)
        if ca is None:
            raise VerificationError(
                "signing CA %s is not in the trust store"
                % ssh_fingerprint(certificate.signature_key)
            )
        return ca

    def verify(self, certificate: Certificate) -> None:
        """Raise :class:`VerificationError` unless the signature is valid."""
        ca = self.trusted_ca(certificate)
        _verify_signature(
            ca.public_key,
            certificate.signature.algorithm,
            certificate.signature.signature,
            certificate.signed_region,
        )

    def is_valid(self, certificate: Certificate) -> bool:
        try:
            self.verify(certificate)
        except VerificationError:
            return False
        return True


def _verify_signature(public_key: object, algorithm: str, signature: bytes, message: bytes) -> None:
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        if algorithm != "ssh-ed25519":
            raise VerificationError(
                "unexpected signature algorithm %r for Ed25519 CA" % algorithm
            )
        try:
            public_key.verify(signature, message)
        except Exception as exc:
            raise VerificationError("Ed25519 signature mismatch") from exc
        return

    if isinstance(public_key, rsa.RSAPublicKey):
        hash_cls = RSA_SIGNATURE_ALGORITHMS.get(algorithm)
        if hash_cls is None:
            raise VerificationError("unsupported RSA signature algorithm: %r" % algorithm)
        try:
            public_key.verify(signature, message, padding.PKCS1v15(), hash_cls())
        except Exception as exc:
            raise VerificationError("RSA signature mismatch") from exc
        return

    if isinstance(public_key, ec.EllipticCurvePublicKey):
        hash_cls = ECDSA_SIGNATURE_ALGORITHMS.get(algorithm)
        if hash_cls is None:
            raise VerificationError("unsupported ECDSA signature algorithm: %r" % algorithm)
        try:
            der_signature = ssh_ecdsa_to_der(signature)
            public_key.verify(der_signature, message, ec.ECDSA(hash_cls()))
        except Exception as exc:
            raise VerificationError("ECDSA signature mismatch") from exc
        return

    raise VerificationError(
        "unsupported CA key type: %s" % type(public_key).__name__
    )


__all__ = [
    "CAVerifier",
    "TrustedCA",
    "VerificationError",
    "load_ca",
    "ssh_ecdsa_to_der",
    "ssh_fingerprint",
]
