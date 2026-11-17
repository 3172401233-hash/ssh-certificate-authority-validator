"""Minimal in-memory OpenSSH certificate builder used for testing and tools.

The builder mirrors the wire layout in ``PROTOCOL.certkeys`` and signs with a
CA key held by the ``cryptography`` library.  It intentionally supports only
the key types needed by the test-suite, but produces byte-identical structures
to ``ssh-keygen`` so the parser can be cross-checked against real certificates.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from .certificate import (
    INFINITY,
    SSH_CERT_TYPE_HOST,
    SSH_CERT_TYPE_USER,
)
from .wire import encode_string, encode_u32, encode_u64


class BuilderError(ValueError):
    pass


def ssh_public_blob(public_key: object) -> bytes:
    """Serialize a public key into the SSH wire format used in ``*.pub``."""
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        raw = public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return encode_string(b"ssh-ed25519") + encode_string(raw)
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        curve_name = {
            "secp256r1": ("nistp256", b"ecdsa-sha2-nistp256"),
            "secp384r1": ("nistp384", b"ecdsa-sha2-nistp384"),
            "secp521r1": ("nistp521", b"ecdsa-sha2-nistp521"),
        }.get(public_key.curve.name)
        if curve_name is None:
            raise BuilderError("unsupported EC curve: %s" % public_key.curve.name)
        nist_name, alg_name = curve_name
        numbers = public_key.public_numbers()
        # Uncompressed point: 0x04 || X || Y, padded to the curve size.
        size = (public_key.curve.key_size + 7) // 8
        point = b"\x04" + numbers.x.to_bytes(size, "big") + numbers.y.to_bytes(size, "big")
        return (
            encode_string(alg_name)
            + encode_string(nist_name.encode("ascii"))
            + encode_string(point)
        )
    if isinstance(public_key, rsa.RSAPublicKey):
        numbers = public_key.public_numbers()
        return (
            encode_string(b"ssh-rsa")
            + encode_mpint(numbers.e)
            + encode_mpint(numbers.n)
        )
    raise BuilderError("unsupported public key type: %s" % type(public_key).__name__)


def encode_mpint(value: int) -> bytes:
    """Encode an integer as an SSH mpint string."""
    if value == 0:
        body = b""
    else:
        length = value.bit_length() // 8 + 1
        body = value.to_bytes(length, "big", signed=False)
        if body[0] & 0x80:
            body = b"\x00" + body
    return encode_string(body)


def der_ecdsa_to_ssh(der_signature: bytes, curve_key_size: int) -> bytes:
    """Convert an ECDSA DER ``SEQUENCE { r, s }`` into two SSH mpints."""
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    try:
        r, s = decode_dss_signature(der_signature)
    except Exception as exc:
        raise BuilderError("invalid DER ECDSA signature") from exc
    # RFC 5656 encodes r and s as fixed-width unsigned integers padded to the
    # curve size, not as general SSH mpints with sign handling.
    width = (curve_key_size + 7) // 8
    return (
        encode_string(r.to_bytes(width, "big"))
        + encode_string(s.to_bytes(width, "big"))
    )


def _cert_key_type(ca_or_subject_blob: bytes) -> bytes:
    leading = _first_string(ca_or_subject_blob)
    mapping = {
        b"ssh-ed25519": b"ssh-ed25519-cert-v01@openssh.com",
        b"ssh-rsa": b"ssh-rsa-cert-v01@openssh.com",
        b"ecdsa-sha2-nistp256": b"ecdsa-sha2-nistp256-cert-v01@openssh.com",
        b"ecdsa-sha2-nistp384": b"ecdsa-sha2-nistp384-cert-v01@openssh.com",
        b"ecdsa-sha2-nistp521": b"ecdsa-sha2-nistp521-cert-v01@openssh.com",
    }
    try:
        return mapping[leading]
    except KeyError as exc:
        raise BuilderError("cannot derive cert type from %r" % leading) from exc


def _first_string(blob: bytes) -> bytes:
    length = int.from_bytes(blob[:4], "big")
    return blob[4:4 + length]


def _pack_name_list(entries: list[bytes]) -> bytes:
    # "valid principals" is a nested string containing concatenated strings,
    # with no leading count (PROTOCOL.certkeys).
    inner = b"".join(encode_string(entry) for entry in entries)
    return encode_string(inner)


def _pack_options(options: list[tuple[str, bytes]]) -> bytes:
    ordered = sorted(options, key=lambda item: item[0])
    inner = b""
    for name, data in ordered:
        inner += encode_string(name.encode("utf-8")) + data
    return encode_string(inner)


def _encode_option_value(data: bytes) -> bytes:
    # Every option carries a data string.  Non-empty values are doubly framed
    # (outer data string wrapping the inner value string); empty flag-style
    # options are a single zero-length string.
    return encode_string(encode_string(data)) if data else encode_string(b"")


class CertificateBuilder:
    def __init__(self, subject_public_key: object, ca_private_key: object) -> None:
        self.subject_public_key = subject_public_key
        self.ca_private_key = ca_private_key
        self.subject_blob = ssh_public_blob(subject_public_key)
        self.ca_blob = ssh_public_blob(ca_private_key.public_key())
        self.cert_type = SSH_CERT_TYPE_USER
        self.serial = 0
        self.key_id = ""
        self.principals: list[str] = []
        self.valid_after = 0
        self.valid_before = INFINITY
        self.critical_options: list[tuple[str, bytes]] = []
        self.extensions: list[tuple[str, bytes]] = []
        self.reserved = b""
        self.nonce = os.urandom(32)

    def set_nonce(self, nonce: bytes) -> "CertificateBuilder":
        self.nonce = nonce
        return self

    def set_host_certificate(self) -> "CertificateBuilder":
        self.cert_type = SSH_CERT_TYPE_HOST
        return self

    def set_user_certificate(self) -> "CertificateBuilder":
        self.cert_type = SSH_CERT_TYPE_USER
        return self

    def set_serial(self, serial: int) -> "CertificateBuilder":
        self.serial = serial
        return self

    def set_key_id(self, key_id: str) -> "CertificateBuilder":
        self.key_id = key_id
        return self

    def set_principals(self, principals: list[str]) -> "CertificateBuilder":
        self.principals = list(principals)
        return self

    def set_validity(self, valid_after: int, valid_before: int) -> "CertificateBuilder":
        self.valid_after = valid_after
        self.valid_before = valid_before
        return self

    def add_critical_option(self, name: str, data: bytes = b"") -> "CertificateBuilder":
        self.critical_options.append((name, _encode_option_value(data)))
        return self

    def add_extension(self, name: str, data: bytes = b"") -> "CertificateBuilder":
        self.extensions.append((name, _encode_option_value(data)))
        return self

    def _subject_key_fields(self) -> bytes:
        # Strip the leading algorithm string; the certificate carries its own.
        reader_pos = 0
        length = int.from_bytes(self.subject_blob[:4], "big")
        return self.subject_blob[4 + length:]

    def build(self) -> bytes:
        cert_key_type = _cert_key_type(self.subject_blob)
        body = encode_string(cert_key_type)
        body += encode_string(self.nonce)
        body += self._subject_key_fields()
        body += encode_u64(self.serial)
        body += encode_u32(self.cert_type)
        body += encode_string(self.key_id.encode("utf-8"))
        body += _pack_name_list([name.encode("utf-8") for name in self.principals])
        body += encode_u64(self.valid_after)
        body += encode_u64(self.valid_before)
        body += _pack_options(self.critical_options)
        body += _pack_options(self.extensions)
        body += encode_string(self.reserved)
        body += encode_string(self.ca_blob)

        signature = self._sign(body)
        signature_blob = encode_string(self._signature_algorithm()) + encode_string(signature)
        # ``body`` already ends with the framed signature-key string; the
        # signature blob is the final outer string with no trailing padding.
        return body + encode_string(signature_blob)

    def _signature_algorithm(self) -> bytes:
        ca_key = self.ca_private_key
        if isinstance(ca_key, ed25519.Ed25519PrivateKey):
            return b"ssh-ed25519"
        if isinstance(ca_key, ec.EllipticCurvePrivateKey):
            return {
                "secp256r1": b"ecdsa-sha2-nistp256",
                "secp384r1": b"ecdsa-sha2-nistp384",
                "secp521r1": b"ecdsa-sha2-nistp521",
            }[ca_key.curve.name]
        if isinstance(ca_key, rsa.RSAPrivateKey):
            return b"rsa-sha2-512"
        raise BuilderError("unsupported CA key")

    def _sign(self, message: bytes) -> bytes:
        ca_key = self.ca_private_key
        if isinstance(ca_key, ed25519.Ed25519PrivateKey):
            return ca_key.sign(message)
        if isinstance(ca_key, ec.EllipticCurvePrivateKey):
            hash_cls = {
                "secp256r1": hashes.SHA256,
                "secp384r1": hashes.SHA384,
                "secp521r1": hashes.SHA512,
            }[ca_key.curve.name]
            der = ca_key.sign(message, ec.ECDSA(hash_cls()))
            return der_ecdsa_to_ssh(der, ca_key.curve.key_size)
        if isinstance(ca_key, rsa.RSAPrivateKey):
            return ca_key.sign(message, padding.PKCS1v15(), hashes.SHA512())
        raise BuilderError("unsupported CA key")


__all__ = [
    "BuilderError",
    "CertificateBuilder",
    "der_ecdsa_to_ssh",
    "encode_mpint",
    "ssh_public_blob",
]
