"""Parsing of OpenSSH ``*-cert-v01@openssh.com`` certificate blobs."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass

from .wire import WireReader, read_packed_pairs, read_packed_strings

SSH_CERT_TYPE_USER = 1
SSH_CERT_TYPE_HOST = 2

#: Certificate type names advertised in the leading cert-key string.
USER_CERT_TYPES = frozenset(
    {
        "ssh-rsa-cert-v01@openssh.com",
        "ssh-ed25519-cert-v01@openssh.com",
        "ecdsa-sha2-nistp256-cert-v01@openssh.com",
        "ecdsa-sha2-nistp384-cert-v01@openssh.com",
        "ecdsa-sha2-nistp521-cert-v01@openssh.com",
    }
)
HOST_CERT_TYPES = USER_CERT_TYPES
KNOWN_CERT_TYPES = USER_CERT_TYPES

#: Marker for ``valid_before`` / ``valid_after`` that disables the boundary.
INFINITY = 0xFFFFFFFFFFFFFFFF

#: OpenSSH rejects nonces shorter than this many bytes.
MINIMUM_NONCE_BYTES = 32


class CertificateError(ValueError):
    """Base class for malformed certificate blobs."""


@dataclass(frozen=True)
class Option:
    """A critical option or extension entry."""

    name: str
    data: bytes


@dataclass(frozen=True)
class Signature:
    """The inner signature blob: algorithm name plus raw signature bytes."""

    algorithm: str
    signature: bytes


@dataclass(frozen=True)
class Certificate:
    """Structured view of an OpenSSH certificate.

    ``signed_region`` is the exact byte range covered by the CA signature:
    every field from the leading cert-key string up to and including the
    nested signature-key string, excluding the outer signature framing.
    """

    cert_key_type: str
    nonce: bytes
    #: Algorithm-specific public-key payload that follows the nonce.
    public_key_fields: tuple[bytes, ...]
    serial: int
    cert_type: int
    key_id: str
    principals: tuple[str, ...]
    valid_after: int
    valid_before: int
    critical_options: tuple[Option, ...]
    extensions: tuple[Option, ...]
    reserved: bytes
    signature_key: bytes
    signature: Signature
    raw_blob: bytes
    signed_region: bytes

    def critical_option(self, name: str) -> Option | None:
        for option in self.critical_options:
            if option.name == name:
                return option
        return None

    def has_extension(self, name: str) -> bool:
        return any(option.name == name for option in self.extensions)

    @property
    def is_user_certificate(self) -> bool:
        return self.cert_type == SSH_CERT_TYPE_USER

    @property
    def is_host_certificate(self) -> bool:
        return self.cert_type == SSH_CERT_TYPE_HOST


def _decode_text(raw: bytes, what: str) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CertificateError("%s is not valid UTF-8" % what) from exc


def _read_key_specific_fields(reader: WireReader, cert_key_type: str) -> tuple[bytes, ...]:
    if cert_key_type.startswith("ssh-rsa-cert"):
        # mpint e, mpint n
        return (reader.string(), reader.string())
    if cert_key_type.startswith("ecdsa-sha2"):
        # string curve identifier, string public key Q
        return (reader.string(), reader.string())
    if "ed25519" in cert_key_type:
        # string pk
        return (reader.string(),)
    raise CertificateError("unsupported certificate key type: %r" % cert_key_type)


def parse_certificate(blob: bytes | str) -> Certificate:
    """Parse a certificate blob.

    Accepts either the raw binary blob, the base64 body of an ``authorized_keys``
    / ``known_hosts`` line, or a full single-line ``*.pub`` certificate.
    """
    raw = _coerce_blob(blob)
    reader = WireReader(raw)

    cert_key_type_raw = reader.string()
    cert_key_type = _decode_text(cert_key_type_raw, "certificate key type")
    if cert_key_type not in KNOWN_CERT_TYPES:
        raise CertificateError("unknown or unsupported cert key type: %r" % cert_key_type)

    nonce = reader.string()
    public_key_fields = _read_key_specific_fields(reader, cert_key_type)

    serial = reader.u64()
    cert_type = reader.u32()
    if cert_type not in (SSH_CERT_TYPE_USER, SSH_CERT_TYPE_HOST):
        raise CertificateError("invalid certificate type value: %d" % cert_type)

    key_id = _decode_text(reader.string(), "key id")

    principals_container = reader.string()
    principals = tuple(
        _decode_text(entry, "principal")
        for entry in read_packed_strings(principals_container)
    )

    valid_after = reader.u64()
    valid_before = reader.u64()

    critical_options = _read_options(reader, "critical options")
    extensions = _read_options(reader, "extensions")
    reserved = reader.string()
    signature_key = reader.string()
    signature_blob = reader.string()
    reader.expect_end()

    signature = _parse_signature(signature_blob)

    # The signature covers everything preceding the outer signature string,
    # including the length prefix of the signature-key field.  The outer
    # signature framing (its uint32 length and payload) is excluded.
    signed_region = raw[: reader.pos - 4 - len(signature_blob)]

    return Certificate(
        cert_key_type=cert_key_type,
        nonce=nonce,
        public_key_fields=tuple(public_key_fields),
        serial=serial,
        cert_type=cert_type,
        key_id=key_id,
        principals=principals,
        valid_after=valid_after,
        valid_before=valid_before,
        critical_options=critical_options,
        extensions=extensions,
        reserved=reserved,
        signature_key=signature_key,
        signature=signature,
        raw_blob=raw,
        signed_region=signed_region,
    )


def _read_options(reader: WireReader, what: str) -> tuple[Option, ...]:
    container = reader.string()
    options: list[Option] = []
    for raw_name, data in read_packed_pairs(container):
        name = _decode_text(raw_name, "%s name" % what)
        # Non-empty values are an outer data string wrapping the inner value
        # string; empty flag-style options carry a zero-length payload.
        if data:
            data = WireReader(data).string()
        options.append(Option(name=name, data=data))
    return tuple(options)


def _parse_signature(blob: bytes) -> Signature:
    reader = WireReader(blob)
    algorithm = _decode_text(reader.string(), "signature algorithm")
    signature = reader.string()
    reader.expect_end()
    return Signature(algorithm=algorithm, signature=signature)


def _coerce_blob(blob: bytes | str) -> bytes:
    if isinstance(blob, bytes):
        return blob
    if not isinstance(blob, str):
        raise CertificateError("certificate blob must be bytes or str")

    text = blob.strip()
    # A full authorized_keys style line: "<type> <base64> [comment]".
    parts = text.split()
    if len(parts) >= 2 and parts[0].startswith(("ssh-", "ecdsa-")):
        text = parts[1]
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CertificateError("certificate blob is not valid base64") from exc


__all__ = [
    "Certificate",
    "CertificateError",
    "HOST_CERT_TYPES",
    "INFINITY",
    "MINIMUM_NONCE_BYTES",
    "Option",
    "SSH_CERT_TYPE_HOST",
    "SSH_CERT_TYPE_USER",
    "Signature",
    "USER_CERT_TYPES",
    "parse_certificate",
]
