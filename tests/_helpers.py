"""Shared fixtures and helpers for the unit-test suite."""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from ssh_cert_validator import CAVerifier
from ssh_cert_validator.builder import CertificateBuilder, ssh_public_blob
from ssh_cert_validator.certificate import (
    SSH_CERT_TYPE_HOST,
    SSH_CERT_TYPE_USER,
)
from ssh_cert_validator.wire import WireReader


def ed25519_pair():
    ca = ed25519.Ed25519PrivateKey.generate()
    subject = ed25519.Ed25519PrivateKey.generate()
    return ca, subject


def ecdsa_pair(curve=ec.SECP256R1):
    ca = ec.generate_private_key(curve())
    subject = ec.generate_private_key(curve())
    return ca, subject


def rsa_pair(key_size=2048):
    ca = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return ca, subject


def ca_public_line(ca_private_key) -> str:
    blob = ssh_public_blob(ca_private_key.public_key())
    name = WireReader(blob).string()
    return (name + b" " + base64.b64encode(blob)).decode("ascii")


def verifier_for(ca_private_key) -> CAVerifier:
    return CAVerifier.from_public_keys([ca_public_line(ca_private_key)])


def build_cert(
    subject_private_key,
    ca_private_key,
    *,
    cert_type=SSH_CERT_TYPE_USER,
    key_id="test-key",
    serial=1,
    principals=None,
    valid_after=0,
    valid_before=2_000_000_000,
    critical_options=None,
    extensions=None,
    nonce=None,
):
    builder = CertificateBuilder(subject_private_key.public_key(), ca_private_key)
    if cert_type == SSH_CERT_TYPE_HOST:
        builder.set_host_certificate()
    else:
        builder.set_user_certificate()
    builder.set_key_id(key_id).set_serial(serial)
    builder.set_principals(["alice"] if principals is None else list(principals))
    builder.set_validity(valid_after, valid_before)
    for name, data in (critical_options or []):
        builder.add_critical_option(name, data)
    for name, data in (extensions or []):
        builder.add_extension(name, data)
    if nonce is not None:
        builder.set_nonce(nonce)
    return builder.build()


def cert_public_line(blob: bytes) -> str:
    head = WireReader(blob).string()
    return (head + b" " + base64.b64encode(blob)).decode("ascii")
