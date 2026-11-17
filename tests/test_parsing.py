import base64
import unittest

from ssh_cert_validator import (
    CertificateError,
    INFINITY,
    SSH_CERT_TYPE_HOST,
    SSH_CERT_TYPE_USER,
    parse_certificate,
)
from ssh_cert_validator.certificate import MINIMUM_NONCE_BYTES
from ssh_cert_validator.wire import WireError

from ._helpers import build_cert, cert_public_line, ed25519_pair, ecdsa_pair, rsa_pair


class ParsingTests(unittest.TestCase):
    def test_parses_all_user_certificate_fields(self):
        ca, subject = ed25519_pair()
        blob = build_cert(
            subject,
            ca,
            key_id="key-42",
            serial=4242,
            principals=["alice", "admin"],
            valid_after=1_700_000_000,
            valid_before=1_700_000_100,
            critical_options=[
                ("force-command", b"/usr/bin/uptime"),
                ("source-address", b"10.0.0.0/24,192.168.1.5"),
            ],
            extensions=[("permit-pty", b""), ("permit-port-forwarding", b"")],
        )
        cert = parse_certificate(blob)

        self.assertEqual(cert.cert_key_type, "ssh-ed25519-cert-v01@openssh.com")
        self.assertEqual(len(cert.nonce), MINIMUM_NONCE_BYTES)
        self.assertEqual(cert.serial, 4242)
        self.assertEqual(cert.cert_type, SSH_CERT_TYPE_USER)
        self.assertEqual(cert.key_id, "key-42")
        self.assertEqual(cert.principals, ("alice", "admin"))
        self.assertEqual(cert.valid_after, 1_700_000_000)
        self.assertEqual(cert.valid_before, 1_700_000_100)
        self.assertEqual(
            cert.critical_option("force-command").data, b"/usr/bin/uptime"
        )
        self.assertEqual(
            cert.critical_option("source-address").data,
            b"10.0.0.0/24,192.168.1.5",
        )
        self.assertTrue(cert.has_extension("permit-pty"))
        self.assertTrue(cert.has_extension("permit-port-forwarding"))
        self.assertFalse(cert.has_extension("permit-X11-forwarding"))

    def test_parses_host_certificate_type(self):
        ca, subject = ed25519_pair()
        blob = build_cert(subject, ca, cert_type=SSH_CERT_TYPE_HOST, principals=["db.example.com"])
        cert = parse_certificate(blob)
        self.assertEqual(cert.cert_type, SSH_CERT_TYPE_HOST)
        self.assertTrue(cert.is_host_certificate)
        self.assertFalse(cert.is_user_certificate)
        self.assertEqual(cert.principals, ("db.example.com",))

    def test_empty_principals_means_wildcard(self):
        ca, subject = ed25519_pair()
        blob = build_cert(subject, ca, principals=[])
        cert = parse_certificate(blob)
        self.assertEqual(cert.principals, ())

    def test_forever_window_uses_uint64_sentinel(self):
        ca, subject = ed25519_pair()
        blob = build_cert(subject, ca, valid_after=0, valid_before=INFINITY)
        cert = parse_certificate(blob)
        self.assertEqual(cert.valid_before, INFINITY)

    def test_signed_region_excludes_signature_framing(self):
        ca, subject = ed25519_pair()
        blob = build_cert(subject, ca)
        cert = parse_certificate(blob)
        # The signature outer string (4 byte length + nested signature blob)
        # is the only part excluded from the signed region.
        nested_sig = cert.signature
        from ssh_cert_validator.wire import encode_string

        signature_blob = encode_string(
            encode_string(nested_sig.algorithm.encode("ascii"))
            + encode_string(nested_sig.signature)
        )
        sig_framing = len(signature_blob)
        self.assertEqual(len(cert.signed_region), len(blob) - sig_framing)
        self.assertEqual(
            cert.signed_region, blob[: len(blob) - sig_framing]
        )

    def test_accepts_authorized_keys_line_and_base64(self):
        ca, subject = ed25519_pair()
        blob = build_cert(subject, ca)
        line = cert_public_line(blob)
        from_line = parse_certificate(line)
        from_b64 = parse_certificate(line.split()[1])
        from_raw = parse_certificate(blob)
        self.assertEqual(from_line.key_id, from_b64.key_id)
        self.assertEqual(from_raw.key_id, from_line.key_id)

    def test_parses_ecdsa_and_rsa_certificates(self):
        ecdsa_ca, ecdsa_subject = ecdsa_pair()
        ecdsa_blob = build_cert(ecdsa_subject, ecdsa_ca)
        ecdsa_cert = parse_certificate(ecdsa_blob)
        self.assertIn("ecdsa-sha2-nistp256", ecdsa_cert.cert_key_type)
        self.assertEqual(len(ecdsa_cert.public_key_fields), 2)

        rsa_ca, rsa_subject = rsa_pair()
        rsa_blob = build_cert(rsa_subject, rsa_ca)
        rsa_cert = parse_certificate(rsa_blob)
        self.assertEqual(rsa_cert.cert_key_type, "ssh-rsa-cert-v01@openssh.com")
        self.assertEqual(len(rsa_cert.public_key_fields), 2)

    def test_rejects_truncated_blob(self):
        ca, subject = ed25519_pair()
        blob = build_cert(subject, ca)
        with self.assertRaises(WireError):
            parse_certificate(blob[:-5])

    def test_rejects_trailing_bytes(self):
        ca, subject = ed25519_pair()
        blob = build_cert(subject, ca)
        with self.assertRaises(WireError):
            parse_certificate(blob + b"\x00\x00\x00\x00")

    def test_rejects_unknown_cert_key_type(self):
        ca, subject = ed25519_pair()
        blob = bytearray(build_cert(subject, ca))
        # Replace the leading type string with an unsupported one of same length.
        fake = b"ssh-dss-cert-v01@openssh.com\x00\x00"
        blob[4:4 + 32] = fake[:32]
        with self.assertRaises(CertificateError):
            parse_certificate(bytes(blob))

    def test_rejects_invalid_base64(self):
        with self.assertRaises(CertificateError):
            parse_certificate("not valid base64!!!")

    def test_rejects_unknown_certificate_type_value(self):
        ca, subject = ed25519_pair()
        blob = bytearray(build_cert(subject, ca))
        # For an Ed25519 cert the uint32 type field sits at byte offset 116.
        self.assertEqual(
            int.from_bytes(blob[116:120], "big"), SSH_CERT_TYPE_USER
        )
        blob[119] = 3
        with self.assertRaises(CertificateError):
            parse_certificate(bytes(blob))


if __name__ == "__main__":
    unittest.main()
