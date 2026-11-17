import unittest

from ssh_cert_validator import (
    CertificateExpiredError,
    CertificateTypeError,
    CriticalOptionError,
    INFINITY,
    PrincipalMismatchError,
    RevocationList,
    RevokedCertificateError,
    SSH_CERT_TYPE_HOST,
    SSH_CERT_TYPE_USER,
    SourceAddressError,
    ValidationResult,
    WeakNonceError,
    forced_command,
    is_within_validity,
    parse_certificate,
    principal_matches,
    source_addresses_permitted,
    validate_certificate,
)

from ._helpers import build_cert, ed25519_pair, verifier_for


class PrincipalMatchingTests(unittest.TestCase):
    def setUp(self):
        self.ca, self.subject = ed25519_pair()

    def test_exact_principal_match_accepted(self):
        cert = parse_certificate(build_cert(self.subject, self.ca, principals=["alice"]))
        self.assertTrue(principal_matches(cert, "alice"))

    def test_prefix_lookalikes_are_rejected(self):
        cert = parse_certificate(
            build_cert(self.subject, self.ca, principals=["alice", "admin"])
        )
        for bogus in ("alice-admin", "alice2", "adminx", "al", "adm", "ALICE"):
            with self.subTest(bogus=bogus):
                self.assertFalse(principal_matches(cert, bogus))

    def test_host_principal_uses_exact_hostname(self):
        cert = parse_certificate(
            build_cert(
                self.subject,
                self.ca,
                cert_type=SSH_CERT_TYPE_HOST,
                principals=["db.example.com"],
            )
        )
        self.assertTrue(principal_matches(cert, "db.example.com"))
        self.assertFalse(principal_matches(cert, "db.example.com.evil.com"))
        self.assertFalse(principal_matches(cert, "db"))

    def test_empty_principal_list_matches_any_identity(self):
        cert = parse_certificate(build_cert(self.subject, self.ca, principals=[]))
        self.assertTrue(principal_matches(cert, "anyone"))
        self.assertFalse(principal_matches(cert, ""))

    def test_validate_raises_on_principal_confusion(self):
        verifier = verifier_for(self.ca)
        cert = parse_certificate(build_cert(self.subject, self.ca, principals=["alice"]))
        with self.assertRaises(PrincipalMismatchError):
            validate_certificate(
                cert,
                verifier,
                expected_type=SSH_CERT_TYPE_USER,
                requested_principal="alice-admin",
            )


class CertificateTypeTests(unittest.TestCase):
    def setUp(self):
        self.ca, self.subject = ed25519_pair()
        self.verifier = verifier_for(self.ca)

    def test_user_cert_rejected_in_host_context(self):
        cert = parse_certificate(
            build_cert(self.subject, self.ca, cert_type=SSH_CERT_TYPE_USER)
        )
        with self.assertRaises(CertificateTypeError):
            validate_certificate(
                cert,
                self.verifier,
                expected_type=SSH_CERT_TYPE_HOST,
                requested_principal="alice",
            )

    def test_host_cert_rejected_in_user_context(self):
        cert = parse_certificate(
            build_cert(
                self.subject,
                self.ca,
                cert_type=SSH_CERT_TYPE_HOST,
                principals=["host.example.com"],
            )
        )
        with self.assertRaises(CertificateTypeError):
            validate_certificate(
                cert,
                self.verifier,
                expected_type=SSH_CERT_TYPE_USER,
                requested_principal="host.example.com",
            )


class ValidityWindowTests(unittest.TestCase):
    def setUp(self):
        self.ca, self.subject = ed25519_pair()

    def test_lower_bound_is_inclusive(self):
        cert = parse_certificate(
            build_cert(self.subject, self.ca, valid_after=100, valid_before=200)
        )
        self.assertTrue(is_within_validity(cert, now=100))

    def test_upper_bound_is_exclusive(self):
        cert = parse_certificate(
            build_cert(self.subject, self.ca, valid_after=100, valid_before=200)
        )
        self.assertTrue(is_within_validity(cert, now=199))
        self.assertFalse(is_within_validity(cert, now=200))

    def test_before_and_after_window_rejected(self):
        cert = parse_certificate(
            build_cert(self.subject, self.ca, valid_after=100, valid_before=200)
        )
        self.assertFalse(is_within_validity(cert, now=99))
        self.assertFalse(is_within_validity(cert, now=201))

    def test_forever_certificate_never_expires(self):
        cert = parse_certificate(
            build_cert(self.subject, self.ca, valid_after=0, valid_before=INFINITY)
        )
        self.assertTrue(is_within_validity(cert, now=10**12))

    def test_validate_raises_expired(self):
        verifier = verifier_for(self.ca)
        cert = parse_certificate(
            build_cert(self.subject, self.ca, valid_after=100, valid_before=200)
        )
        with self.assertRaises(CertificateExpiredError):
            validate_certificate(
                cert,
                verifier,
                expected_type=SSH_CERT_TYPE_USER,
                requested_principal="alice",
                now=200,
            )


class NonceTests(unittest.TestCase):
    def test_short_nonce_rejected(self):
        ca, subject = ed25519_pair()
        blob = build_cert(subject, ca, nonce=b"\x01" * 16)
        cert = parse_certificate(blob)
        verifier = verifier_for(ca)
        with self.assertRaises(WeakNonceError):
            validate_certificate(
                cert,
                verifier,
                expected_type=SSH_CERT_TYPE_USER,
                requested_principal="alice",
            )

    def test_minimum_length_nonce_accepted(self):
        ca, subject = ed25519_pair()
        blob = build_cert(subject, ca, nonce=b"\x02" * 32)
        cert = parse_certificate(blob)
        result = validate_certificate(
            cert,
            verifier_for(ca),
            expected_type=SSH_CERT_TYPE_USER,
            requested_principal="alice",
        )
        self.assertIsInstance(result, ValidationResult)


class RevocationTests(unittest.TestCase):
    def setUp(self):
        self.ca, self.subject = ed25519_pair()
        self.verifier = verifier_for(self.ca)

    def _cert(self, serial=7, key_id="alice-001"):
        return parse_certificate(
            build_cert(self.subject, self.ca, serial=serial, key_id=key_id)
        )

    def test_revoked_serial_rejected(self):
        cert = self._cert(serial=7)
        revocation = RevocationList()
        revocation.revoke_serial(7)
        with self.assertRaises(RevokedCertificateError):
            validate_certificate(
                cert,
                self.verifier,
                expected_type=SSH_CERT_TYPE_USER,
                requested_principal="alice",
                revocation_list=revocation,
            )

    def test_revoked_serial_range_rejected(self):
        cert = self._cert(serial=50)
        revocation = RevocationList()
        revocation.revoke_serial_range(40, 60)
        self.assertTrue(revocation.is_revoked(cert))
        self.assertFalse(RevocationList().is_revoked(cert))

    def test_revoked_key_id_rejected(self):
        cert = self._cert(key_id="leaked-key")
        revocation = RevocationList()
        revocation.revoke_key_id("leaked-key")
        with self.assertRaises(RevokedCertificateError):
            validate_certificate(
                cert,
                self.verifier,
                expected_type=SSH_CERT_TYPE_USER,
                requested_principal="alice",
                revocation_list=revocation,
            )

    def test_unrevoked_certificate_passes(self):
        cert = self._cert(serial=7)
        revocation = RevocationList()
        revocation.revoke_serial(8)
        result = validate_certificate(
            cert,
            self.verifier,
            expected_type=SSH_CERT_TYPE_USER,
            requested_principal="alice",
            revocation_list=revocation,
        )
        self.assertEqual(result.certificate.serial, 7)


class SourceAddressTests(unittest.TestCase):
    def setUp(self):
        self.ca, self.subject = ed25519_pair()

    def test_address_within_cidr_accepted(self):
        cert = parse_certificate(
            build_cert(
                self.subject,
                self.ca,
                critical_options=[("source-address", b"10.0.0.0/24,192.168.1.5")],
            )
        )
        self.assertTrue(source_addresses_permitted(cert, "10.0.0.7"))
        self.assertTrue(source_addresses_permitted(cert, "192.168.1.5"))

    def test_address_outside_cidr_rejected(self):
        cert = parse_certificate(
            build_cert(
                self.subject,
                self.ca,
                critical_options=[("source-address", b"10.0.0.0/24")],
            )
        )
        self.assertFalse(source_addresses_permitted(cert, "10.0.1.1"))
        self.assertFalse(source_addresses_permitted(cert, "8.8.8.8"))

    def test_missing_peer_address_fails_when_option_present(self):
        cert = parse_certificate(
            build_cert(
                self.subject,
                self.ca,
                critical_options=[("source-address", b"10.0.0.0/24")],
            )
        )
        self.assertFalse(source_addresses_permitted(cert, None))

    def test_no_option_allows_any_address(self):
        cert = parse_certificate(build_cert(self.subject, self.ca))
        self.assertTrue(source_addresses_permitted(cert, "8.8.8.8"))

    def test_validate_enforces_source_address(self):
        verifier = verifier_for(self.ca)
        cert = parse_certificate(
            build_cert(
                self.subject,
                self.ca,
                critical_options=[("source-address", b"10.0.0.0/24")],
            )
        )
        with self.assertRaises(SourceAddressError):
            validate_certificate(
                cert,
                verifier,
                expected_type=SSH_CERT_TYPE_USER,
                requested_principal="alice",
                peer_address="203.0.113.9",
            )

    def test_ipv6_source_address_matching(self):
        cert = parse_certificate(
            build_cert(
                self.subject,
                self.ca,
                critical_options=[("source-address", b"2001:db8::/32")],
            )
        )
        self.assertTrue(source_addresses_permitted(cert, "2001:db8::1"))
        self.assertFalse(source_addresses_permitted(cert, "2001:dead::1"))

    def test_invalid_cidr_entry_raises_critical_option_error(self):
        cert = parse_certificate(
            build_cert(
                self.subject,
                self.ca,
                critical_options=[("source-address", b"garbage")],
            )
        )
        with self.assertRaises(CriticalOptionError):
            source_addresses_permitted(cert, "10.0.0.1")


class ForceCommandTests(unittest.TestCase):
    def setUp(self):
        self.ca, self.subject = ed25519_pair()

    def test_force_command_is_returned_for_user_certificate(self):
        cert = parse_certificate(
            build_cert(
                self.subject,
                self.ca,
                critical_options=[("force-command", b"/usr/bin/uptime")],
            )
        )
        self.assertEqual(forced_command(cert), "/usr/bin/uptime")
        result = validate_certificate(
            cert,
            verifier_for(self.ca),
            expected_type=SSH_CERT_TYPE_USER,
            requested_principal="alice",
        )
        self.assertEqual(result.forced_command, "/usr/bin/uptime")

    def test_no_force_command_returns_none(self):
        cert = parse_certificate(build_cert(self.subject, self.ca))
        self.assertIsNone(forced_command(cert))

    def test_force_command_rejected_on_host_certificate(self):
        cert = parse_certificate(
            build_cert(
                self.subject,
                self.ca,
                cert_type=SSH_CERT_TYPE_HOST,
                principals=["host.example.com"],
                critical_options=[("force-command", b"/bin/sh")],
            )
        )
        with self.assertRaises(CriticalOptionError):
            validate_certificate(
                cert,
                verifier_for(self.ca),
                expected_type=SSH_CERT_TYPE_HOST,
                requested_principal="host.example.com",
            )

    def test_unknown_critical_option_refused(self):
        cert = parse_certificate(
            build_cert(
                self.subject,
                self.ca,
                critical_options=[("custom-restriction@example.com", b"x")],
            )
        )
        with self.assertRaises(CriticalOptionError):
            validate_certificate(
                cert,
                verifier_for(self.ca),
                expected_type=SSH_CERT_TYPE_USER,
                requested_principal="alice",
            )

    def test_force_command_and_source_address_enforced_together(self):
        cert = parse_certificate(
            build_cert(
                self.subject,
                self.ca,
                principals=["deploy"],
                critical_options=[
                    ("force-command", b"/usr/local/bin/deploy"),
                    ("source-address", b"10.1.0.0/16"),
                ],
            )
        )
        verifier = verifier_for(self.ca)
        allowed = validate_certificate(
            cert,
            verifier,
            expected_type=SSH_CERT_TYPE_USER,
            requested_principal="deploy",
            peer_address="10.1.2.3",
        )
        self.assertEqual(allowed.forced_command, "/usr/local/bin/deploy")
        with self.assertRaises(SourceAddressError):
            validate_certificate(
                cert,
                verifier,
                expected_type=SSH_CERT_TYPE_USER,
                requested_principal="deploy",
                peer_address="10.2.0.1",
            )


if __name__ == "__main__":
    unittest.main()
