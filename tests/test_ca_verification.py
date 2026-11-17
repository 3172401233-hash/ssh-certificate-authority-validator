import unittest

from cryptography.hazmat.primitives.asymmetric import ec

from ssh_cert_validator import (
    CAVerifier,
    VerificationError,
    parse_certificate,
)

from ._helpers import (
    build_cert,
    ecdsa_pair,
    ed25519_pair,
    rsa_pair,
    verifier_for,
)


class CAVerificationTests(unittest.TestCase):
    def test_ed25519_signature_verifies(self):
        ca, subject = ed25519_pair()
        cert = parse_certificate(build_cert(subject, ca))
        verifier_for(ca).verify(cert)
        self.assertTrue(verifier_for(ca).is_valid(cert))

    def test_ecdsa_signature_verifies_on_all_curves(self):
        for curve in (ec.SECP256R1, ec.SECP384R1, ec.SECP521R1):
            with self.subTest(curve=curve.__name__):
                ca, subject = ecdsa_pair(curve)
                cert = parse_certificate(build_cert(subject, ca))
                verifier_for(ca).verify(cert)

    def test_rsa_sha512_signature_verifies(self):
        ca, subject = rsa_pair()
        cert = parse_certificate(build_cert(subject, ca))
        self.assertEqual(cert.signature.algorithm, "rsa-sha2-512")
        verifier_for(ca).verify(cert)

    def test_wrong_ca_is_rejected(self):
        signing_ca, subject = ed25519_pair()
        other_ca, _ = ed25519_pair()
        cert = parse_certificate(build_cert(subject, signing_ca))
        verifier = verifier_for(other_ca)
        self.assertFalse(verifier.trusts(cert))
        with self.assertRaises(VerificationError):
            verifier.verify(cert)

    def test_tampered_signed_region_is_rejected(self):
        ca, subject = ed25519_pair()
        blob = bytearray(build_cert(subject, ca, key_id="original"))
        # Flip a byte inside the key id, which is part of the signed region.
        blob[124] ^= 0x01
        cert = parse_certificate(bytes(blob))
        with self.assertRaises(VerificationError):
            verifier_for(ca).verify(cert)

    def test_empty_trust_store_rejects_everything(self):
        ca, subject = ed25519_pair()
        cert = parse_certificate(build_cert(subject, ca))
        with self.assertRaises(VerificationError):
            CAVerifier().verify(cert)

    def test_multiple_trusted_cas(self):
        ca_one, subject_one = ed25519_pair()
        ca_two, subject_two = ed25519_pair()
        cert_one = parse_certificate(build_cert(subject_one, ca_one))
        cert_two = parse_certificate(build_cert(subject_two, ca_two))
        verifier = CAVerifier()
        verifier.add(verifier_for(ca_one).trusted_ca(cert_one))
        verifier.add(verifier_for(ca_two).trusted_ca(cert_two))
        verifier.verify(cert_one)
        verifier.verify(cert_two)

    def test_cross_algorithm_ca_and_subject(self):
        rsa_ca, _ = rsa_pair()
        _, ed_subject = ed25519_pair()
        cert = parse_certificate(build_cert(ed_subject, rsa_ca))
        verifier_for(rsa_ca).verify(cert)


if __name__ == "__main__":
    unittest.main()
