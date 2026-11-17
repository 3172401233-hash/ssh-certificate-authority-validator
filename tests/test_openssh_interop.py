import base64
import os
import shutil
import subprocess
import tempfile
import unittest

from ssh_cert_validator import (
    CAVerifier,
    SSH_CERT_TYPE_HOST,
    SSH_CERT_TYPE_USER,
    parse_certificate,
    validate_certificate,
)
from ssh_cert_validator.builder import CertificateBuilder
from ssh_cert_validator.wire import WireReader


def _ssh_keygen_available():
    return shutil.which("ssh-keygen") is not None


@unittest.skipUnless(_ssh_keygen_available(), "ssh-keygen not installed")
class OpenSSHInteropTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sshpatch-")
        self.old_cwd = os.getcwd()
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self.old_cwd)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, *args):
        subprocess.run(
            ["ssh-keygen", "-q", *args],
            check=True,
            capture_output=True,
        )

    def test_parses_real_user_certificate(self):
        self._run("-t", "ed25519", "-N", "", "-f", "ca")
        self._run("-t", "ed25519", "-N", "", "-f", "subject")
        self._run(
            "-s", "ca",
            "-I", "interop-key",
            "-n", "alice,admin",
            "-z", "3",
            "-V", "always:forever",
            "-O", "force-command=/usr/bin/id",
            "-O", "source-address=10.0.0.0/24",
            "subject.pub",
        )
        with open("subject-cert.pub") as handle:
            cert = parse_certificate(handle.read())
        self.assertEqual(cert.key_id, "interop-key")
        self.assertEqual(cert.serial, 3)
        self.assertEqual(cert.cert_type, SSH_CERT_TYPE_USER)
        self.assertEqual(cert.principals, ("alice", "admin"))
        self.assertEqual(
            cert.critical_option("force-command").data, b"/usr/bin/id"
        )
        self.assertEqual(
            cert.critical_option("source-address").data, b"10.0.0.0/24"
        )
        with open("ca.pub") as handle:
            verifier = CAVerifier.from_public_keys([handle.read()])
        result = validate_certificate(
            cert,
            verifier,
            expected_type=SSH_CERT_TYPE_USER,
            requested_principal="admin",
            peer_address="10.0.0.9",
        )
        self.assertEqual(result.forced_command, "/usr/bin/id")

    def test_parses_real_host_certificate(self):
        self._run("-t", "ed25519", "-N", "", "-f", "host_ca")
        self._run("-t", "ed25519", "-N", "", "-f", "host")
        self._run(
            "-s", "host_ca", "-I", "host-id", "-h",
            "-n", "db.example.com", "-V", "always:forever", "host.pub",
        )
        with open("host-cert.pub") as handle:
            cert = parse_certificate(handle.read())
        self.assertEqual(cert.cert_type, SSH_CERT_TYPE_HOST)
        self.assertEqual(cert.principals, ("db.example.com",))
        with open("host_ca.pub") as handle:
            CAVerifier.from_public_keys([handle.read()]).verify(cert)

    def test_builder_output_is_accepted_by_ssh_keygen(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519

        ca = ed25519.Ed25519PrivateKey.generate()
        subject = ed25519.Ed25519PrivateKey.generate()
        blob = (
            CertificateBuilder(subject.public_key(), ca)
            .set_key_id("py-built")
            .set_serial(11)
            .set_principals(["alice"])
            .add_extension("permit-pty")
            .build()
        )
        head = WireReader(blob).string()
        with open("py-cert.pub", "wb") as handle:
            handle.write(head + b" " + base64.b64encode(blob) + b"\n")
        # ssh-keygen -L returns non-zero on any structural corruption.
        subprocess.run(
            ["ssh-keygen", "-L", "-f", "py-cert.pub"],
            check=True,
            capture_output=True,
        )


if __name__ == "__main__":
    unittest.main()
