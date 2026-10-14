import base64
import unittest
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from citadel.gateway.configuration import validate_deployment_inputs, validate_gateway_certificate


class InputTests(unittest.TestCase):
    def test_rejects_mutable_images_and_shell_entrypoint_omissions(self):
        with self.assertRaisesRegex(ValueError, "digest"):
            validate_deployment_inputs({
                "deploymentId": "demo1",
                "applications": {"reference-data": {"image": "registry.azurecr.io/reference:latest", "command": [], "args": []}},
            })

    def test_certificate_import_requires_real_matching_ninety_day_private_key_material(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unit-test-only")])
        now = datetime.now(timezone.utc).replace(microsecond=0)
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                       .public_key(key.public_key()).serial_number(1)
                       .not_valid_before(now - timedelta(minutes=1))
                       .not_valid_after(now - timedelta(minutes=1) + timedelta(days=90))
                       .sign(key, hashes.SHA256()))
        metadata = [{
            "sha256": certificate.fingerprint(hashes.SHA256()).hex(),
            "not_before": certificate.not_valid_before_utc.isoformat(),
            "not_after": certificate.not_valid_after_utc.isoformat(),
        }]
        pfx = base64.b64encode(pkcs12.serialize_key_and_certificates(
            b"test-only", key, certificate, None, serialization.NoEncryption(),
        )).decode()
        self.assertIsNone(validate_gateway_certificate(pfx, metadata))
        with self.assertRaisesRegex(ValueError, "allowlist"):
            validate_gateway_certificate(pfx, [dict(metadata[0], sha256="b" * 64)])
        with self.assertRaisesRegex(ValueError, "certificate"):
            validate_gateway_certificate("not-a-certificate", metadata)


if __name__ == "__main__":
    unittest.main()
