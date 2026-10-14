import base64
import copy
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

    def test_entrypoints_are_string_arrays_not_shell_strings(self):
        with self.assertRaisesRegex(ValueError, "command"):
            validate_deployment_inputs({
                "deploymentId": "demo1",
                "applications": {
                    "reference-data": {
                        "image": f"registry.azurecr.io/reference@sha256:{'a' * 64}",
                        "command": "uvicorn actual:app",
                        "args": [],
                    },
                },
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
        targets = ["reference-data", "evidence-assessor", "release-reviewer", "candidate-planner", "briefing-author"]
        callers = ["operator"] + targets[1:]
        parameters = {
            "deploymentId": "demo1",
            "applications": {target: {
                "image": f"registry.azurecr.io/{target}@sha256:{'a' * 64}",
                "command": ["python", "-m", "actual_entrypoint"], "args": [],
            } for target in targets},
            "gatewayCertificates": metadata,
            "gatewayCertificatePfx": pfx,
            "contextKeys": {target: {"activeId": "current", "keys": {"current": f"context-{target}".ljust(64, "_")}} for target in targets},
            "callerKeys": {caller: {
                "primary": f"caller-{caller}-primary".ljust(64, "_"),
                "secondary": f"caller-{caller}-secondary".ljust(64, "_"),
            } for caller in callers},
            "modelCapacity": 120,
        }
        self.assertIsNone(validate_deployment_inputs(parameters))
        shared = copy.deepcopy(parameters)
        shared["contextKeys"]["reference-data"] = shared["contextKeys"]["evidence-assessor"]
        with self.assertRaisesRegex(ValueError, "isolated"):
            validate_deployment_inputs(shared)
        duplicate = copy.deepcopy(parameters)
        duplicate["callerKeys"]["operator"]["primary"] = duplicate["callerKeys"]["candidate-planner"]["primary"]
        with self.assertRaisesRegex(ValueError, "distinct"):
            validate_deployment_inputs(duplicate)


if __name__ == "__main__":
    unittest.main()
