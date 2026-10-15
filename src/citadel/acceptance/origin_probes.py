"""Fixed read-only origin probes; no exported gateway certificate or caller key."""

import asyncio
import base64
import hashlib
import math
import os
import ssl
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from citadel.gateway.trust import INVOCATION_CALLERS
from citadel.operations import OperationError, identity
from citadel.runtime.configuration import endpoint
from .oracle import hash_value
from .telemetry import correlate, emit, opaque


MODES = ("missing-certificate", "unrelated-certificate", "forged-context")


@contextmanager
def unrelated_certificate():
    """Ephemeral unrelated key, never the gateway key; private files always removed."""
    directory = Path(".build") / ("acceptance-certificate-" + uuid4().hex)
    directory.parent.mkdir(mode=0o700, exist_ok=True)
    directory.mkdir(mode=0o700)
    keyfile, certfile = directory / "key.pem", directory / "certificate.pem"
    try:
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unrelated-acceptance")])
        now = datetime.now(timezone.utc)
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .sign(key, hashes.SHA256()))
        for path, content in (
            (keyfile, key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption())),
            (certfile, certificate.public_bytes(serialization.Encoding.PEM)),
        ):
            with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
                stream.write(content)
        context = ssl.create_default_context()
        context.load_cert_chain(certfile, keyfile)
        yield context, certificate.fingerprint(hashes.SHA256()).hex()
    finally:
        keyfile.unlink(missing_ok=True)
        certfile.unlink(missing_ok=True)
        directory.rmdir()


class OriginProbe:
    def __init__(self, *, workload, origin, principal_id, approved_certificate, key_id,
                 enabled, run_id, deadline, admit, client_factory=None):
        if (enabled is not True or workload not in INVOCATION_CALLERS
                or not hash_value(approved_certificate) or not callable(admit)
                or type(deadline) not in (int, float) or not math.isfinite(deadline)
                or not time.time() < deadline <= time.time() + 900):
            raise ValueError("An explicitly enabled, allocated and bounded origin probe is required")
        self.origin = endpoint(origin, ".azurecontainerapps.io")
        self.workload, self.run_id = workload, identity(run_id)
        self.principal = hashlib.sha256(str(UUID(principal_id)).encode()).hexdigest()
        self.pin, self.key_id = approved_certificate, identity(key_id)
        self.deadline, self.admit, self.client = deadline, admit, client_factory or httpx.AsyncClient

    async def observe(self, mode):
        if mode not in MODES:
            raise ValueError("Only fixed origin authorization probes are permitted")
        if time.time() >= self.deadline:
            raise OperationError("deadline", "Origin dispatch after deadline refused")
        await self.admit()
        if mode == "missing-certificate":
            return await self._exchange(mode, ssl.create_default_context(), None)
        with unrelated_certificate() as (context, fingerprint):
            if fingerprint == self.pin:
                raise ValueError("The probe certificate must not be a trusted gateway certificate")
            return await self._exchange(mode, context, fingerprint)

    async def _exchange(self, mode, context, fingerprint):
        if time.time() >= self.deadline:
            raise OperationError("deadline", "Origin dispatch after admission deadline refused")
        operation = uuid4().hex
        path = "/mcp" if self.workload == "reference-data" else "/.well-known/agent-card.json"
        payload = ({"jsonrpc": "2.0", "id": operation, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "citadel-acceptance", "version": "1"}}}
            if self.workload == "reference-data" else None)
        headers = {"Accept": "application/json, text/event-stream"}
        if mode == "forged-context":
            headers.update({
                "x-forwarded-client-cert": "Hash=" + self.pin,
                "x-citadel-key-id": self.key_id,
                "x-citadel-timestamp": str(int(time.time())),
                "x-citadel-request-id": uuid4().hex,
                "x-citadel-caller": sorted(INVOCATION_CALLERS[self.workload])[0],
                "x-citadel-target": self.workload,
                "x-citadel-signature": base64.b64encode(bytes(32)).decode(),
            })
        result = {"check_id": f"origin.{self.workload}.{mode}", "run_id": self.run_id,
            "operation_id": operation, "caller": self.workload, "runtime_identity": self.principal,
            "target": hashlib.sha256((self.origin + path).encode()).hexdigest(),
            "started": time.time(), "status": "blocked", "reason": "independent_origin_proof_required"}
        if fingerprint is not None:
            result["certificate_sha256"] = fingerprint
        try:
            async with self.client(verify=context, timeout=30, follow_redirects=False,
                                   trust_env=False) as client:
                async with asyncio.timeout(max(0, min(30, self.deadline - time.time()))):
                    response = await client.request("POST" if payload else "GET", self.origin + path,
                                                    headers=headers, json=payload)
            request_id = (response.headers.get("x-citadel-origin-request-id")
                          or response.headers.get("x-ms-request-id") or response.headers.get("x-azure-ref"))
            result["status_code"] = response.status_code
            if request_id:
                result["request_id"] = opaque(request_id)
            with correlate(self.run_id, operation, self.workload):
                emit("probe", request_id=result.get("request_id"), status_code=response.status_code,
                     target=result["target"])
        except (httpx.HTTPError, TimeoutError, ValueError):
            # Transport failure alone is not proof of authorization denial.
            result["reason"] = "origin_transport_or_response_unverified"
        result["finished"] = time.time()
        return result


def evaluate_origin(observation, control, snapshots, evidence, *,
                    runtime_identity, observer_identity, subscription_id):
    from .storage_probes import _correlated
    blocked = {"check_id": observation.get("check_id"), "status": "blocked",
               "reason": "origin_service_control_or_no_effect_proof_missing"}
    actor = observation.get("caller")
    if (not isinstance(actor, str) or actor not in INVOCATION_CALLERS or not hash_value(runtime_identity)
            or observation.get("runtime_identity") != runtime_identity
            or observation.get("check_id") not in {f"origin.{actor}.{mode}" for mode in MODES}
            or not isinstance(observation.get("operation_id"), str)
            or not isinstance(observation.get("run_id"), str)
            or not hash_value(observation.get("target"))):
        return blocked

    def matches(record, source, **fields):
        if (not isinstance(record.get("request_id"), str) or not record["request_id"]
                or type(record.get("status_code")) is not int
                or any(type(record.get(key)) not in (int, float) or not math.isfinite(record[key])
                       for key in ("started", "finished"))
                or not 0 <= record["finished"] - record["started"] <= 900):
            return False
        return any(row.get("source") == source and row.get("request_id") == record["request_id"]
                   and row.get("status_code") == record["status_code"]
                   and type(row.get("observed")) in (int, float)
                   and record["started"] - 5 <= row["observed"] <= record["finished"] + 5
                   and all(row.get(key) == value for key, value in fields.items()) for row in evidence)

    if not matches(observation, "application", method="probe", runtime_identity=runtime_identity,
                   run_id=observation.get("run_id"), operation_id=observation.get("operation_id"),
                   caller=actor, target=observation["target"]):
        return blocked
    if 200 <= observation["status_code"] < 300:
        return blocked | {"status": "fail", "reason": "unauthorized_origin_succeeded"}
    if observation["status_code"] not in (401, 403):
        return blocked
    rejection = [row for row in evidence if row.get("method") == "authorization.denied"
                 and isinstance(row.get("facts"), dict)
                 and row["facts"].get("business_state") == "not_dispatched"
                 and row["facts"].get("reason") in (
                     "certificate_required", "certificate_rejected", "invalid_gateway_context")]
    if not any(matches(observation, "application", method="authorization.denied",
                       runtime_identity=runtime_identity, facts=row["facts"]) for row in rejection):
        return blocked
    capability = "initialize" if actor == "reference-data" else "discovery"
    caller = control.get("caller")
    if (not isinstance(caller, str) or caller not in INVOCATION_CALLERS[actor] or control.get("status_code") != 200
            or control.get("status") == "blocked"
            or control.get("check_id") != f"route.{caller}.{actor}.{capability}"
            or capability == "discovery" and control.get("actual") != "gateway_card"
            or control.get("request_id") == observation["request_id"]
            or not isinstance(subscription_id, str) or not subscription_id.endswith("/" + caller)
            or not matches(control, "application", method=capability,
                           runtime_identity=runtime_identity, caller=caller)
            or not any(matches(control, "gateway", caller=value)
                       for value in (subscription_id, caller))):
        return blocked
    if (max(observation["finished"], control["finished"])
            - min(observation["started"], control["started"]) > 900):
        return blocked
    for container in ("drafts", "findings"):
        before, after = (snapshots.get(side, {}).get(container, {}) for side in ("before", "after"))
        for record in (before, after):
            if (record.get("container") != container or record.get("action") != "read"
                    or record.get("status_code") not in (200, 206)
                    or type(record.get("count")) is not int or record["count"] < 0
                    or not hash_value(record.get("sha256"))
                    or not _correlated(record, evidence, observer_identity)):
                return blocked
        if (before.get("target") != after.get("target") or not before.get("suite_id")
                or before["suite_id"] != after.get("suite_id")
                or before["finished"] > observation["started"] or after["started"] < observation["finished"]):
            return blocked
        if before["sha256"] != after["sha256"] or before["count"] != after["count"]:
            return blocked | {"status": "fail", "reason": "origin_probe_changed_business_products"}
    return blocked | {"status": "pass", "reason": "verified_origin_authorization_and_no_effect"}
