import hashlib
import time
import unittest

from citadel.acceptance.storage_probes import StorageProbe, storage_target, evaluate_storage
from citadel.operations import OperationError
from tests.runtime.test_storage import BlobResponse, BlobTransport, FixtureCredential


DATA = b'{"kind":"disposable-known-target"}'
HASH = hashlib.sha256(DATA).hexdigest()
PRINCIPAL = "11111111-1111-1111-1111-111111111111"


class Credential(FixtureCredential):
    def __init__(self):
        self.scopes = []

    async def get_token(self, *scopes, **kwargs):
        self.scopes.append(scopes)
        return await super().get_token(*scopes, **kwargs)


class Response(BlobResponse):
    async def read(self):
        return self.content


class StorageTransport(BlobTransport):
    def __init__(self):
        super().__init__(None)
        self.forbidden = True
        self.data = DATA

    async def send(self, request, **kwargs):
        self.requests.append(request)
        denied = "/drafts/" in request.url and self.forbidden
        content = (b"<Error><Code>AuthorizationPermissionMismatch</Code><Message>Denied</Message></Error>"
                   if denied else self.data)
        response = Response(request, content)
        response.headers["x-ms-request-id"] = f"service-{len(self.requests)}"
        if denied:
            response.status_code, response.reason = 403, "Forbidden"
            response.headers["x-ms-error-code"] = "AuthorizationPermissionMismatch"
            response.content_type = "application/xml"
        elif request.method == "PUT":
            response.status_code, response.reason = 201, "Created"
            self.data = request.body
        return response


class StorageProbeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.transport, self.credential, self.admissions = StorageTransport(), Credential(), 0

    async def admit(self):
        self.admissions += 1

    def probe(self, **changes):
        options = dict(account="https://allocated.blob.core.windows.net",
            credential=self.credential, workload="candidate-planner", principal_id=PRINCIPAL,
            enabled=True, run_id="probe1", suite_id="suite1",
            deadline=time.time() + 120, admit=self.admit,
            transport=self.transport)
        return StorageProbe(**(options | changes))

    async def test_actual_sdk_wire_denials_preserve_service_ids_and_assigned_token_scope(self):
        probe = self.probe()
        for action in ("read", "write"):
            result = await probe.observe("drafts", action, {"sha256": HASH, "etag": '"verified-fixture"'})
            self.assertEqual(result["status_code"], 403)
            self.assertEqual(result["reason"], "AuthorizationPermissionMismatch")
            self.assertEqual(result["runtime_identity"], hashlib.sha256(PRINCIPAL.encode()).hexdigest())
            self.assertEqual(result["request_id"], f"service-{self.admissions}")
            self.assertEqual(result["target"], hashlib.sha256(
                self.transport.requests[-1].url.split("?", 1)[0].encode()).hexdigest())
        self.assertEqual(self.admissions, 2)
        self.assertEqual([r.method for r in self.transport.requests], ["GET", "PUT"])
        self.assertTrue(all("/drafts/acceptance/suite1/storage-boundary-v1.json" in r.url
                            for r in self.transport.requests))
        self.assertTrue(all(r.headers["x-ms-version"] == "2026-10-06" for r in self.transport.requests))
        self.assertEqual(set(self.credential.scopes), {("https://storage.azure.com/.default",)})
        self.assertEqual(self.transport.data, DATA)

    async def test_permitted_read_and_conditional_write_use_known_bytes_not_fake_success(self):
        probe = self.probe()
        read = await probe.observe("planner-operations", "read",
                                   {"sha256": HASH, "etag": '"verified-fixture"'})
        write = await probe.observe("planner-operations", "write",
                                    {"sha256": HASH, "etag": '"verified-fixture"'})
        self.assertEqual(read["sha256"], HASH)
        self.assertEqual(write["status_code"], 201)
        self.assertEqual(self.transport.requests[-1].headers["If-Match"], '"verified-fixture"')
        self.assertEqual(self.transport.data, DATA)
        self.assertNotIn("disposable-known-target", str(read) + str(write))

    async def test_fixed_targets_deadline_and_normal_mode_cannot_be_bypassed(self):
        with self.assertRaises(ValueError):
            self.probe(enabled=False)
        with self.assertRaises((ValueError, OperationError)):
            storage_target("../other")
        probe = self.probe()
        with self.assertRaises(ValueError):
            await probe.observe("arbitrary", "read", {})
        probe.deadline = time.time() - 1
        with self.assertRaises(OperationError):
            await probe.observe("drafts", "read", {"sha256": HASH, "etag": '"v1"'})
        self.assertEqual(self.transport.requests, [])

    def test_missing_working_control_or_changed_target_cannot_pass(self):
        result = evaluate_storage({}, {}, {}, [], {})
        self.assertEqual(result["status"], "blocked")

    def test_oracle_binds_actual_service_target_identity_method_and_control(self):
        identities = {"candidate-planner": "a" * 64, "evidence-assessor": "b" * 64, "operator": "c" * 64}
        base = {"container": "drafts", "suite_id": "suite1", "target": "d" * 64,
                "started": 100.0, "finished": 101.0, "action": "read", "sha256": HASH, "count": 1}
        observation = base | {"check_id": "storage.candidate-planner.drafts.read",
            "caller": "candidate-planner", "runtime_identity": "a" * 64,
            "run_id": "probe1", "operation_id": "op1", "request_id": "denial",
            "status_code": 403, "reason": "AuthorizationPermissionMismatch"}
        control = base | {"caller": "evidence-assessor", "runtime_identity": "b" * 64,
            "run_id": "control1", "operation_id": "controlop1", "request_id": "control", "status_code": 206}
        snapshots = {name: base | {"request_id": name, "operation_id": name + "-op", "status_code": 206}
                     for name in ("before", "after")}
        snapshots["before"].update(started=98.0, finished=99.0)
        snapshots["after"].update(started=102.0, finished=103.0)
        evidence = []
        for record, actor in ((observation, "candidate-planner"), (control, "evidence-assessor"),
                              (snapshots["before"], "operator"), (snapshots["after"], "operator")):
            evidence.append(record | {"source": "storage", "method": "GetBlob", "observed": 100.5,
                                      "client_request_id": record["operation_id"],
                                      "runtime_identity": identities[actor]})
            if actor != "operator":
                evidence.append(record | {"source": "application", "method": "storage.read", "observed": 100.5})
        self.assertEqual(evaluate_storage(observation, control, snapshots, evidence, identities)["status"], "pass")
        for field, value in (("target", "e" * 64), ("runtime_identity", "f" * 64),
                             ("method", "PutBlob"), ("request_id", "unrelated")):
            changed = [e | {field: value} if e["request_id"] == "denial" else e for e in evidence]
            self.assertEqual(evaluate_storage(observation, control, snapshots, changed, identities)["status"], "blocked")
        changed = [e | {"run_id": "different"} if e["source"] == "application" else e for e in evidence]
        self.assertEqual(evaluate_storage(observation, control, snapshots, changed, identities)["status"], "blocked")
        altered = snapshots | {"after": snapshots["after"] | {"sha256": "e" * 64}}
        self.assertEqual(evaluate_storage(observation, control, altered, evidence, identities)["status"], "fail")
        reordered = snapshots | {"after": snapshots["after"] | {"started": 99.0, "finished": 100.0}}
        self.assertEqual(evaluate_storage(observation, control, reordered, evidence, identities)["status"], "blocked")
        for action, status in (("write", 201), ("read", 403)):
            altered = snapshots | {"after": snapshots["after"] | {"action": action, "status_code": status}}
            changed = [e | {"method": "PutBlob" if action == "write" else "GetBlob",
                            "status_code": status} if e["request_id"] == "after" else e for e in evidence]
            self.assertEqual(evaluate_storage(observation, control, altered, changed, identities)["status"], "blocked")
        unexpected = observation | {"status_code": 200}
        changed = [e | {"status_code": 200} if e["request_id"] == "denial" else e for e in evidence]
        self.assertEqual(evaluate_storage(unexpected, {}, {}, changed, identities)["status"], "fail")
        self.assertEqual(evaluate_storage(unexpected, {}, {}, [], identities)["status"], "blocked")
