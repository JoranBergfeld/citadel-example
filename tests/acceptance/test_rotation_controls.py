import copy
import asyncio
import hashlib
import io
import json
import os
import time
import unittest
from types import SimpleNamespace
from pathlib import Path
from uuid import uuid4
from unittest.mock import patch

import httpx

from citadel.acceptance.worker import validate_request
from citadel.acceptance.proof_gate import evaluate_check
from citadel.acceptance.reports import sanitize
from citadel.evidence.manifests import sha256


def proof_fixture(kind="subscription", *, actor="candidate-planner", backend="evidence-assessor"):
    run = "rotation-control"
    identities = dict(zip(("candidate-planner", "evidence-assessor", "release-reviewer",
        "briefing-author", "reference-data"), (value * 64 for value in "abcde")))
    target, observer = "7" * 64, "f" * 64
    rows, evidence = [], []
    check_id = "rotation." + kind + "-allowed-and-revoked"
    for index, status in enumerate((200, 401 if kind == "subscription" else 403, 200)):
        row = {"check_id": check_id, "run_id": run, "operation_id": "probe" + str(index),
            "caller": actor, "runtime_identity": identities[actor], "target": target,
            "request_id": "gateway" + str(index), "origin_request_id": "origin-denied" if index == 1 else None,
            "status_code": status, "started": 110 + index * 10, "finished": 111 + index * 10,
            "credential_sha256": ("2" if index == 1 and kind == "subscription" else "1") * 64,
            "actual": "read_only_control" if status == 200 else "unverified_response"}
        rows.append(row)
        evidence.append(row | {"source": "gateway", "method": "GET", "observed": row["finished"],
            "credential_sha256": "8" * 64 if status == 200 or kind != "subscription" else None,
            "facts": {"backend_dispatched": status != 401, "backend_status": status if status != 401 else 0,
                      "reason": "SubscriptionKeyInvalid" if status == 401 else ""}})
        evidence.append(row | {"source": "application", "method": "rotation.probe",
            "observed": row["finished"], "facts": {"sha256": sha256(row), "probe_id": check_id}})
        if status == 200:
            evidence.append(row | {"source": "application", "method": "findings-read" if actor == "briefing-author" else "discovery",
                "runtime_identity": identities[backend], "observed": row["finished"]})
        elif kind != "subscription":
            evidence.append(row | {"source": "application", "method": "authorization.denied",
                "request_id": "origin-denied", "runtime_identity": identities[backend], "observed": row["finished"],
                "facts": {"reason": "certificate_rejected" if kind == "certificate" else "invalid_gateway_context",
                          "business_state": "not_dispatched"}})
    snapshots = {}
    for side, started in (("before", 115), ("after", 135)):
        snapshots[side] = []
        for container in ("planner-operations", "assessor-operations", "reviewer-operations",
                          "author-operations", "drafts", "findings"):
            row = {"suite_id": "suite", "operation_id": side + container, "caller": "operator",
                "action": "read", "container": container, "target": sha256(container),
                "request_id": side + container, "status_code": 206,
                "started": started, "finished": started + 1, "sha256": "3" * 64, "count": 1,
                "runtime_identity": observer}
            snapshots[side].append(row)
            evidence.append(row | {"source": "storage", "method": "GetBlob",
                "client_request_id": row["operation_id"], "observed": started + 1})
    actual = {"run_id": run, "name": backend, "caller": actor, "observations": rows,
        "before_sha256": "4" * 64, "after_sha256": "4" * 64, "state": "restored", **snapshots}
    report = {"run_id": "suite", "runtime_identities": identities,
        "operation_ids": [run, *[row["operation_id"] for row in rows],
                          *[row["operation_id"] for side in snapshots.values() for row in side]],
        "storage_targets": {row["container"]: row["target"] for row in snapshots["before"]},
        "subscription_bindings": {actor: "8" * 64}, "evidence": evidence}
    return {"check_id": check_id, "expected": "evidence", "actual": actual}, report


class RotationControlTests(unittest.TestCase):
    def test_exported_author_rotation_requires_real_finding_reads_not_forbidden_discovery(self):
        check, report = proof_fixture(actor="briefing-author", backend="release-reviewer")
        self.assertEqual(evaluate_check(sanitize(check), sanitize(report))["status"], "pass")
        for row in report["evidence"]:
            if row.get("method") == "findings-read":
                row["method"] = "discovery"
        self.assertEqual(evaluate_check(sanitize(check), sanitize(report))["status"], "blocked")

    def test_embedded_rotations_spend_the_parent_collection_allowance_even_after_missing_queries(self):
        from contextlib import contextmanager
        from citadel.acceptance.rotation_harness import RotationAcceptance
        from citadel.acceptance.collection import collection_remaining
        from citadel.operator.state import Blocked, write_private
        directory = Path(".build") / ("rotation-shared-" + uuid4().hex)
        directory.mkdir(mode=0o700)
        clock, queries = [1000.0], []
        parent = {"run_id": "suite", "collection_windows": {"prior": {"started": 100, "finished": 300}}}

        class Native:
            def rest(self, *args):
                return {"properties": {"customerId": "11111111-1111-1111-1111-111111111111"}}

            @contextmanager
            def document(self, body):
                yield "query.json"

            def az(self, *args, **options):
                queries.append(options["timeout"])
                clock[0] += 200
                raise Blocked("fixture_query_unavailable")

        lifecycle = SimpleNamespace(native=Native(), state=SimpleNamespace(directory=directory, save=lambda: None),
            value={"runs": {}, "acceptance_attempts": {"suite": parent}, "rotation_controls": {},
                "inventory": ["/owned/Microsoft.OperationalInsights/workspaces/owned"]})
        try:
            with patch("time.time", lambda: clock[0]):
                for run in ("subscription", "certificate", "context"):
                    write_private(directory / "rotation.json", {"run_id": run, "kind": "subscription",
                        "target": "candidate-planner", "phase": "staged", "acceptance_run_id": "suite"})
                    lifecycle.value["runs"] = {run: {"state": "control_intent"}}
                    lifecycle.value["rotation_controls"][run] = {
                        "fingerprint": "a" * 64, "acceptance_run_id": "suite", "new": {"state": "observed"},
                        "read_attempts": 0, "deadline": 1900, "started": 900, "evidence": []}
                    with self.assertRaises(Blocked):
                        RotationAcceptance(lifecycle).control("new", run,
                            fingerprints={"fingerprint": "a" * 64}, directory=directory)
                self.assertEqual(len(queries), 2, "Third rotation must not receive a new 600-second allowance")
                self.assertEqual(collection_remaining(parent, clock[0]), 0)
        finally:
            for file in directory.iterdir():
                file.unlink()
            directory.rmdir()

    def test_retired_stage_can_collect_existing_verified_current_control_without_replaying_it(self):
        from citadel.acceptance.rotation_harness import RotationAcceptance
        from citadel.operator.state import Blocked, write_private
        directory = Path(".build") / ("rotation-resume-" + uuid4().hex)
        directory.mkdir(mode=0o700)
        write_private(directory / "rotation.json", {"run_id": "owned", "kind": "subscription",
            "target": "candidate-planner", "phase": "retired"})
        record = {"fingerprint": "a" * 64, "new": {"state": "verified"}, "old": {"state": "observed"},
                  "read_attempts": 0, "deadline": time.time() + 900}
        lifecycle = SimpleNamespace(native=SimpleNamespace(), state=SimpleNamespace(
            directory=directory, save=lambda: None), value={"runs": {"owned": {"state": "control_intent"}},
                "rotation_controls": {"owned": record}, "inventory": []})
        try:
            with self.assertRaises(Blocked) as caught:
                RotationAcceptance(lifecycle).control("new", "owned", fingerprints={"fingerprint": "a" * 64},
                                                       directory=directory)
            self.assertEqual(caught.exception.code, "exact_rotation_workspace_required")
            self.assertNotIn("observations", record, "A verified current request must not be dispatched again")
        finally:
            for file in directory.iterdir():
                file.unlink()
            directory.rmdir()

    def test_pending_observation_only_allows_matching_finalization_not_other_control_changes(self):
        from citadel.operator.rotation import rotate_command
        from citadel.operator.state import Blocked, write_private
        directory = Path(".build") / ("rotation-exclusion-" + uuid4().hex)
        directory.mkdir(mode=0o700)
        pending = {"run_id": "owned", "kind": "context", "target": "evidence-assessor",
                   "selector_intent": {"state": "restored"}}
        write_private(directory / "rotation.json", pending)

        def prohibited():
            raise AssertionError("Pending proof cannot authorize unrelated changes")

        lifecycle = SimpleNamespace(state=SimpleNamespace(directory=directory), inventory=prohibited,
            value={"phase": "deployed_unverified", "runs": {"owned": {"state": "control_intent"}},
                "rotation_controls": {"owned": {"new": {"state": "verified"}, "old": {"state": "observed"}}}})
        try:
            with self.assertRaises(Blocked):
                rotate_command(lifecycle, SimpleNamespace(command="revoke", caller="operator"))
        finally:
            for file in directory.iterdir():
                file.unlink()
            directory.rmdir()

    def test_certificate_version_capture_reads_metadata_only_never_exports_platform_private_material(self):
        from citadel.acceptance.rotation_harness import capture_retired_secret
        identifier = "https://platform.vault.azure.net/secrets/gateway-certificate/" + "1" * 32

        class Native:
            def az(self, *args):
                if args[:3] != ("keyvault", "secret", "list-versions"):
                    raise AssertionError("Platform private material must stay inside APIM/Key Vault")
                return [{"id": identifier, "attributes": {"enabled": True, "created": 100}}]

        lifecycle = SimpleNamespace(native=Native(), value={"outputs": {"inventory": {"platform": {
            "resources": ["/owned/providers/Microsoft.KeyVault/vaults/platform"]}}}})
        self.assertEqual(capture_retired_secret(lifecycle, "certificate", None, {}), identifier)

    def test_prepare_captures_actual_owned_secret_version_before_existing_lifecycle_reconciliation(self):
        from citadel.operator.rotation import rotate_command
        from citadel.operator.state import read_private
        directory = Path(".build") / ("rotation-prepare-" + uuid4().hex)
        directory.mkdir(mode=0o700)
        calls = []
        credentials = {"callerKeys": {"candidate-planner": {"primary": "allocated-original-key",
            "secondary": "allocated-secondary-key"}}, "callerStates": {"candidate-planner": "active"}}
        app = "/subscriptions/fixture/resourceGroups/planning/providers/Microsoft.App/containerApps/sample-candidate-planner"

        class Native:
            def rest(self, method, resource, api, body=None):
                calls.append((method, resource))
                if (method, resource) == ("get", app):
                    return {"properties": {"template": {"containers": [{"env": [
                        {"name": "CITADEL_VAULT_URL", "value": "https://planning.vault.azure.net"},
                        {"name": "CITADEL_SUBSCRIPTION_SECRET_NAME", "value": "candidate-gateway-key"}]}]}}}
                raise AssertionError((method, resource))

            def az(self, *args):
                calls.append(args)
                if args[:3] == ("keyvault", "secret", "show"):
                    self_test.assertIn("candidate-gateway-key", args)
                    return {"value": "allocated-original-key",
                            "id": "https://planning.vault.azure.net/secrets/candidate-gateway-key/" + "1" * 32}
                if args[:3] == ("containerapp", "revision", "list"):
                    return [{"name": "normal", "properties": {"active": True}}]
                if args[:3] == ("containerapp", "revision", "restart"):
                    return {}
                raise AssertionError(args)

        self_test = self
        lifecycle = SimpleNamespace(id="sample", native=Native(), config={"subscriptionId": "allocated"},
            value={"phase": "deployed_unverified", "runs": {}, "outputs": {"appInventory": [{"app": app}]}},
            credentials=lambda: copy.deepcopy(credentials), inventory=lambda: None,
            state=SimpleNamespace(directory=directory, event=lambda *args: None),
            arm=lambda *args, **kwargs: {}, capture_outputs=lambda *args: None)
        try:
            result = rotate_command(lifecycle, SimpleNamespace(command="rotate", kind="subscription",
                                                              target="candidate-planner", stage="prepare"))
            self.assertEqual(result["status"], "rotation_staged")
            pending = read_private(directory / "rotation.json")
            self.assertTrue(pending["old_secret_id"].endswith("/" + "1" * 32))
            self.assertEqual(pending["old"]["callerKeys"]["candidate-planner"]["primary"], "allocated-original-key")
        finally:
            for file in directory.iterdir():
                file.unlink()
            directory.rmdir()

    def test_context_control_changes_only_owned_signer_not_backend_trust_and_restores_policy(self):
        import base64
        from citadel.acceptance.rotation_selector import RetiredSigner
        from citadel.operator.state import ROOT
        named, policy = "/owned/apim/namedValues/context-evidence-assessor", "/owned/apim/apis/evidence-assessor/policies/policy"
        xml = (ROOT / "infra/policies/workload.xml").read_text().replace("__TARGET__", "evidence-assessor"
            ).replace("__KEY_ID__", "current-key").replace("__CALLERS__", "&quot;candidate-planner&quot;")
        original = {named: {"displayName": "context-evidence-assessor", "secret": True},
                    policy: {"format": "rawxml", "value": xml}}
        values = copy.deepcopy(original)
        secret = base64.b64encode(b"current-secret-material-0000000000").decode()
        writes = []

        class Native:
            def rest(self, method, resource, api, body=None):
                nonlocal secret
                if method == "get" and resource in values:
                    return {"properties": copy.deepcopy(values[resource])}
                if method == "post" and resource == named + "/listValue":
                    return {"value": secret}
                if (method, resource) in (("patch", named), ("put", policy)):
                    writes.append((method, resource))
                    properties = copy.deepcopy(body["properties"])
                    if resource == named:
                        secret = properties.pop("value")
                    values[resource] = properties
                    return {}
                raise AssertionError((method, resource))

        credentials = {"contextKeys": {"evidence-assessor": {"activeId": "current-key",
            "keys": {"current-key": "current-secret-material-0000000000"}}}}
        pending = {"kind": "context", "target": "evidence-assessor", "old": {
            "contextKeys": {"evidence-assessor": {"activeId": "retired-key",
                "keys": {"retired-key": "retired-secret-material-0000000000"}}}}}
        lifecycle = SimpleNamespace(native=Native(), credentials=lambda: credentials, value={"outputs": {
            "inventory": {"gateway": {"contextValues": [named]},
                "gatewayApis": [{"api": "/owned/apim/apis/evidence-assessor", "policy": policy}]}}})
        control = RetiredSigner(lifecycle, pending, save=lambda: None, admit=lambda: None)
        before = control.switch()
        self.assertIn("retired-key", values[policy]["value"])
        selected = copy.deepcopy(values)
        values[policy]["value"] += "\n<!-- concurrent-policy-change -->"
        with self.assertRaises(ValueError):
            control.restore()
        self.assertEqual(pending["selector_intent"]["state"], "selected")
        self.assertEqual(len(writes), 2)
        values = selected
        self.assertEqual(control.restore(), before)
        self.assertEqual(values, original)
        self.assertEqual(credentials["contextKeys"]["evidence-assessor"]["activeId"], "current-key")
        self.assertEqual(writes, [("patch", named), ("put", policy), ("put", policy), ("patch", named)])

    def test_retired_signer_control_preserves_backend_trust_and_restores_exact_owned_selector(self):
        from citadel.acceptance.rotation_selector import RetiredSigner
        from citadel.operator.rotation import certificate as material
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.serialization.pkcs12 import load_pkcs12
        import base64
        old, current = material("retired"), material("current")

        def fingerprint(credentials):
            return load_pkcs12(base64.b64decode(credentials["gatewayCertificatePfx"]), None
                              ).cert.certificate.fingerprint(hashes.SHA1()).hex()

        certificate = "/owned/apim/certificates/gateway-client"
        original = {"secretIdentifier": "https://platform.vault.azure.net/secrets/gateway-certificate",
                    "identityClientId": "00000000-0000-0000-0000-000000000001"}
        values = {certificate: {"properties": {"keyVault": original, "thumbprint": fingerprint(current)}}}
        writes = []

        class Native:
            def rest(self, method, resource, api, body=None):
                if method == "get" and resource in values:
                    return copy.deepcopy(values[resource])
                if method == "put" and resource == certificate:
                    if api != "2024-05-01" or set(body["properties"]) != {"keyVault"}:
                        raise AssertionError("Pinned Certificate_CreateOrUpdate key-vault contract required")
                    writes.append((resource, copy.deepcopy(body)))
                    values[resource]["properties"].update(copy.deepcopy(body["properties"]))
                    values[resource]["properties"]["thumbprint"] = fingerprint(
                        old if body["properties"]["keyVault"]["secretIdentifier"].endswith("1" * 32) else current)
                    return {}
                if method == "post" and resource == certificate + "/refreshSecret":
                    return {}
                raise AssertionError((method, resource))

        pending = {"kind": "certificate", "target": None, "old": old, "old_secret_id":
            "https://platform.vault.azure.net/secrets/gateway-certificate/" + "1" * 32}
        lifecycle = SimpleNamespace(native=Native(), credentials=lambda: current, value={"outputs": {"inventory": {
            "gateway": {"resources": [certificate]}}}}, state=SimpleNamespace(save=lambda: None))
        control = RetiredSigner(lifecycle, pending, save=lambda: None, admit=lambda: None)
        before = control.switch()
        self.assertTrue(values[certificate]["properties"]["keyVault"]["secretIdentifier"].endswith("1" * 32))
        self.assertEqual(control.restore(), before)
        self.assertEqual(values[certificate]["properties"]["keyVault"], original)
        self.assertEqual(len(writes), 2)
        self.assertTrue(all(set(body["properties"]) == {"keyVault"} for _, body in writes))
        with self.assertRaises(ValueError):
            RetiredSigner(lifecycle, pending, save=lambda: None, admit=lambda: None).switch()

    def test_export_requires_real_allowed_retired_and_restored_controls_and_independent_no_effect(self):
        for kind in ("subscription", "certificate", "context"):
            check, report = proof_fixture(kind)
            self.assertEqual(evaluate_check(sanitize(check), sanitize(report))["status"], "pass", kind)
            for mutation in ("no-service", "changed-state", "not-restored", "fake-denial", "wrong-identity"):
                changed, proof = copy.deepcopy(check), copy.deepcopy(report)
                if mutation == "no-service":
                    proof["evidence"] = [row for row in proof["evidence"] if row["source"] != "gateway"]
                elif mutation == "changed-state":
                    changed["actual"]["after"][0]["sha256"] = "9" * 64
                elif mutation == "not-restored":
                    changed["actual"]["after_sha256"] = "9" * 64
                elif mutation == "fake-denial":
                    changed["actual"]["observations"][1]["status_code"] = 500
                else:
                    changed["actual"]["observations"][1]["runtime_identity"] = "9" * 64
                with self.subTest(kind=kind, mutation=mutation):
                    self.assertNotEqual(evaluate_check(sanitize(changed), sanitize(proof))["status"], "pass")

    def test_rotation_rejects_missing_denial_reason_or_effect_in_any_business_ledger(self):
        check, report = proof_fixture()
        report["storage_targets"] = {row["container"]: row["target"] for row in check["actual"]["before"]}
        for missing in ("gateway-reason", "planner-operations", "reviewer-operations"):
            changed, proof = copy.deepcopy(check), copy.deepcopy(report)
            if missing == "gateway-reason":
                next(row for row in proof["evidence"] if row["source"] == "gateway"
                     and row["status_code"] == 401)["facts"].pop("reason")
            else:
                next(row for row in changed["actual"]["after"]
                     if row["container"] == missing)["sha256"] = "9" * 64
            with self.subTest(missing=missing):
                self.assertEqual(evaluate_check(sanitize(changed), sanitize(proof))["status"], "blocked")

    def test_rotation_worker_only_admits_owned_fixed_read_only_controls(self):
        request = {"schema_version": 1, "run_id": "rotation-control", "mode": "rotation",
            "workload": "candidate-planner", "client_id": "11111111-1111-1111-1111-111111111111",
            "deadline": time.time() + 900, "rotation": {
                "kind": "subscription", "target": "evidence-assessor",
                "credential_sha256": "a" * 64, "secret_version": "1" * 32}}
        self.assertEqual(validate_request(request, enabled=True, workload=request["workload"],
            client_id=request["client_id"]), request)
        for change in ({"target": "release-reviewer"}, {"kind": "arbitrary"},
                       {"secret_version": "../unallocated"}, {"url": "https://unallocated.invalid"}):
            changed = copy.deepcopy(request)
            changed["rotation"].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_request(changed, enabled=True, workload=request["workload"],
                                 client_id=request["client_id"])


class RotationWorkerTests(unittest.IsolatedAsyncioTestCase):
    async def test_author_subscription_control_reads_one_exact_funded_finding_not_discovery(self):
        from citadel.acceptance.rotation_controls import rotation_read, TARGETS
        from citadel.operations.testing import MemoryLedger
        from citadel.runtime.agents import Runtime, agent_application
        from test_reference import signed, trust
        self.assertEqual(TARGETS.get("briefing-author"), "release-reviewer")
        ledger, artifacts = MemoryLedger(), MemoryLedger()
        finding = {"schema_version": 1, "airport_ident": "EB01", "classification": "complete"}
        artifacts.document["findings"] = {"owned": {"1": finding}}
        await ledger.ticket_store.open_pool("evidence-assessor/invoke/review")
        await ledger.ticket_store.bind_finding("evidence-assessor/invoke/review", "owned", 1)
        runtime = Runtime("release-reviewer", ledger, artifacts=artifacts,
            gateway_url="https://gateway.test", model=None, peers=None)
        calls = []

        async def authorize(request):
            calls.append((request.method, request.url.path, request.headers.get("x-citadel-read-pool")))
            request.url = request.url.copy_with(path=request.url.path.removeprefix("/release-reviewer"))
            request.headers.update(signed(request.content, "release-reviewer", request.url.path,
                                          "briefing-author", request.method))

        async def admit():
            pass

        request = {"run_id": "author-control", "deadline": time.time() + 120, "rotation": {
            "kind": "subscription", "target": "release-reviewer",
            "credential_sha256": hashlib.sha256(b"owned-author-key").hexdigest(), "secret_version": None,
            "finding": {"artifact_id": "owned", "version": 1, "sha256": sha256(finding)},
            "read_scope": {"run_id": "comparison", "operation_id": "review"}}}
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=agent_application(
                runtime, trust("release-reviewer"))), event_hooks={"request": [authorize]}) as client:
            row = await rotation_read(workload="briefing-author", gateway="https://gateway.test",
                key="owned-author-key", request=request, client=client, admit=admit)
        self.assertEqual(row["status_code"], 200)
        self.assertEqual(row["actual"], "read_only_control")
        self.assertEqual(calls, [("GET", "/release-reviewer/findings/owned/versions/1", "review")])
        self.assertEqual(artifacts.document["findings"], {"owned": {"1": finding}})

    async def test_public_worker_retrieves_only_own_version_and_sends_real_fixed_wire_exchange(self):
        from azure.storage.blob.aio import ContainerClient
        from citadel.acceptance.worker import run_gateway_matrix
        from citadel.acceptance.telemetry import Telemetry
        from citadel.runtime.configuration import Configuration
        from tests.runtime.test_startup import environment
        from tests.runtime.test_storage import FixtureCredential
        from tests.runtime.test_ticket_storage import TicketWire
        env = environment() | {"CITADEL_ACCEPTANCE_ENABLED": "true",
            "AZURE_PRINCIPAL_ID": "00000000-0000-0000-0000-000000000002"}
        config = Configuration.from_environment(env)
        wire, secret_reads, http_requests, telemetry = TicketWire(clock=time.time), [], [], io.StringIO()
        wire.blobs["/planner-operations/active-run-slot.json"] = b"{}"
        wire.etags["/planner-operations/active-run-slot.json"] = 1

        class Credential(FixtureCredential):
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

        class Vault:
            def __init__(self, url, credential, **kwargs):
                self_test.assertEqual(url, config.vault)

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            async def get_secret(self, name, **kwargs):
                secret_reads.append((name, kwargs))
                return SimpleNamespace(value="retired-allocated-key")

        def send(request):
            http_requests.append(request)
            return httpx.Response(401, headers={"apim-request-id": "actual-fixture-gateway"}, json={"statusCode": 401})

        self_test, original_client = self, httpx.AsyncClient
        request = {"schema_version": 1, "mode": "rotation", "workload": config.target,
            "client_id": config.client_id, "run_id": "rotation-wire", "deadline": time.time() + 900,
            "rotation": {"kind": "subscription", "target": "evidence-assessor",
                "credential_sha256": hashlib.sha256(b"retired-allocated-key").hexdigest(),
                "secret_version": "1" * 32}}
        with (patch.dict(os.environ, env),
              patch("citadel.acceptance.worker.ManagedIdentityCredential", lambda **kwargs: Credential()),
              patch("citadel.acceptance.worker.ContainerClient",
                    lambda *args, **kwargs: ContainerClient(*args, transport=wire, **kwargs)),
              patch("citadel.acceptance.worker.SecretClient", Vault),
              patch("httpx.AsyncClient", lambda **kwargs: original_client(transport=httpx.MockTransport(send), **kwargs)),
              patch("citadel.acceptance.telemetry._exporter", Telemetry(config.target, env["AZURE_PRINCIPAL_ID"],
                                                                      output=telemetry))):
            rows = await run_gateway_matrix(config, request)
        self.assertEqual(secret_reads, [(config.subscription_secret, {"version": "1" * 32})])
        self.assertEqual(len(http_requests), 1)
        self.assertEqual(http_requests[0].method, "GET")
        self.assertTrue(str(http_requests[0].url).endswith("/evidence-assessor/.well-known/agent-card.json"))
        self.assertEqual(rows[0]["status_code"], 401)
        self.assertEqual(json.loads(telemetry.getvalue().splitlines()[-1])["method"], "rotation.probe")
        self.assertNotIn("retired-allocated-key", telemetry.getvalue())
        self.assertNotIn("/planner-operations/active-run-slot.json", wire.leases)
