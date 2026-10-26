import base64
import copy
import json
import time
import unittest
from types import SimpleNamespace

from citadel.acceptance.revision import RevisionProbe


class NativeFixture:
    def __init__(self):
        self.app = {"properties": {"provisioningState": "Succeeded",
            "latestRevisionName": "normal", "latestReadyRevisionName": "normal",
            "template": {"containers": [{
            "name": "candidate-planner", "image": "registry.example/image@sha256:" + "a" * 64,
            "command": ["python", "-m", "citadel.runtime"], "args": [],
            "env": [{"name": "CITADEL_BLOB_URL", "value": "https://planning.blob.core.windows.net"},
                    {"name": "CITADEL_OPERATIONS_CONTAINER", "value": "planner-operations"}],
        }], "scale": {"minReplicas": 1, "maxReplicas": 1}}}}
        self.patches = []

    def rest(self, method, resource, version, body=None):
        if method == "get":
            return copy.deepcopy(self.app)
        assert method == "patch" and version == "2025-01-01"
        self.patches.append(copy.deepcopy(body))
        self.app["properties"]["template"] = copy.deepcopy(body["properties"]["template"])
        self.app["properties"]["latestRevisionName"] = "revision-" + str(len(self.patches))
        self.app["properties"]["latestReadyRevisionName"] = self.app["properties"]["latestRevisionName"]
        return copy.deepcopy(self.app)

    def blob_read(self, account, container, name):
        if name.endswith("/observations.json"):
            return json.dumps({"schema_version": 1, "run_id": "r1", "observations": []}).encode()
        raise AssertionError("Unexpected blob read")


class AsyncRestoreFixture(NativeFixture):
    def __init__(self, *, never_ready=False):
        super().__init__()
        self.never_ready, self.restoration_gets = never_ready, 0

    def rest(self, method, resource, version, body=None):
        if method == "patch" and len(self.patches) == 1:
            self.worker = copy.deepcopy(self.app)
        result = super().rest(method, resource, version, body)
        if method == "get" and len(self.patches) == 2:
            self.restoration_gets += 1
            if self.restoration_gets == 1:
                return copy.deepcopy(self.worker)
            if self.never_ready or self.restoration_gets == 2:
                result["properties"]["provisioningState"] = "Updating"
                result["properties"]["latestReadyRevisionName"] = self.worker["properties"]["latestRevisionName"]
        return result


class RevisionTests(unittest.TestCase):
    def test_restoration_waits_through_stale_worker_and_pending_normal_revision(self):
        started = time.time()
        native, now, admissions, saved = AsyncRestoreFixture(), [started], [], []
        value = {}
        lifecycle = SimpleNamespace(native=native, value=value, state=SimpleNamespace(
            save=lambda: saved.append(copy.deepcopy(value))))
        app = {"app": "/d-candidate-planner", "identityClientId": "11111111-1111-1111-1111-111111111111",
               "image": native.app["properties"]["template"]["containers"][0]["image"]}
        try:
            result = RevisionProbe(lifecycle, clock=lambda: now[0],
                sleep=lambda seconds: now.__setitem__(0, now[0] + seconds),
                admit=lambda: admissions.append(now[0])).execute(
                    app, "candidate-planner", "r1", deadline=started + 90)
        except ValueError as error:
            self.fail("Asynchronous normal revision restoration must be observed, not rejected: " + str(error))
        self.assertEqual(result["run_id"], "r1")
        self.assertEqual(native.restoration_gets, 3)
        self.assertEqual(now[0] - started, 30)
        self.assertEqual(len(admissions), 6)
        self.assertEqual(len(native.patches), 2)
        self.assertTrue(any(item.get("probe_intents", {}).get("r1", {}).get("state") == "restoring" for item in saved))
        self.assertEqual(value["probe_intents"]["r1"]["state"], "observed")

    def test_normal_template_without_ready_revision_expires_without_repatch_or_deadline_extension(self):
        started = time.time()
        native, now, admissions = AsyncRestoreFixture(never_ready=True), [started], []
        lifecycle = SimpleNamespace(native=native, value={}, state=SimpleNamespace(save=lambda: None))
        app = {"app": "/d-candidate-planner", "identityClientId": "11111111-1111-1111-1111-111111111111",
               "image": native.app["properties"]["template"]["containers"][0]["image"]}
        with self.assertRaises(TimeoutError):
            RevisionProbe(lifecycle, clock=lambda: now[0],
                sleep=lambda seconds: now.__setitem__(0, now[0] + seconds),
                admit=lambda: admissions.append(now[0])).execute(
                    app, "candidate-planner", "r1", deadline=started + 31)
        self.assertEqual(now[0] - started, 31)
        self.assertEqual(native.restoration_gets, 3)
        self.assertEqual(len(native.patches), 2)
        self.assertTrue(all(instant < started + 31 for instant in admissions))
        self.assertEqual(lifecycle.value["probe_intents"]["r1"]["deadline"], started + 31)
        self.assertEqual(lifecycle.value["probe_intents"]["r1"]["state"], "indeterminate")

    def test_restoration_rejects_unrelated_template_without_another_patch(self):
        class ConcurrentFixture(AsyncRestoreFixture):
            def rest(self, *arguments, **options):
                result = super().rest(*arguments, **options)
                if self.restoration_gets == 2:
                    result["properties"]["template"]["containers"][0]["image"] = "unrelated"
                return result

        started = time.time()
        native, now = ConcurrentFixture(), [started]
        lifecycle = SimpleNamespace(native=native, value={}, state=SimpleNamespace(save=lambda: None))
        app = {"app": "/d-candidate-planner", "identityClientId": "11111111-1111-1111-1111-111111111111",
               "image": native.app["properties"]["template"]["containers"][0]["image"]}
        with self.assertRaisesRegex(ValueError, "Concurrent revision modification"):
            RevisionProbe(lifecycle, clock=lambda: now[0],
                sleep=lambda seconds: now.__setitem__(0, now[0] + seconds)).execute(
                    app, "candidate-planner", "r1", deadline=started + 90)
        self.assertEqual(len(native.patches), 2)
        self.assertEqual(lifecycle.value["probe_intents"]["r1"]["state"], "restoring")

    def test_direct_model_manifest_survives_exact_revision_dispatch_without_any_credential(self):
        native = NativeFixture()
        lifecycle = SimpleNamespace(native=native, value={}, state=SimpleNamespace(save=lambda: None))
        app = {"app": "/d-candidate-planner",
               "identityClientId": "11111111-1111-1111-1111-111111111111",
               "image": "registry.example/image@sha256:" + "a" * 64}
        model = {"run_id": "phase1", "origin": "https://allocated.openai.azure.com",
                 "deployment": "citadel-gpt-41-mini"}
        RevisionProbe(lifecycle).execute(app, "candidate-planner", "r1", mode="direct-model", model=model)
        environment = native.patches[0]["properties"]["template"]["containers"][0]["env"]
        request = json.loads(base64.b64decode(next(
            entry["value"] for entry in environment if entry["name"] == "CITADEL_ACCEPTANCE_REQUEST")))
        self.assertEqual(request["model"], model)
        self.assertEqual(request["mode"], "direct-model")
        self.assertEqual(lifecycle.value["probe_intents"]["r1"]["state"], "observed")

    def test_origin_driver_uses_actual_app_ingress_not_caller_supplied_destination(self):
        native = NativeFixture()
        native.app["properties"]["configuration"] = {"ingress": {
            "fqdn": "deployed.example.azurecontainerapps.io", "clientCertificateMode": "require"}}
        lifecycle = SimpleNamespace(native=native, value={},
                                    state=SimpleNamespace(save=lambda: None))
        app = {"app": "/subscriptions/s/resourceGroups/g/providers/Microsoft.App/containerApps/d-candidate-planner",
               "identityClientId": "11111111-1111-1111-1111-111111111111",
               "image": "registry.example/image@sha256:" + "a" * 64}
        RevisionProbe(lifecycle).execute(app, "candidate-planner", "r1", mode="origin-boundary")
        environment = native.patches[0]["properties"]["template"]["containers"][0]["env"]
        request = json.loads(base64.b64decode(next(
            entry["value"] for entry in environment if entry["name"] == "CITADEL_ACCEPTANCE_REQUEST")))
        self.assertEqual(request["origin"], "https://deployed.example.azurecontainerapps.io")
        self.assertEqual(request["mode"], "origin-boundary")
        self.assertEqual(lifecycle.value["probe_intents"]["r1"]["origin"], request["origin"])

    def test_same_image_identity_fixed_command_and_restore_without_operator_keys(self):
        from citadel.acceptance.route_context import build_route_context
        from tests.acceptance.test_route_context import ledgers
        context = build_route_context(ledgers(), run_ids=["real-run"])
        native = NativeFixture()
        original = copy.deepcopy(native.app["properties"]["template"])
        app = {"app": "/subscriptions/s/resourceGroups/g/providers/Microsoft.App/containerApps/d-candidate-planner",
               "identityClientId": "11111111-1111-1111-1111-111111111111",
               "image": "registry.example/image@sha256:" + "a" * 64}
        state = SimpleNamespace(save=lambda: None)
        lifecycle = SimpleNamespace(native=native, value={"probe_intents": {}}, state=state)
        admissions = []
        result = RevisionProbe(lifecycle, sleep=lambda seconds: None,
                               admit=lambda: admissions.append(1)).execute(
                                   app, "candidate-planner", "r1", routes=context)
        self.assertEqual(result["run_id"], "r1")
        self.assertEqual(len(admissions), 4)
        self.assertEqual(native.app["properties"]["template"], original)
        container = native.patches[0]["properties"]["template"]["containers"][0]
        self.assertEqual(container["command"], ["python", "-m", "citadel.acceptance.worker"])
        self.assertEqual(container["image"], app["image"])
        manifest = next(e["value"] for e in container["env"] if e["name"] == "CITADEL_ACCEPTANCE_REQUEST")
        request = json.loads(base64.b64decode(manifest))
        self.assertEqual(request["client_id"], app["identityClientId"])
        self.assertEqual(request["routes"], context)
        self.assertNotIn("private test prose", json.dumps(request))
        self.assertNotIn("credential", manifest)

    def test_ambiguous_previous_dispatch_cannot_be_replayed(self):
        lifecycle = SimpleNamespace(native=NativeFixture(), value={"probe_intents": {"r1": {"state": "dispatching"}}})
        with self.assertRaises(ValueError):
            RevisionProbe(lifecycle).execute({}, "candidate-planner", "r1")
