import base64
import copy
import json
import unittest
from types import SimpleNamespace

from citadel.acceptance.revision import RevisionProbe


class NativeFixture:
    def __init__(self):
        self.app = {"properties": {"template": {"containers": [{
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
        return copy.deepcopy(self.app)

    def blob_read(self, account, container, name):
        if name.endswith("/observations.json"):
            return json.dumps({"schema_version": 1, "run_id": "r1", "observations": []}).encode()
        raise AssertionError("Unexpected blob read")


class RevisionTests(unittest.TestCase):
    def test_same_image_identity_fixed_command_and_restore_without_operator_keys(self):
        native = NativeFixture()
        original = copy.deepcopy(native.app["properties"]["template"])
        app = {"app": "/subscriptions/s/resourceGroups/g/providers/Microsoft.App/containerApps/d-candidate-planner",
               "identityClientId": "11111111-1111-1111-1111-111111111111",
               "image": "registry.example/image@sha256:" + "a" * 64}
        state = SimpleNamespace(save=lambda: None)
        lifecycle = SimpleNamespace(native=native, value={"probe_intents": {}}, state=state)
        result = RevisionProbe(lifecycle, sleep=lambda seconds: None).execute(app, "candidate-planner", "r1")
        self.assertEqual(result["run_id"], "r1")
        self.assertEqual(native.app["properties"]["template"], original)
        container = native.patches[0]["properties"]["template"]["containers"][0]
        self.assertEqual(container["command"], ["python", "-m", "citadel.acceptance.worker"])
        self.assertEqual(container["image"], app["image"])
        manifest = next(e["value"] for e in container["env"] if e["name"] == "CITADEL_ACCEPTANCE_REQUEST")
        request = json.loads(base64.b64decode(manifest))
        self.assertEqual(request["client_id"], app["identityClientId"])
        self.assertNotIn("credential", manifest)

    def test_ambiguous_previous_dispatch_cannot_be_replayed(self):
        lifecycle = SimpleNamespace(native=NativeFixture(), value={"probe_intents": {"r1": {"state": "dispatching"}}})
        with self.assertRaises(ValueError):
            RevisionProbe(lifecycle).execute({}, "candidate-planner", "r1")
