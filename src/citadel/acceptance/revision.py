"""Run fixed probes in the existing image/identity, without a console/proxy service."""

import base64
import copy
import json
import time

from citadel.evidence.manifests import canonical_bytes, sha256
from citadel.operations import identity
from citadel.runtime.configuration import endpoint, OPERATIONS
from .probes import AGENTS


def template(value):
    result = copy.deepcopy(value)
    result.pop("revisionSuffix", None)
    return result


class RevisionProbe:
    def __init__(self, lifecycle, *, sleep=time.sleep, clock=time.time, admit=None):
        self.lifecycle, self.sleep, self.clock = lifecycle, sleep, clock
        self.admit = admit

    def execute(self, app, workload, run_id, *, mode="gateway-matrix", storage=None, routes=None,
                release=None, versions=None, model=None, rotation=None, deadline=None):
        identity(run_id)
        if workload not in AGENTS:
            raise ValueError("Only an allocated, durably admitted workload probe is supported")
        intents = self.lifecycle.value.setdefault("probe_intents", {})
        if run_id in intents:
            raise ValueError("Existing probe dispatch must be reconciled, never replayed")
        native = self.lifecycle.native
        if self.admit is not None:
            self.admit()
        deployed = native.rest("get", app["app"], "2025-01-01")
        original = template(deployed["properties"]["template"])
        containers = original["containers"]
        if (len(containers) != 1 or containers[0]["image"] != app["image"]
                or containers[0].get("command") != ["python", "-m", "citadel.runtime"]):
            raise ValueError("Pinned normal workload revision required")
        env = {item["name"]: item.get("value") for item in containers[0]["env"]}
        account = endpoint(env["CITADEL_BLOB_URL"], ".blob.core.windows.net")
        container = env["CITADEL_OPERATIONS_CONTAINER"]
        if container != OPERATIONS[workload]:
            raise ValueError("Result channel is not allocated to this workload")
        request = {"schema_version": 1, "run_id": run_id, "workload": workload,
                   "client_id": app["identityClientId"], "deadline": min(deadline or float("inf"), self.clock() + 900),
                   "mode": mode}
        if storage is not None:
            request["storage"] = storage
        if routes is not None:
            request["routes"] = routes
        if release is not None:
            request["release"] = release
        if versions is not None:
            request["versions"] = versions
        if model is not None:
            request["model"] = model
        if rotation is not None:
            request["rotation"] = rotation
        if mode == "origin-boundary":
            request["origin"] = endpoint(
                "https://" + deployed["properties"]["configuration"]["ingress"]["fqdn"],
                ".azurecontainerapps.io")
        from .worker import validate_request
        validate_request(request, enabled=True, workload=workload, client_id=app["identityClientId"])
        replacement = copy.deepcopy(original)
        replacement["containers"][0]["command"] = ["python", "-m", "citadel.acceptance.worker"]
        replacement["containers"][0]["env"] += [
            {"name": "CITADEL_ACCEPTANCE_ENABLED", "value": "true"},
            {"name": "CITADEL_ACCEPTANCE_REQUEST",
             "value": base64.b64encode(canonical_bytes(request)).decode()},
        ]
        intents[run_id] = {"state": "dispatching", "workload": workload, "original": original,
                          "replacement_sha256": sha256(replacement), "deadline": request["deadline"]}
        if mode == "origin-boundary":
            intents[run_id]["origin"] = request["origin"]
        self.lifecycle.state.save()
        native.rest("patch", app["app"], "2025-01-01", {"properties": {"template": replacement}})
        while self.clock() < request["deadline"]:
            if self.admit is not None:
                self.admit()
            content = native.blob_read(account, container, f"acceptance/{run_id}/observations.json")
            if content is not None:
                result = json.loads(content)
                if (result.get("schema_version") != 1 or result.get("run_id") != run_id
                        or not isinstance(result.get("observations"), list)):
                    raise ValueError("Probe result has the wrong immutable binding")
                if self.admit is not None:
                    self.admit()
                current = template(native.rest("get", app["app"], "2025-01-01")["properties"]["template"])
                if current != replacement:
                    raise ValueError("Concurrent revision modification; do not overwrite")
                intents[run_id].update(state="restoring", sha256=sha256(result))
                self.lifecycle.state.save()
                native.rest("patch", app["app"], "2025-01-01", {"properties": {"template": original}})
                while self.clock() < request["deadline"]:
                    if self.admit is not None:
                        self.admit()
                    properties = native.rest("get", app["app"], "2025-01-01")["properties"]
                    restored = template(properties["template"])
                    if restored not in (original, replacement):
                        raise ValueError("Concurrent revision modification; do not overwrite")
                    if (restored == original and properties.get("provisioningState") == "Succeeded"
                            and properties.get("latestRevisionName")
                            and properties["latestRevisionName"] == properties.get("latestReadyRevisionName")
                            and self.clock() < request["deadline"]):
                        intents[run_id]["state"] = "observed"
                        self.lifecycle.state.save()
                        return result
                    self.sleep(min(15, max(0, request["deadline"] - self.clock())))
                break
            self.sleep(min(15, max(0, request["deadline"] - self.clock())))
        intents[run_id]["state"] = "indeterminate"
        self.lifecycle.state.save()
        raise TimeoutError("Probe revision or restoration deadline expired; reconcile/repair explicitly")
