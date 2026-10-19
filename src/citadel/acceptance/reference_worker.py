"""Explicit one-shot Reference Data probes; no subscription secret or write grant."""

import argparse
import asyncio
import base64
import hashlib
import json
import math
import os
import time
from uuid import UUID

from azure.identity.aio import ManagedIdentityCredential

from citadel.evidence.manifests import canonical_bytes, sha256
from citadel.operations import OperationError, identity
from citadel.runtime.configuration import Configuration, endpoint
from .coverage import CONTAINERS
from .storage_probes import StorageProbe, validate_storage_manifest


PREFIX = "CITADEL_ACCEPTANCE_RESULT_V1:"


def validate_request(config, request, *, enabled):
    keys = {"schema_version", "run_id", "workload", "client_id", "deadline", "mode"}
    if not isinstance(request, dict):
        raise ValueError("A fixed reference probe manifest is required")
    if request.get("mode") == "storage-boundaries":
        keys.add("storage")
    if request.get("mode") == "origin-boundary":
        keys.add("origin")
    if request.get("mode") == "direct-model":
        keys.add("model")
    if (enabled is not True or config.target != "reference-data"
            or config.operations_container is not None or config.subscription_secret is not None
            or set(request) != keys or type(request.get("schema_version")) is not int
            or request["schema_version"] != 1 or request["workload"] != "reference-data"
            or str(UUID(request["client_id"])) != config.client_id
            or request["mode"] not in ("storage-boundaries", "origin-boundary", "direct-model")
            or type(request["deadline"]) not in (float, int) or not math.isfinite(request["deadline"])
            or not time.time() < request["deadline"] <= time.time() + 900):
        raise ValueError("Only an explicitly enabled, allocated read-only reference probe is allowed")
    identity(request["run_id"])
    if request["mode"] == "storage-boundaries":
        validate_storage_manifest(request["storage"])
        from .storage_accounts import probe_accounts
        probe_accounts(request["storage"], config.target, config.blob)
    elif request["mode"] == "origin-boundary":
        endpoint(request["origin"], ".azurecontainerapps.io")
    else:
        from .model_probes import validate_model_manifest
        validate_model_manifest(request["model"])


async def execute(config, request, *, enabled, principal_id,
                  credential_factory=ManagedIdentityCredential, storage_transport=None, client_factory=None):
    validate_request(config, request, enabled=enabled)
    principal = str(UUID(principal_id))
    result = {"schema_version": 1, "run_id": request["run_id"], "manifest_sha256": sha256(request),
        "state": "blocked", "runtime_identity": hashlib.sha256(principal.encode()).hexdigest(),
        "read_attempts": 0, "observations": []}

    async def admit():
        if result["read_attempts"] >= 512 or time.time() >= request["deadline"]:
            raise OperationError("exhausted", "Reference probe envelope exhausted")
        result["read_attempts"] += 1

    try:
        async with asyncio.timeout(max(0, request["deadline"] - time.time())):
            async with credential_factory(client_id=config.client_id, retry_total=0) as credential:
                if request["mode"] == "storage-boundaries":
                    from .storage_accounts import probe_accounts
                    probe = StorageProbe(account=probe_accounts(request["storage"], config.target, config.blob), credential=credential,
                        workload="reference-data", principal_id=principal, enabled=True,
                        run_id=request["run_id"], suite_id=request["storage"]["suite_id"],
                        deadline=request["deadline"], admit=admit, transport=storage_transport)
                    for container in CONTAINERS:
                        for action in ("read", "write"):
                            target = request["storage"]["targets"][container]
                            observed = await probe.observe(container, action, target)
                            result["observations"].append(observed)
                            if not observed.get("request_id"):
                                return result
                            if container == "reference" and action == "read":
                                if observed.get("sha256") != target["sha256"]:
                                    return result
                                control = await probe.observe(container, action, target)
                                control["control"] = True
                                result["observations"].append(control)
                elif request["mode"] == "origin-boundary":
                    from .origin_probes import MODES, OriginProbe
                    probe = OriginProbe(workload="reference-data", origin=request["origin"],
                        principal_id=principal, run_id=request["run_id"], enabled=True,
                        deadline=request["deadline"], admit=admit, client_factory=client_factory,
                        approved_certificate=next(iter(config.trust.certificates)),
                        key_id=next(iter(config.trust.signing_keys)))
                    for mode in MODES:
                        result["observations"].append(await probe.observe(mode))
                else:
                    from .model_probes import DirectModelProbe

                    async def admitted():
                        if time.time() >= request["deadline"]:
                            raise OperationError("deadline", "Model control window expired")

                    model = request["model"]
                    probe = DirectModelProbe(workload=config.target, origin=model["origin"],
                        deployment=model["deployment"], credential=credential, principal_id=principal,
                        enabled=True, run_id=model["run_id"], operation_id=request["run_id"],
                        deadline=request["deadline"], admit=admitted, client_factory=client_factory)
                    observation = await probe.observe()
                    result["observations"].append(observation)
                    if observation["state"] != "observed":
                        return result
                result["state"] = "complete"
    except (OperationError, TimeoutError, ValueError):
        pass
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--enabled", action="store_true")
    parser.add_argument("--manifest", required=True)
    args = parser.parse_args()
    exporter = None
    try:
        if len(args.manifest) > 8192:
            raise ValueError("Reference manifest bound exceeded")
        request = json.loads(base64.b64decode(args.manifest, validate=True))
        config = Configuration.from_environment(os.environ)
        validate_request(config, request, enabled=args.enabled)
        from .telemetry import configure, finish
        exporter = configure(config.target, os.environ["AZURE_PRINCIPAL_ID"],
            client_id=config.client_id, connection_string=os.environ["APPLICATIONINSIGHTS_CONNECTION_STRING"])
        result = asyncio.run(execute(config, request, enabled=args.enabled,
                                    principal_id=os.environ["AZURE_PRINCIPAL_ID"]))
        result["telemetry"] = finish()
        exporter = None
        content = canonical_bytes(result)
        print("\n" + PREFIX + base64.b64encode(content).decode() + ":" + hashlib.sha256(content).hexdigest(), flush=True)
        return 0 if result["state"] == "complete" else 2
    except Exception:
        print('{"status":"blocked","reason":"reference_probe_not_admitted"}', flush=True)
        return 2
    finally:
        if exporter is not None:
            exporter.close()


if __name__ == "__main__":
    raise SystemExit(main())
