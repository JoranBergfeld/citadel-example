"""One-shot fixed-purpose workload process; same image, assigned MI and allocated key."""

import asyncio
import base64
import hashlib
import json
import math
import os
import time
from uuid import UUID, uuid4

import httpx
from azure.identity.aio import ManagedIdentityCredential
from azure.keyvault.secrets.aio import SecretClient
from azure.storage.blob.aio import ContainerClient

from citadel.evidence.manifests import canonical_bytes, sha256
from citadel.gateway.trust import INVOCATION_CALLERS
from citadel.operations import identity, OperationError
from citadel.runtime.configuration import Configuration
from citadel.runtime.state import read_scope
from citadel.runtime.tickets import AzureTicketStore, TicketPool
from .probes import AGENTS, GatewayProbe
from .telemetry import correlate, emit


def validate_request(request, *, enabled, workload, client_id):
    keys = {"schema_version", "run_id", "workload", "client_id", "deadline", "mode"}
    if isinstance(request, dict) and request.get("mode") == "storage-boundaries":
        keys.add("storage")
    if isinstance(request, dict) and request.get("mode") == "origin-boundary":
        keys.add("origin")
    if isinstance(request, dict) and request.get("mode") == "gateway-matrix" and "routes" in request:
        keys.add("routes")
    if isinstance(request, dict) and request.get("mode") in ("release-faults", "draft-versions"):
        keys.add("release")
    if isinstance(request, dict) and request.get("mode") == "immutable-versions":
        keys.add("versions")
    if (enabled is not True or not isinstance(request, dict)
            or request.keys() != keys
            or type(request["schema_version"]) is not int or request["schema_version"] != 1
            or request["workload"] != workload
            or workload not in AGENTS or str(UUID(request["client_id"])) != str(UUID(client_id))
            or request["mode"] not in ("gateway-matrix", "operation-faults", "admission-limits", "release-faults",
                                      "draft-versions", "immutable-versions", "storage-boundaries", "origin-boundary")
            or request["mode"] == "operation-faults" and workload not in ("candidate-planner", "briefing-author")
            or request["mode"] == "admission-limits" and workload != "candidate-planner"
            or request["mode"] == "release-faults" and workload != "release-reviewer"
            or request["mode"] == "draft-versions" and workload != "evidence-assessor"
            or request["mode"] == "immutable-versions" and workload != "release-reviewer"
            or type(request["deadline"]) not in (float, int) or not math.isfinite(request["deadline"])
            or not time.time() < request["deadline"] <= time.time() + 900):
        raise ValueError("Disabled, unallocated or malformed fixed-purpose probe")
    identity(request["run_id"])
    if len(canonical_bytes(request)) > 3072:
        raise ValueError("Probe manifest exceeds its 4096-byte base64 environment envelope")
    if "routes" in request:
        from .route_context import validate_route_context
        validate_route_context(request["routes"])
    if "release" in request:
        from .release_probes import validate_source
        validate_source(request["release"])
    if "versions" in request:
        from .release_probes import validate_versions
        validate_versions(request["versions"])
        if request["versions"]["run_id"] == request["run_id"]:
            raise ValueError("Reviewer requires a fresh run distinct from its assessor source")
    if request["mode"] == "storage-boundaries":
        from .storage_probes import validate_storage_manifest
        validate_storage_manifest(request["storage"])
    if request["mode"] == "origin-boundary":
        from citadel.runtime.configuration import endpoint
        endpoint(request["origin"], ".azurecontainerapps.io")
    return request


class ProbeLedger:
    def __init__(self, ledger, pool, deadline):
        self.ledger, self.pool, self.deadline = ledger, pool, deadline

    async def read(self):
        await self.pool.admit()
        async with asyncio.timeout(max(0, min(30, self.deadline - time.time()))):
            return await self.ledger.read()

    async def commit(self, document, etag, *, deadline):
        return await self.ledger.commit(document, etag, deadline=min(deadline, self.deadline))


async def publish_operation(container, *, run_id, workload, principal_id, check_id, actual, started, deadline):
    identity(run_id)
    operation = identity(actual["operation_id"])
    from .release_probes import RELEASE_CHECKS
    if not (workload == "release-reviewer" and check_id in RELEASE_CHECKS | {"fault.immutable-versions"}) and not (
            workload == "evidence-assessor" and check_id == "fault.concurrent-version-conflict") and not (
            workload == "candidate-planner" and check_id == "limit.agent_executions") and (
            workload not in ("candidate-planner", "briefing-author") or check_id not in {
            "fault.dropped-committed-write", "fault.pending-incomplete", "fault.fenced-explicit-retry",
            "fault.safe-read-recovery", "fault.safe-read-exhaustion", "fault.deadline-no-late-effect"}):
        raise ValueError("Only fixed durable-operation observations may be published")
    blob = container.get_blob_client(f"acceptance/{run_id}/observations/{operation}.json")
    row = {"check_id": check_id, "probe_id": check_id, "run_id": run_id, "operation_id": operation,
        "caller": workload, "runtime_identity": hashlib.sha256(str(UUID(principal_id)).encode()).hexdigest(),
        "target": hashlib.sha256(blob.url.encode()).hexdigest(), "started": started, "actual": actual}
    sent = False

    def once(request):
        nonlocal sent
        if sent or time.time() >= deadline:
            raise OperationError("deadline", "Late or repeated fault-publication dispatch refused")
        sent = True
        request.http_request.headers["x-ms-client-request-id"] = operation

    def received(response):
        row.update(request_id=response.http_response.headers.get("x-ms-request-id"),
                   status_code=response.http_response.status_code)

    async with asyncio.timeout(max(0, min(30, deadline - time.time()))):
        await blob.upload_blob(canonical_bytes(row), overwrite=False, timeout=5,
                               raw_request_hook=once, raw_response_hook=received)
    row["finished"] = time.time()
    with correlate(run_id, operation, workload):
        emit("execution", request_id=row.get("request_id"), status_code=row.get("status_code", 0),
             target=row["target"], facts={"sha256": sha256(actual), "probe_id": check_id,
                 "business_state": actual.get("state", "incomplete"),
                 "artifact_count": actual.get("artifact_count", 0)})
    return row


async def run_draft_version_control(config, request, pool, container, drafts, reference, source, reference_reads):
    from citadel.operations.blob import AzureBlobLedger
    from .version_probes import VersionProbes
    operation, started = uuid4().hex, time.time()
    if started >= request["deadline"]:
        raise OperationError("deadline", "Late draft-version initialization refused")
    with correlate(request["run_id"], operation, config.target):
        ledger = AzureBlobLedger(drafts.get_blob_client(
            f"acceptance/{request['run_id']}/drafts/{operation}.json"), control_plane=True)
        await ledger.initialize()
        actual = await VersionProbes(ProbeLedger(ledger, pool, request["deadline"]),
            reference=reference, workload=config.target, enabled=True, run_id=request["run_id"],
            deadline=request["deadline"]).concurrent_version(source, operation_id=operation)
        actual["reference_reads"] = reference_reads
        return await publish_operation(container, run_id=request["run_id"], workload=config.target,
            principal_id=os.environ["AZURE_PRINCIPAL_ID"], check_id="fault.concurrent-version-conflict",
            actual=actual, started=started, deadline=request["deadline"])


async def run_release_faults(config, request, credential, pool, container):
    from citadel.operations import DraftReader
    from citadel.operations.blob import AzureBlobLedger
    from citadel.runtime.network import GatewayPeers
    from .release_probes import ReleaseProbes, RELEASE_CHECKS
    deadline, run_id = request["deadline"], request["run_id"]
    immutable = request["mode"] == "immutable-versions"
    source = ({"run_id": request["versions"]["run_id"], "draft": request["versions"]["drafts"][0]}
              if immutable else request["release"])
    source_name = (f"acceptance/{request['versions']['run_id']}/drafts/{request['versions']['operation_id']}.json"
                   if immutable else "ledger-v1.json")
    options = dict(credential=credential, api_version="2026-10-06", retry_total=0,
                   retry_connect=0, retry_read=0, retry_status=0, connection_timeout=5, read_timeout=30)
    results, state, reference_reads = [], "complete", []

    async def sent(request):
        request.extensions["citadel_probe_started"] = time.time()

    async def received(response):
        from .telemetry import gateway_request_id
        request = response.request
        if request.method != "POST":
            return
        payload = json.loads(request.content)
        method = (payload.get("params", {}).get("name")
                  if payload.get("method") == "tools/call" else payload.get("method"))
        if method not in ("initialize", "lookup_airport", "list_runways"):
            return
        if len(reference_reads) >= 3:
            raise OperationError("exhausted", "Unexpected repeated Reference Data control")
        reference_reads.append({"method": method, "run_id": run_id, "operation_id": run_id,
            "request_id": gateway_request_id(response.headers), "status_code": int(response.status_code),
            "target": hashlib.sha256(str(request.url).encode()).hexdigest(),
            "started": request.extensions["citadel_probe_started"],
            "finished": time.time()})
    try:
        with read_scope(pool, deadline=deadline), correlate(run_id, run_id, config.target):
            async with ContainerClient(config.blob, "drafts", **options) as drafts:
                source_ledger = ProbeLedger(
                    AzureBlobLedger(drafts.get_blob_client(source_name), control_plane=True), pool, deadline)
                reader = DraftReader(source_ledger)
                if immutable:
                    document, _ = await source_ledger.read()
                    source_deadline = document["runs"][source["run_id"]]["deadline"]
                    if (type(source_deadline) not in (float, int) or not math.isfinite(source_deadline)
                            or deadline > source_deadline):
                        raise ValueError("Reviewer cannot extend the assessor control's inherited deadline")
                ref = source["draft"]
                draft = await reader.get_draft(ref["artifact_id"], ref["version"], ref["sha256"])
                if draft["run_id"] != source["run_id"]:
                    raise ValueError("Observed draft belongs to another source run")
                async with SecretClient(config.vault, credential, api_version="2025-07-01",
                        retry_total=0, connection_timeout=5, read_timeout=30) as vault:
                    async with asyncio.timeout(max(0, min(30, deadline - time.time()))):
                        secret = await vault.get_secret(config.subscription_secret)
                if not secret.value:
                    raise ValueError("Allocated workload subscription is missing")
                async with httpx.AsyncClient(timeout=30, follow_redirects=False, trust_env=False,
                        event_hooks={"request": [sent], "response": [received]}) as client:
                    peers = GatewayPeers(config.target, config.gateway, secret.value, http_client=client)
                    reference = await peers.reference(
                        draft["provenance"]["fixture"]["id"], deadline, ident=draft["airport_ident"])
                if request["mode"] == "draft-versions":
                    results.append(await run_draft_version_control(
                        config, request, pool, container, drafts, reference, draft, reference_reads))
                    async with asyncio.timeout(max(0, min(30, deadline - time.time()))):
                        await container.get_blob_client(f"acceptance/{run_id}/observations.json").upload_blob(
                            canonical_bytes({"schema_version": 1, "run_id": run_id,
                                             "state": "complete", "observations": results}),
                            overwrite=False, timeout=5)
                    return results
                async with ContainerClient(config.blob, "findings", **options) as findings:
                    for check in (["fault.immutable-versions"] if immutable else sorted(RELEASE_CHECKS)):
                        operation, started = uuid4().hex, time.time()
                        with correlate(run_id, operation, config.target):
                            ledger = AzureBlobLedger(findings.get_blob_client(
                                f"acceptance/{run_id}/releases/{operation}.json"), control_plane=True)
                            if time.time() >= deadline:
                                raise OperationError("deadline", "Late release initialization refused")
                            await ledger.initialize()
                            probe = ReleaseProbes(ProbeLedger(ledger, pool, deadline),
                                drafts=reader, reference=reference, workload=config.target, enabled=True,
                                source_run=source["run_id"], deadline=deadline)
                            if immutable:
                                actual = await probe.immutable_versions(request["versions"]["drafts"], operation_id=operation)
                            elif check == "fault.dropped-committed-release":
                                actual = await probe.committed_response_loss(ref, operation_id=operation)
                            elif check == "fault.draft-hash-binding":
                                actual = await probe.hash_binding(ref, operation_id=operation)
                            else:
                                actual = await probe.concurrent_release(ref, operation_id=operation,
                                    distinct_operations=check == "fault.concurrent-different-operation-release")
                            actual["reference_reads"] = reference_reads
                            results.append(await publish_operation(container, run_id=run_id,
                                workload=config.target, principal_id=os.environ["AZURE_PRINCIPAL_ID"],
                                check_id=check, actual=actual, started=started, deadline=deadline))
    except (OperationError, ValueError, TimeoutError):
        state = "blocked"
    async with asyncio.timeout(max(0, min(30, deadline - time.time()))):
        await container.get_blob_client(f"acceptance/{run_id}/observations.json").upload_blob(
            canonical_bytes({"schema_version": 1, "run_id": run_id, "state": state,
                             "observations": results}), overwrite=False, timeout=5)
    return results


async def run_gateway_matrix(config, request):
    """No supplied credentials, identity substitution, developer fallback or raw URL."""
    validate_request(request, enabled=os.environ.get("CITADEL_ACCEPTANCE_ENABLED") == "true",
                     workload=config.target, client_id=config.client_id)
    async with ManagedIdentityCredential(client_id=config.client_id) as credential:
        async with ContainerClient(config.blob, config.operations_container, credential=credential,
                api_version="2026-10-06", retry_total=0, retry_connect=0, retry_read=0, retry_status=0,
                connection_timeout=5, read_timeout=30) as container:
            store = AzureTicketStore(container)
            scope = "acceptance/" + request["run_id"]
            # The conditional marker is authoritative; a lost response is not permission to rerun.
            await container.get_blob_client(scope + "/dispatch.json").upload_blob(
                canonical_bytes(request), overwrite=False, timeout=5)
            if not await store.open_pool(scope, exclusive=config.target == "candidate-planner"):
                raise ValueError("Existing probe admission cannot be replayed")
            pool = TicketPool(store, scope, 512)
            if request["mode"] in ("release-faults", "draft-versions", "immutable-versions"):
                return await run_release_faults(config, request, credential, pool, container)
            if request["mode"] == "storage-boundaries":
                from .storage_probes import StorageProbe
                from .coverage import CONTAINERS, STORAGE
                probe = StorageProbe(account=config.blob, credential=credential,
                    workload=config.target, principal_id=os.environ["AZURE_PRINCIPAL_ID"],
                    enabled=True, run_id=request["run_id"],
                    suite_id=request["storage"]["suite_id"], deadline=request["deadline"],
                    admit=pool.admit)
                results = []
                state = "complete"
                try:
                    with read_scope(pool, deadline=request["deadline"]):
                        for name in CONTAINERS:
                            for action in ("read", "write"):
                                target = request["storage"]["targets"][name]
                                result = await probe.observe(name, action, target)
                                results.append(result)
                                await container.get_blob_client(
                                    scope + "/observations/" + result["operation_id"] + ".json").upload_blob(
                                        canonical_bytes(result), overwrite=False, timeout=5)
                                grant = STORAGE[config.target].get(name)
                                if grant == "write" or action == "read" and grant == "read":
                                    if (not 200 <= result.get("status_code", 0) < 300
                                            or action == "read" and result.get("sha256") != target["sha256"]):
                                        raise OperationError("unavailable", "Known permitted storage control failed")
                                    if action == "write":
                                        target = target | {"etag": result["etag"]}
                                    control = await probe.observe(name, action, target)
                                    control["control"] = True
                                    results.append(control)
                except (OperationError, ValueError):
                    state = "blocked"
                if config.target == "candidate-planner" and state == "complete":
                    await store.release_run(scope)
                await container.get_blob_client(scope + "/observations.json").upload_blob(
                    canonical_bytes({"schema_version": 1, "run_id": request["run_id"],
                                     "state": state, "observations": results}), overwrite=False, timeout=5)
                return results
            if request["mode"] == "origin-boundary":
                from .origin_probes import OriginProbe, MODES
                probe = OriginProbe(workload=config.target, origin=request["origin"],
                    principal_id=os.environ["AZURE_PRINCIPAL_ID"],
                    approved_certificate=next(iter(config.trust.certificates)),
                    key_id=next(iter(config.trust.signing_keys)), enabled=True,
                    run_id=request["run_id"], deadline=request["deadline"], admit=pool.admit)
                results, state = [], "complete"
                try:
                    with read_scope(pool, deadline=request["deadline"]):
                        for mode in MODES:
                            result = await probe.observe(mode)
                            results.append(result)
                            await container.get_blob_client(
                                scope + "/observations/" + result["operation_id"] + ".json").upload_blob(
                                    canonical_bytes(result), overwrite=False, timeout=5)
                except (OperationError, ValueError):
                    state = "blocked"
                if config.target == "candidate-planner" and state == "complete":
                    await store.release_run(scope)
                await container.get_blob_client(scope + "/observations.json").upload_blob(
                    canonical_bytes({"schema_version": 1, "run_id": request["run_id"],
                                     "state": state, "observations": results}), overwrite=False, timeout=5)
                return results
            if request["mode"] in ("operation-faults", "admission-limits"):
                from citadel.operations.blob import AzureBlobLedger
                from citadel.acceptance.faults import OperationProbes
                ledger = AzureBlobLedger(container.get_blob_client(scope + "/ledger-v1.json"), control_plane=True)
                await ledger.initialize()
                bounded = ProbeLedger(ledger, pool, request["deadline"])
                faults = OperationProbes(bounded, workload=config.target, enabled=True,
                    run_id=request["run_id"], deadline=request["deadline"])
                results, state = [], "complete"
                with read_scope(pool, deadline=request["deadline"]):
                    callbacks = [
                        ("fault.dropped-committed-write", faults.committed_response_loss),
                        ("fault.pending-incomplete", faults.identity_and_incomplete_status),
                        ("fault.fenced-explicit-retry", faults.fenced_retry),
                        ("fault.deadline-no-late-effect", faults.deadline_no_late_effect),
                    ]
                    if request["mode"] == "admission-limits":
                        from .admission_limits import AdmissionProbes, global_slot
                        async def admission(operation_id):
                            slot = await global_slot(container, run_id=request["run_id"],
                                operation_id=operation_id, deadline=request["deadline"])
                            result = await AdmissionProbes(bounded, workload=config.target,
                                enabled=True, deadline=request["deadline"]).nonmodel(operation_id=operation_id)
                            return result | {"slot": slot}
                        callbacks = [("limit.agent_executions", admission)]
                    elif config.target == "candidate-planner":
                        callbacks += [
                            ("fault.safe-read-recovery", faults.safe_read_recovery),
                            ("fault.safe-read-exhaustion", faults.safe_read_exhaustion),
                        ]
                    for name, callback in callbacks:
                        operation = uuid4().hex
                        started = time.time()
                        try:
                            with correlate(request["run_id"], operation, config.target):
                                result = await callback(operation_id=operation)
                                observed = await publish_operation(container, run_id=request["run_id"],
                                    workload=config.target, principal_id=os.environ["AZURE_PRINCIPAL_ID"],
                                    check_id=name, actual=result, started=started, deadline=request["deadline"])
                            results.append(observed)
                        except (OperationError, ValueError, TimeoutError):
                            state = "blocked"
                            break
                if config.target == "candidate-planner" and state == "complete":
                    await store.release_run(scope)
                await container.get_blob_client(scope + "/observations.json").upload_blob(
                    canonical_bytes({"schema_version": 1, "run_id": request["run_id"],
                                     "state": state, "observations": results}), overwrite=False, timeout=5)
                return results
            async with SecretClient(config.vault, credential, api_version="2025-07-01",
                    retry_total=0, connection_timeout=5, read_timeout=30) as vault:
                async with asyncio.timeout(30):
                    secret = await vault.get_secret(config.subscription_secret)
            if not secret.value:
                raise ValueError("Allocated subscription is missing")
            results = []
            async with httpx.AsyncClient(timeout=30, follow_redirects=False, trust_env=False) as client:
                probe = GatewayProbe(config.target, config.gateway, secret.value, client=client,
                    enabled=True, run_id=request["run_id"], deadline=request["deadline"], admit=pool.admit,
                    route_context=request.get("routes"))
                with read_scope(pool, deadline=request["deadline"]), correlate(
                        request["run_id"], request["run_id"], config.target):
                    for target in AGENTS:
                        result = await probe.discovery(target)
                        result["check_id"] = f"route.{config.target}.{target}.discovery"
                        results.append(result)
                        if "routes" in request:
                            owner = request["routes"]["operations"][target]["operation_id"]
                            if not (target in ("evidence-assessor", "release-reviewer")
                                    and config.target in INVOCATION_CALLERS[target]):
                                results.append(await probe.status(target, owner))
                            results.append(await probe.task(target, owner))
                        if config.target not in INVOCATION_CALLERS[target]:
                            result = await probe.denied_invocation(target)
                            result["check_id"] = f"route.{config.target}.{target}.invoke"
                            results.append(result)
                    result = await probe.mcp_initialize()
                    result["check_id"] = f"route.{config.target}.reference-data.initialize"
                    results.append(result)
                    for tool in ("search_airports", "lookup_airport", "list_runways"):
                        result = await probe.reference_tool(
                            tool, ident=None if tool == "search_airports" else "EBAM")
                        result["check_id"] = f"route.{config.target}.reference-data.{tool}"
                        results.append(result)
                    if "routes" in request:
                        from .route_context import finding_control
                        control = finding_control(request["routes"], config.target)
                        results.append(await probe.finding(control["finding"], control["read_scope"]))
            # Private allocated storage is the worker-result channel, not an operator HTTP proxy.
            if config.target == "candidate-planner":
                await store.release_run(scope)
            await container.get_blob_client(scope + "/observations.json").upload_blob(
                canonical_bytes({"schema_version": 1, "run_id": request["run_id"], "observations": results}),
                overwrite=False, timeout=5)
            with correlate(request["run_id"], request["run_id"], config.target):
                emit("probe", facts={"artifact_count": len(results), "business_state": "observed"})
            return results


async def serve(request):
    import uvicorn
    from citadel.runtime.hosting import application
    config = Configuration.from_environment(os.environ)
    validate_request(request, enabled=os.environ.get("CITADEL_ACCEPTANCE_ENABLED") == "true",
                     workload=config.target, client_id=config.client_id)
    async with application(config) as app:
        server = uvicorn.Server(uvicorn.Config(app, host="0.0.0.0", port=8000, lifespan="off",
                                              access_log=False, log_level="warning"))
        task = asyncio.create_task(server.serve())
        try:
            while not server.started:
                if task.done():
                    await task
                    raise ValueError("Probe revision could not serve its workload")
                await asyncio.sleep(.1)
            try:
                async with asyncio.timeout(max(0, request["deadline"] - time.time())):
                    await run_gateway_matrix(config, request)
            except Exception:
                # No exception/request bodies or credentials enter logs.
                emit("probe", facts={"business_state": "blocked"})
            await task
        finally:
            server.should_exit = True
            await task


def main():
    # Manifest is nonsecret, fixed-purpose and supplied by a private operator revision.
    try:
        encoded = os.environ["CITADEL_ACCEPTANCE_REQUEST"]
        if len(encoded) > 4096:
            raise ValueError("Oversized probe request")
        request = json.loads(base64.b64decode(encoded, validate=True))
        asyncio.run(serve(request))
    except Exception:
        print('{"status":"blocked","reason":"fixed_probe_not_admitted"}')
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
