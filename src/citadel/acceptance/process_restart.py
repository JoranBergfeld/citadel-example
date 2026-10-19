"""Two fixed interpreters share durable admission; the first exits without cleanup."""

import asyncio
import json
import os
import sys
import time
from uuid import uuid4

from citadel.evidence.manifests import sha256
from citadel.operations import Operations, OperationError, operation_key
from citadel.operations.limits import Accounting


CHECK = "fault.restart-no-replay"


async def process_restart(request, *, operation_id):
    results = []
    for phase, suffix, expected in (("crash", "-crashed", 73), ("observe", "-restarted", 0)):
        payload = request | {"phase": phase, "operation_id": operation_id}
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "citadel.acceptance.process_restart",
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL, limit=16384)
        try:
            async with asyncio.timeout(max(0, request["deadline"] - time.time())):
                output, _ = await process.communicate(json.dumps(payload).encode())
        except BaseException:
            if process.returncode is None:
                process.kill()
            await process.wait()
            raise
        if process.returncode != expected or len(output) > 16384:
            raise OperationError("indeterminate", "Fixed process exit was not independently observed")
        result = json.loads(output)
        if (result.get("operation_id") != operation_id + suffix
                or result.get("actual", {}).get("process_id") != process.pid):
            raise OperationError("data_integrity", "Fixed process receipt does not bind its OS child")
        result["exit_code"] = process.returncode
        results.append(result)
    first, second = [row["actual"] for row in results]
    if (first["process_id"] == second["process_id"] or first["boot_id"] == second["boot_id"]
            or not first["after_sha256"] == second["before_sha256"] == second["after_sha256"]):
        raise OperationError("data_integrity", "Restart must preserve the original operation and budget")
    return {"operation_id": operation_id, "state": "running", "artifact_count": 0,
            "before_sha256": first["after_sha256"], "after_sha256": second["after_sha256"],
            "processes": results}


async def child(request):
    from azure.identity.aio import ManagedIdentityCredential
    from azure.storage.blob.aio import ContainerClient
    from citadel.operations.blob import AzureBlobLedger
    from citadel.runtime.configuration import Configuration
    from citadel.runtime.state import read_scope
    from citadel.runtime.tickets import AzureTicketStore, TicketPool
    from .faults import rejected
    from .telemetry import configure, correlate, finish
    from .worker import ProbeLedger, publish_operation, validate_request

    phase, operation = request.pop("phase"), request.pop("operation_id")
    config = Configuration.from_environment(os.environ)
    validate_request(request, enabled=os.environ.get("CITADEL_ACCEPTANCE_ENABLED") == "true",
                     workload=config.target, client_id=config.client_id)
    if request["mode"] != "process-restart" or phase not in ("crash", "observe"):
        raise ValueError("Only the two exact allocated restart phases are supported")
    from citadel.operations import identity
    identity(operation)
    run_id, deadline = request["run_id"], request["deadline"]
    scope, started = "acceptance/" + run_id, time.time()
    # Telemetry goes to stderr; stdout contains only the bounded process receipt.
    from contextlib import redirect_stdout
    with redirect_stdout(sys.stderr):
        configure(config.target, os.environ["AZURE_PRINCIPAL_ID"], client_id=config.client_id,
                  connection_string=os.environ["APPLICATIONINSIGHTS_CONNECTION_STRING"])
    async with ManagedIdentityCredential(client_id=config.client_id) as credential:
        async with ContainerClient(config.blob, config.operations_container, credential=credential,
                api_version="2026-10-06", retry_total=0, retry_connect=0, retry_read=0,
                retry_status=0, connection_timeout=5, read_timeout=30) as container:
            store = AzureTicketStore(container)
            await store.require_pool(scope)
            pool = TicketPool(store, scope, 512)
            ledger = ProbeLedger(AzureBlobLedger(
                container.get_blob_client(scope + "/ledger-v1.json"), control_plane=True), pool, deadline)
            ops = Operations(ledger, workload=config.target)
            accounting = Accounting(ledger, workload=config.target)
            boot = uuid4().hex
            inputs = {"kind": "fixed-process-restart"}
            with read_scope(pool, deadline=deadline), correlate(run_id, operation, config.target):
                if phase == "crash":
                    await accounting.start_run(operation, deadline=deadline)
                    await accounting.start_agent(operation, operation)
                    await ops.accept(config.target, "acceptance", operation, inputs,
                                     run_id=operation, deadline=deadline)
                    await ops.claim(config.target, "acceptance", operation,
                                    worker=boot, lease_seconds=180)
                before, _ = await ledger.read()
                monotonic_started = time.monotonic()
                responses = {}
                if phase == "observe":
                    await asyncio.sleep(60)
                    status = await ops.accept(config.target, "acceptance", operation, inputs,
                                              run_id=operation, deadline=deadline)
                    responses = {"replay": await rejected(lambda: ops.claim(
                        config.target, "acceptance", operation, worker=boot)),
                        "retried": await rejected(lambda: ops.retry(config.target, "acceptance", operation)),
                        "response": await rejected(lambda: accounting.start_run(operation, deadline=deadline)),
                        "state": status["state"]}
                after, _ = await ledger.read()
                key = operation_key(config.target, "acceptance", operation)
                if (sha256(before) != sha256(after) or after["operations"][key]["state"] != "running"
                        or "product" in after["operations"][key]
                        or phase == "observe" and responses != {
                            "replay": "conflict", "retried": "conflict", "response": "conflict", "state": "running"}):
                    raise OperationError("data_integrity", "Crashed operation or admission was replayed")
                actual = {"operation_id": operation + ("-crashed" if phase == "crash" else "-restarted"),
                    "process_id": os.getpid(), "boot_id": boot, "state": "running", "artifact_count": 0,
                    "before_sha256": sha256(before), "after_sha256": sha256(after),
                    "monotonic_started": monotonic_started, "monotonic_finished": time.monotonic(),
                    "deadline": deadline, **responses}
                with redirect_stdout(sys.stderr):
                    result = await publish_operation(container, run_id=run_id, workload=config.target,
                        principal_id=os.environ["AZURE_PRINCIPAL_ID"], check_id=CHECK, actual=actual,
                        started=started, deadline=deadline)
            if phase == "crash":
                with redirect_stdout(sys.stderr):
                    finish()
                print(json.dumps(result), flush=True)
                os._exit(73)
    with redirect_stdout(sys.stderr):
        finish()
    return result


def main():
    try:
        raw = sys.stdin.buffer.read(4097)
        if len(raw) > 4096:
            raise ValueError("Oversized fixed process request")
        result = asyncio.run(child(json.loads(raw)))
        print(json.dumps(result), flush=True)
        return 0
    except Exception:
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
