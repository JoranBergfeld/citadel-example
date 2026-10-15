"""Bounded origin/gateway dispatch with real operator and workload authorities."""

import asyncio
import hashlib
import math
import time
from uuid import UUID, uuid4

import httpx
from azure.core.exceptions import AzureError

from citadel.operations import OperationError, identity
from citadel.operator.scenarios import PlannerClient
from citadel.operator.state import Blocked
from .origin_probes import MODES, evaluate_origin
from .oracle import hash_value
from .revision import RevisionProbe
from .storage_probes import StorageControls


def bind_origin_result(result, *, actor, run_id, principal, origin):
    if (not isinstance(result, dict) or type(result.get("schema_version")) is not int
            or result["schema_version"] != 1 or result.get("run_id") != run_id
            or result.get("state") not in ("complete", "blocked")
            or not isinstance(result.get("observations"), list) or len(result["observations"]) > 3):
        raise Blocked("origin_worker_result_shape_conflict")
    path = "/mcp" if actor == "reference-data" else "/.well-known/agent-card.json"
    target = hashlib.sha256((origin + path).encode()).hexdigest()
    expected = {f"origin.{actor}.{mode}" for mode in MODES}
    checks, operations = [], []
    for row in result["observations"]:
        if (not isinstance(row, dict) or row.get("caller") != actor or row.get("run_id") != run_id
                or row.get("runtime_identity") != principal or row.get("target") != target
                or row.get("check_id") not in expected):
            raise Blocked("origin_worker_authority_or_destination_conflict")
        checks.append(row["check_id"])
        operations.append(identity(row.get("operation_id")))
    if (len(set(checks)) != len(checks) or len(set(operations)) != len(operations)
            or result["state"] == "complete" and set(checks) != expected):
        raise Blocked("origin_worker_coverage_conflict")
    return operations


async def operator_discovery(lifecycle, *, run_id, deadline, admit, client):
    if (type(deadline) not in (float, int) or not math.isfinite(deadline)
            or not time.time() < deadline <= time.time() + 900):
        raise OperationError("deadline", "Operator origin control requires its bounded deadline")
    credentials = lifecycle.credentials()
    if credentials["callerStates"]["operator"] != "active":
        raise Blocked("operator_credential_suspended")
    planner = PlannerClient(lifecycle.value["outputs"]["gatewayUrl"],
                            credentials["callerKeys"]["operator"]["primary"], http=client)
    operation = uuid4().hex
    result = {"check_id": "route.operator.candidate-planner.discovery", "caller": "operator",
              "run_id": identity(run_id), "operation_id": operation, "started": time.time()}
    admit()
    path = "/candidate-planner/.well-known/agent-card.json"
    response = await planner.exchange(path, deadline, lambda: client.get(planner.gateway + path, headers={
        "x-citadel-run-id": run_id, "x-citadel-operation-id": operation}))
    result.update(finished=time.time(), status_code=response.status_code,
        request_id=response.headers.get("apim-request-id") or response.headers.get("x-citadel-gateway-request-id"))
    if response.status_code == 200:
        try:
            interfaces = response.json()["supportedInterfaces"]
            result["actual"] = ("gateway_card" if len(interfaces) == 1
                and interfaces[0].get("url") == planner.gateway + "/candidate-planner/a2a"
                and interfaces[0].get("protocolBinding") == "JSONRPC"
                and interfaces[0].get("protocolVersion") == "1.0" else "invalid_card")
        except (ValueError, TypeError, KeyError):
            result["actual"] = "invalid_card"
    return result


class BoundaryAcceptance:
    def __init__(self, lifecycle):
        self.lifecycle = lifecycle

    def execute(self, report):
        if "boundary_phase" in report:
            raise Blocked("boundary_probe_intent_requires_reconciliation")
        accounts = [rid for rid in self.lifecycle.value["inventory"]
                    if "/providers/Microsoft.Storage/storageAccounts/" in rid and "/blobServices/" not in rid]
        if len(accounts) != 1:
            raise Blocked("exact_storage_account_required")
        phase = {"state": "dispatching", "deadline": time.time() + 900, "read_attempts": 0,
                 "snapshots": {}, "origins": [], "gateway": [], "identities": {}}
        report["boundary_phase"] = phase
        self.lifecycle.state.save()

        def admit():
            if phase["read_attempts"] >= 512 or time.time() >= phase["deadline"]:
                raise OperationError("exhausted", "Boundary control envelope exhausted")
            phase["read_attempts"] += 1
            self.lifecycle.state.save()

        def retain(rows, operations):
            if set(operations) & set(report["operation_ids"]):
                raise Blocked("boundary_physical_operation_reused")
            report["operation_ids"].extend(operations)
            self.lifecycle.state.save()
            return rows

        account = "https://" + accounts[0].split("/")[-1] + ".blob.core.windows.net"
        controls = StorageControls(self.lifecycle.native, account=account, suite_id=report["run_id"], admit=admit)
        native = self.lifecycle.native
        previous = getattr(native, "deadline", None)
        native.deadline = min(previous or float("inf"), time.monotonic() + 900)
        try:
            driver = RevisionProbe(self.lifecycle, admit=admit)
            for app in self.lifecycle.value["outputs"]["appInventory"]:
                actor = app["app"].split("/")[-1].removeprefix(self.lifecycle.id + "-")
                principal = hashlib.sha256(str(UUID(app["identityPrincipalId"])).encode()).hexdigest()
                phase["identities"][actor] = principal
                if actor == "reference-data":
                    continue
                origin_run = uuid4().hex
                report["operation_ids"].append(origin_run)
                phase["snapshots"][origin_run] = {"before": controls.products()}
                self.lifecycle.state.save()
                result = driver.execute(app, actor, origin_run, mode="origin-boundary", deadline=phase["deadline"])
                operations = bind_origin_result(result, actor=actor, run_id=origin_run, principal=principal,
                    origin=self.lifecycle.value["probe_intents"][origin_run]["origin"])
                phase["origins"].extend(retain(result["observations"], operations))
                phase["snapshots"][origin_run]["after"] = controls.products()
                self.lifecycle.state.save()
                if result["state"] != "complete":
                    raise Blocked("origin_worker_partial_requires_reconciliation")
                gateway_run = uuid4().hex
                report["operation_ids"].append(gateway_run)
                self.lifecycle.state.save()
                result = driver.execute(app, actor, gateway_run, deadline=phase["deadline"])
                rows = result["observations"]
                if any(row.get("caller") != actor or row.get("run_id") != gateway_run for row in rows):
                    raise Blocked("gateway_worker_authority_binding_conflict")
                operations = [identity(row.get("operation_id")) for row in rows]
                if len(set(operations)) != len(operations):
                    raise Blocked("gateway_worker_duplicate_operation")
                phase["gateway"].extend(retain(rows, operations))
                self.lifecycle.state.save()

            async def operator():
                async with httpx.AsyncClient(follow_redirects=False, trust_env=False, timeout=30) as client:
                    return await operator_discovery(self.lifecycle, run_id=report["run_id"],
                        deadline=phase["deadline"], admit=admit, client=client)
            control = asyncio.run(operator())
            phase["gateway"].extend(retain([control], [control["operation_id"]]))
            phase["state"] = "observed"
        except (AzureError, OperationError, ValueError, TimeoutError, Blocked):
            phase["state"] = "blocked"
            raise Blocked("boundary_probe_phase_incomplete") from None
        finally:
            native.deadline = previous
            self.lifecycle.state.save()
        return phase["gateway"]

    def evaluate(self, report, evidence):
        phase = report.get("boundary_phase", {})
        if not phase.get("origins"):
            return []
        snapshots = phase.get("snapshots", {})
        observer_rows = [row for pair in snapshots.values() for side in ("before", "after")
                         for row in pair.get(side, {}).values()]
        bindings = {(r.get("request_id"), r.get("operation_id"), r.get("target")) for r in observer_rows}
        operators = {row.get("runtime_identity") for row in evidence if row.get("source") == "storage"
            and (row.get("request_id"), row.get("client_request_id"), row.get("target")) in bindings
            and hash_value(row.get("runtime_identity"))}
        observer = next(iter(operators)) if len(operators) == 1 else None
        subscriptions = self.lifecycle.value["outputs"]["inventory"]["gateway"]["subscriptions"]
        output = []
        for row in phase.get("origins", []):
            actor = row.get("caller")
            pair = snapshots.get(row.get("run_id"), {})
            evaluations = []
            for control in phase.get("gateway", []):
                caller = control.get("caller")
                subscription = next((rid for rid in subscriptions if rid.endswith("/" + caller)), None)
                checked = evaluate_origin(row, control, pair, evidence,
                    runtime_identity=phase["identities"].get(actor), observer_identity=observer,
                    subscription_id=subscription)
                evaluations.append((checked, control))
            selected = next((item for item in evaluations if item[0]["status"] == "pass"),
                next((item for item in evaluations if item[0]["status"] == "fail"), None))
            result, control = selected or ({"check_id": row.get("check_id"), "status": "blocked",
                "reason": "origin_service_control_or_no_effect_proof_missing"}, {})
            result["actual"] = {"observation": row, "control": control,
                                "before": list(pair.get("before", {}).values()),
                                "after": list(pair.get("after", {}).values())}
            output.append(result)
        return output
