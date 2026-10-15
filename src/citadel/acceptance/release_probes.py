"""Enabled-only release faults over genuine drafts and real conditional storage."""

import math
import asyncio
import time
from uuid import uuid4

from citadel.evidence.manifests import sha256
from citadel.operations import Operations, OperationError, identity
from .faults import _DropCommittedResponse, rejected
from .oracle import hash_value


RELEASE_CHECKS = frozenset({"fault.dropped-committed-release",
    "fault.concurrent-exact-draft-release", "fault.concurrent-different-operation-release"})


def validate_source(value):
    if (not isinstance(value, dict) or value.keys() != {"run_id", "draft"}
            or not isinstance(value["draft"], dict)
            or value["draft"].keys() != {"artifact_id", "version", "sha256"}
            or type(value["draft"]["version"]) is not int or value["draft"]["version"] < 1
            or not hash_value(value["draft"]["sha256"])):
        raise ValueError("An exact observed draft and original run are required")
    identity(value["run_id"])
    identity(value["draft"]["artifact_id"])
    return value


class _ConcurrentCommits:
    def __init__(self, ledger, deadline):
        self.ledger, self.deadline = ledger, deadline
        self.barrier, self.arrivals, self.conflicts = asyncio.Barrier(2), 0, 0

    async def read(self):
        return await self.ledger.read()

    async def commit(self, document, etag, *, deadline):
        self.arrivals += 1
        if self.arrivals <= 2:
            async with asyncio.timeout(max(0, min(30, self.deadline - time.time()))):
                await self.barrier.wait()
        try:
            return await self.ledger.commit(document, etag, deadline=min(deadline, self.deadline))
        except OperationError as exc:
            if exc.code == "conflict":
                self.conflicts += 1
            raise


class ReleaseProbes:
    def __init__(self, ledger, *, drafts, reference, workload, enabled, source_run, deadline):
        if (enabled is not True or workload != "release-reviewer"
                or type(deadline) not in (float, int) or not math.isfinite(deadline)
                or not time.time() < deadline <= time.time() + 900):
            raise ValueError("Only a bounded, explicitly enabled actual reviewer may run release faults")
        self.ledger, self.drafts, self.reference = ledger, drafts, reference
        self.run_id, self.deadline = identity(source_run), deadline

    async def concurrent_release(self, draft_ref, *, operation_id=None, distinct_operations=False):
        if type(distinct_operations) is not bool or time.time() >= self.deadline:
            raise ValueError("An unexpired fixed two-participant race is required")
        operation = identity(operation_id or uuid4().hex)
        identifiers = ([identity(operation + "-a"), identity(operation + "-b")] if distinct_operations
                       else [operation, operation])
        setup = Operations(self.ledger, workload="release-reviewer")
        owners = []
        for identifier in dict.fromkeys(identifiers):
            await setup.accept("evidence-assessor", "release", identifier, {"draft": draft_ref},
                               run_id=self.run_id, deadline=self.deadline)
            owners.append(await setup.claim("evidence-assessor", "release", identifier,
                                            worker=uuid4().hex, lease_seconds=180))
        if not distinct_operations:
            owners *= 2
        transport = _ConcurrentCommits(self.ledger, self.deadline)
        clients = [Operations(transport, workload="release-reviewer") for _ in range(2)]
        before, _ = await self.ledger.read()
        results = await asyncio.gather(*[
            client.release(owner, draft_ref, drafts=self.drafts, reference=self.reference)
            for client, owner in zip(clients, owners)], return_exceptions=True)
        for result in results:
            if isinstance(result, BaseException):
                raise result
        after, _ = await self.ledger.read()
        return {"operation_id": operation, "operation_ids": identifiers, "states": [row["state"] for row in results],
            "result_hashes": [row["result"]["sha256"] for row in results],
            "artifact_count": sum(len(versions) for versions in after["findings"].values()),
            "simultaneous_commits": min(2, transport.arrivals), "conditional_conflicts": transport.conflicts,
            "draft_sha256": draft_ref["sha256"],
            "before_count": sum(len(versions) for versions in before["findings"].values()),
            "before_sha256": sha256(before["findings"]), "after_sha256": sha256(after["findings"])}

    async def committed_response_loss(self, draft_ref, *, operation_id=None):
        if time.time() >= self.deadline:
            raise OperationError("deadline", "Expired release control cannot dispatch")
        operation = identity(operation_id or uuid4().hex)
        transport = _DropCommittedResponse(self.ledger)
        reviewer = Operations(transport, workload="release-reviewer")
        await reviewer.accept("evidence-assessor", "release", operation, {"draft": draft_ref},
                              run_id=self.run_id, deadline=self.deadline)
        owner = await reviewer.claim("evidence-assessor", "release", operation,
                                     worker=uuid4().hex, lease_seconds=180)
        before, _ = await self.ledger.read()
        transport.armed = True
        response = await rejected(lambda: reviewer.release(
            owner, draft_ref, drafts=self.drafts, reference=self.reference))
        fresh = Operations(self.ledger, workload="release-reviewer")
        status = await fresh.status("evidence-assessor", "release", operation)
        if status["state"] != "succeeded" or status["result"].get("kind") != "finding":
            raise OperationError("data_integrity", "Actual committed release was not observed")
        result = status["result"]
        finding = await fresh.get_finding(result["artifact_id"], result["version"])
        replay = await rejected(lambda: fresh.claim(
            "evidence-assessor", "release", operation, worker=uuid4().hex))
        after, _ = await self.ledger.read()
        return {"operation_id": operation, "state": status["state"], "response": response, "replay": replay,
            "artifact_id": result["artifact_id"], "version": result["version"], "sha256": sha256(finding),
            "draft_sha256": finding["draft"]["sha256"],
            "artifact_count": sum(len(versions) for versions in after["findings"].values()),
            "before_count": sum(len(versions) for versions in before["findings"].values()),
            "before_sha256": sha256(before["findings"]), "after_sha256": sha256(after["findings"])}
