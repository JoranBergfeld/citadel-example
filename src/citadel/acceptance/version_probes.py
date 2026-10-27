"""Enabled-only draft-version contention using actual assessor conditional writes."""

import asyncio
import math
import time
from uuid import uuid4

from citadel.evidence.manifests import sha256
from citadel.operations import Operations, OperationError, identity
from .release_probes import _ConcurrentCommits


class VersionProbes:
    def __init__(self, ledger, *, reference, workload, enabled, run_id, deadline):
        if (enabled is not True or workload != "evidence-assessor"
                or type(deadline) not in (float, int) or not math.isfinite(deadline)
                or not time.time() < deadline <= time.time() + 900):
            raise ValueError("Only a bounded, explicitly enabled assessor may run draft-version faults")
        self.ledger, self.reference = ledger, reference
        self.run_id, self.deadline = identity(run_id), deadline

    async def concurrent_version(self, source, *, operation_id=None):
        if time.time() >= self.deadline:
            raise OperationError("deadline", "Expired draft-version control cannot dispatch")
        self.reference.shareable_projection(source)
        operation = identity(operation_id or uuid4().hex)
        identifiers = [identity(operation + suffix) for suffix in ("-v1", "-a", "-b")]
        first = source | {"artifact_id": operation, "run_id": self.run_id,
                          "operation_id": identifiers[0], "version": 1}
        assessor = Operations(self.ledger, workload="evidence-assessor")
        await assessor.accept("candidate-planner", "submit-draft", identifiers[0],
            {"draft": first, "expected_version": 0}, run_id=self.run_id, deadline=self.deadline)
        owner = await assessor.claim("candidate-planner", "submit-draft", identifiers[0],
                                     worker=uuid4().hex, lease_seconds=180)
        initial = await assessor.submit_draft(owner, first, expected_version=0, reference=self.reference)
        before = await assessor.get_draft(operation, 1, initial["result"]["sha256"])
        versions, owners = [], []
        for identifier in identifiers[1:]:
            version = first | {"operation_id": identifier, "version": 2}
            await assessor.accept("candidate-planner", "submit-draft", identifier,
                {"draft": version, "expected_version": 1}, run_id=self.run_id, deadline=self.deadline)
            owners.append(await assessor.claim("candidate-planner", "submit-draft", identifier,
                                                worker=uuid4().hex, lease_seconds=180))
            versions.append(version)
        transport = _ConcurrentCommits(self.ledger, self.deadline)
        clients = [Operations(transport, workload="evidence-assessor") for _ in range(2)]
        responses = await asyncio.gather(*[
            client.submit_draft(owner, version, expected_version=1, reference=self.reference)
            for client, owner, version in zip(clients, owners, versions)], return_exceptions=True)
        for response in responses:
            if isinstance(response, BaseException) and (
                    not isinstance(response, OperationError) or response.code != "conflict"):
                raise response
        statuses = [await assessor.status("candidate-planner", "submit-draft", identifier)
                    for identifier in identifiers[1:]]
        document, _ = await self.ledger.read()
        latest = document["drafts"].get(operation, {}).get("2")
        after = await assessor.get_draft(operation, 1, initial["result"]["sha256"])
        references = [{"artifact_id": operation, "version": 1, "sha256": sha256(after)}]
        if latest is not None:
            references.append({"artifact_id": operation, "version": 2, "sha256": sha256(latest)})
        return {"operation_id": operation, "operation_ids": identifiers,
            "states": sorted(row["state"] for row in statuses),
            "responses": sorted(row.code if isinstance(row, OperationError) else row["state"] for row in responses),
            "attempts": [{"operation_id": identifier, "state": status["state"],
                "response": response.code if isinstance(response, OperationError) else response["state"],
                "sha256": sha256(version)} for identifier, status, response, version in zip(
                    identifiers[1:], statuses, responses, versions)],
            "drafts": references, "source_sha256": sha256(source),
            "artifact_count": sum(len(rows) for rows in document["drafts"].values()),
            "simultaneous_commits": min(2, transport.arrivals), "conditional_conflicts": transport.conflicts,
            "before_sha256": sha256(before), "after_sha256": sha256(after)}
