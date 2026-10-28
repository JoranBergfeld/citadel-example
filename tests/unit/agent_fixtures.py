"""Single-agent boundaries only: no workflow harness, sibling runtime or cloud setup."""

import json
from contextlib import AsyncExitStack
from copy import deepcopy
from pathlib import Path

import httpx2

from citadel.evidence import ReferenceData
from citadel.evidence.manifests import sha256
from citadel.operations import Operations
from citadel.operations.limits import Accounting
from citadel.operations.testing import MemoryLedger
from citadel.runtime.agents import Runtime
from citadel.runtime.model import GovernedModel
from citadel.runtime.reference import RetrievedReference
from citadel.runtime.tickets import CAPACITY


FIXTURES = Path(__file__).parent / "fixtures"


def reference(fixture="base-source"):
    data = ReferenceData.from_rows(**json.loads((FIXTURES / "reference.json").read_text()))
    return data if fixture == "base-source" else data.with_overlay(data.fixture_manifests()[fixture])


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    async def sleep(self, seconds):
        self.now += seconds


class PeerResponses:
    """Controlled remote service contract; never executes a second agent.

    Child invocation/accounting and exact HTTP hash checks belong to separate
    boundary tests, not this deliberately small agent behavior double.
    """

    def __init__(self, data):
        self.data = data
        self.findings = {}
        self.references = []
        self.scopes = []
        for number in range(1, 5):
            ident = f"EB{number:02}"
            finding = {"airport_ident": ident, **data.assess_airport(ident),
                       "reviewer": "release-reviewer"}
            ref = {"artifact_id": f"finding{number}", "version": 1, "sha256": sha256(finding)}
            self.findings[ref["artifact_id"]] = finding
            self.references.append(ref)
            self.scopes.append({"run_id": "run1", "operation_id": f"review{number}"})
        self.calls = []
        self.authored = None
        self.rejected = set()

    async def reference(self, fixture, deadline, ident=None):
        self.calls.append(("reference", ident))
        if ident is None:
            return self.data.search_airports()
        return RetrievedReference(self.data.lookup_airport(ident), self.data.list_runways(ident))

    async def finding(self, ref, deadline, *, read_scope):
        self.calls.append(("finding", deepcopy(ref)))
        return deepcopy(self.findings[ref["artifact_id"]])

    async def child(self, runtime, ownership, payload, child, arguments, allowance):
        self.calls.append((child, deepcopy(arguments)))
        if child == "evidence-assessor":
            ident = arguments["airport_ident"]
            if ident in self.rejected:
                return {"kind": "rejected", "reason": "draft_evidence_mismatch"}
            index = int(ident[-2:]) - 1
            return {"kind": "collaboration", "finding": deepcopy(self.references[index]),
                    "read_scope": deepcopy(self.scopes[index])}
        if child == "briefing-author":
            self.authored = deepcopy(arguments)
            return {"status": "complete", "citations": deepcopy(arguments["findings"])}
        if child == "release-reviewer":
            return {"kind": "rejected", "reason": "draft_evidence_mismatch"}
        raise AssertionError(f"Unexpected external peer {child}")


class AgentCase:
    async def asyncSetUp(self):
        self.stack = AsyncExitStack()
        self.addAsyncCleanup(self.stack.aclose)
        self.clock = Clock()
        self.peers = PeerResponses(reference())
        self.model_requests = []
        self.model_status = 200
        self.drafts = MemoryLedger(clock=self.clock)
        self.artifacts = MemoryLedger(clock=self.clock)
        self.ledger = MemoryLedger(clock=self.clock)
        self.draft_store = Operations(self.drafts, workload="evidence-assessor", clock=self.clock)
        self.finding_store = Operations(self.artifacts, workload="release-reviewer", clock=self.clock)

    async def agent(self, role, **arguments):
        async def response(request):
            self.model_requests.append(json.loads(request.content))
            return httpx2.Response(self.model_status, json=(
                json.loads((FIXTURES / "model.json").read_text()) if self.model_status == 200
                else {"error": {"message": "controlled unit-fixture outage"}}))

        http = await self.stack.enter_async_context(
            httpx2.AsyncClient(transport=httpx2.MockTransport(response)))
        model = GovernedModel(role, "https://gateway.test", "unit-fixture-only", "unit-fixture",
                              http_client=http, clock=self.clock, sleep=self.clock.sleep)
        self.stack.push_async_callback(model.close)
        runtime = Runtime(role, self.ledger, model=model, peers=self.peers,
                          gateway_url="https://gateway.test", clock=self.clock,
                          artifacts=self.drafts if role == "evidence-assessor" else self.artifacts,
                          drafts=self.drafts)
        self.stack.push_async_callback(runtime.shutdown)
        self.payload = {"run_id": "run1", "operation_id": "run1", "fixture": "base-source", **arguments}
        self.caller = "operator"
        if role != "candidate-planner":
            parent = Accounting(MemoryLedger(clock=self.clock), workload="candidate-planner", clock=self.clock)
            await parent.start_run("run1")
            child = role if role != "release-reviewer" else "evidence-assessor"
            grant = await parent.delegate("run1", "child1", child,
                {"agents": 2, "models": 2, "tokens": 36000, "reads": CAPACITY[child]})
            self.caller = "candidate-planner"
            if role == "release-reviewer":
                assessor = Accounting(MemoryLedger(clock=self.clock), workload="evidence-assessor", clock=self.clock)
                await assessor.adopt(grant, authenticated_issuer="candidate-planner")
                grant = await assessor.delegate("child1", "review1", role,
                    {"agents": 1, "models": 1, "tokens": 18000, "reads": CAPACITY[role]})
                self.caller = "evidence-assessor"
            self.payload.update(operation_id=grant["grant_id"], grant=grant)
        return runtime

    async def execute(self, runtime):
        await runtime.accept(self.caller, self.payload)
        task = await runtime.task_status(self.caller, self.payload["operation_id"])
        status = await runtime.status(self.caller, self.payload["operation_id"])
        product = json.loads(task.artifacts[0].parts[0].text) if task.artifacts else None
        return status, product

    async def save_draft(self, *, version=1, expected_version=0):
        data = reference()
        op = f"draft-op{version}"
        draft = {"artifact_id": "draft1", "version": version, "schema_version": 1,
                 "run_id": "run1", "operation_id": op, "airport_ident": "EB01",
                 "private_notes": "Private unit-fixture assessment", **data.assess_airport("EB01")}
        ops = self.draft_store
        await ops.accept("evidence-assessor", "submit-draft", op,
                         {"draft": draft, "expected_version": expected_version}, run_id="run1", deadline=1900)
        owner = await ops.claim("evidence-assessor", "submit-draft", op, worker="unit-worker")
        await ops.submit_draft(owner, draft, expected_version=expected_version, reference=data)
        return {"artifact_id": "draft1", "version": version, "sha256": sha256(draft)}
