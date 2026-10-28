# Development and merge test contract

The full offline unit suite below is the contributor development/merge test
gate. Run focused areas while iterating and the full command before merging.
No other suite, catalogue completion, cloud evidence or human narrative signoff
is a development/merge prerequisite.

From the repository root, in the installed project's pinned Python environment:

```sh
python -m unittest discover -s tests/unit -v
```

For focused feedback, replace `<area>` with a filename stem below:

```sh
python -m unittest discover -s tests/unit -p 'test_<area>.py' -v
```

For example:

```sh
python -m unittest discover -s tests/unit -p 'test_candidate_planner.py' -v
```

The explicit start directory matters: root `tests` discovery can report a
misleading zero-test success for the older nested suites. Unit test modules are
flat; `fixtures/` holds labelled, fictional reference rows and a canned model
response, not downloaded source data or actual inference.
The gate began with 75 migrated units; subsequent feature slices add tests.
Focused commands select matching flat test modules. Use the runner's reported
count for the current total; a zero-test result is not a successful gate.
The `candidate_planner` focused example includes four cases.

These commands require only the already-installed project dependencies. No Azure
deployment, credentials, Docker, real model, network, retained dataset,
telemetry collection or production-duration waits are needed. Ambient cloud
configuration does not select live tests or transports.

`.github/workflows/unit-tests.yml` runs the full explicit command on pushes,
pull requests and merge queues, using CPython 3.12.15 and the hash-locked
application/build dependencies. Installation may access the package registry;
the test step needs no network, Docker, credentials or Azure resource. No
numerical timing benchmark or coverage target is required. Hosted workflow
execution and branch-protection configuration are not established by local
validation.

Validate packaging changes with a non-editable wheel installation and
`PYTHONPATH` unset, then run these same commands from the checkout root.
Source-path overrides or editable installs alone can mask installation-layout
failures. The Operator CLI resolves deployment assets and source fingerprints
from that invocation checkout, not from `site-packages`; deployment still needs
the checkout's infrastructure/image inputs, which are not wheel resources.

Client-only refresh and retry-confirmation behavior has a dependency-free local gate, using Node 20+
and its built-in test runner (no npm install, browser or network):

```sh
node --test tests/client/*.test.mjs
```

The same workflow runs it after the Python gate. Tests use controlled visibility
and timers to cover selected-active-only scheduling, coalesced manual/automatic
requests, hidden/history/terminal/unknown/exhausted stopping. Server-side tests
own cross-tab physical-read coalescing, timestamps and stale projections.
Retry client tests cover unchecked/cancelled confirmation and duplicate-submit
denial; they never schedule execution or retry a lost response.

## Boundaries and focused areas

| Area | Behavior exercised |
| --- | --- |
| `candidate_planner` | Public `Runtime.accept`/status/task result: complete selection, missing-width replacement, rejection/exhaustion without author dispatch, model outage without replay. |
| `evidence_assessor` | Actual private draft persistence and exact reviewer input, rejection propagation and failure before draft/release. |
| `release_reviewer` | Exact requested immutable version rather than latest draft, hash denial, independent recheck rejection and private-field exclusion from actual saved findings. |
| `briefing_author` | Actual saved narrative/citations/caveats, duplicate-reference denial and approved-but-incomplete evidence denial before inference. |
| `planning_observation` | Actual Planner/Author owner services and authenticated HTTP presentation: all saved decisions/replacements, exact original released citations, filtered private fields, incomplete/exhausted/legacy history, bounded responses, physical admission, total deadlines and independently stale panels. |
| `evidence` | Pure completeness, raw/parsed values, source/overlay provenance, bounded candidates and shareable-projection rules. |
| `operations`, `completion` | Conditional immutable approval, exact versions, privacy, ownership, lost-response reconciliation, atomic product/result publication and closed receipts. |
| `accounting`, `read_tickets` | Finite inherited budgets/deadlines, charged retries, physical reads, shared-store concurrency/reconstruction/exhaustion and ambiguous marker admission refusing dispatch. |
| `peer_reads` | Actual gateway-client exact-version/hash checks through controlled HTTP; a failed finding read spends its allowance and cannot dispatch again after exhaustion. |
| `recovery`, `operator_quiescence` | Fencing, no replay/refund, restricted explicit retry, immutable deadlines and quiescent partial work staying incomplete. |
| `operator_recovery*` | Real hosted recovery handlers/client, durable duplicate/lost-response reconciliation, bound child/private effects, proof-read charging, auth/CSRF denial and mutable-cache invalidation. No cloud calls or automatic replay. |
| `operator_retry*` | Separately confirmed real owner/backend/client retry; authoritative no-commit, original deadline/remaining accounting, stale fencing, admission blockers, duplicate/lost/ambiguous/restart safety and cache invalidation. Controlled model/peer responses, not a whole-flow or cloud test. |
| `gateway`, `startup` | Local ASGI authorization/signature/path denials and explicit workload configuration/capability validation. |
| `operator_checkout` | Relocated-package CLI uses invocation-checkout deployment resources and still denies unconfirmed paid actions. |
| `operator_web*` | Actual protected HTTP handlers/server-rendered chooser, fake-time sessions/throttling, private login configuration and controlled deployment contracts; see [operator-web.md](operator-web.md). |
| `submission`, `browser_scenarios`, `scenario_summary`, `observation` | Actual hosted Planner/HTTP dispatch, immutable intent before execution, duplicate/ambiguous refusal, shared CLI admission, fixed scenario bindings, saved summary privacy and shared observation/cache behavior. |

Agent behavior tests execute **one runtime per independently exercised agent**.
Observation HTTP cases may compose independently seeded owner services; peer
responses never execute another agent or a whole-flow harness.
`agent_fixtures.py` supplies controlled
peer-service responses, `MemoryLedger`, a fake clock and a real `GovernedModel`
with HTTPX2's `MockTransport`. Assertions concern the agent's decisions,
saved products and denied boundary calls, not just fixture responses. Peer
responses do not execute another agent; they do not prove child-protocol or
delegated-accounting wiring. The separate shared-rule and local handler tests
exercise those owning boundaries where selected.

Private-file reads in quiescence validation are controlled filesystem responses;
the real proof validator and CLI refusal run without opening Operator state.
`Accounting` accepts an optional injected `sleep`; `runs_quiescent` accepts an
optional `clock`. Production defaults remain ordinary asyncio sleep/wall time.

## Migration and claim limits

The isolated evidence, operation, gateway, completion, startup, recovery,
read-ticket and Operator proof checks were relocated by behavior. Optional
protocol/SDK diagnostics reuse the relocated signing/configuration/recovery
helpers; the unit gate imports no optional test suite or whole-flow harness.
Useful broader diagnostics remain intact and are not dependencies of these
commands.

Passing units establishes behavior under controlled inputs only. It proves
neither deployed Azure/APIM enforcement, real model quality, cloud
reproducibility, telemetry delivery nor actual demo success. Historical cloud
results and incomplete/blocked verification remain unchanged; nothing here
closes or marks real-cloud verification passed.

## Optional diagnostics, not additional gates

Choose a diagnostic explicitly for an investigation; do not discover all nested
suites as a development/merge requirement. Use the same installed environment
from the repository root. Retained helpers/probes and the 278-check catalogue
are diagnostic reference, not a parallel mandatory programme. Two consecutive
cloud passes, fresh-deployment proof and human narrative signoff are retired as
development/merge obligations; the legacy reporter still requires its original
proofs before it will label a diagnostic report complete.

| Diagnostic | Explicit command / prerequisites |
| --- | --- |
| Installed SDK/stack serialization | `python -m unittest discover -s tests/stack -v`; exact pinned runtime/dependencies. Optional Docker smoke and lock maintenance are in [stack.md](stack.md), not required by the unit gate. |
| Protocol handlers and in-process multi-agent scenarios | `python -m unittest discover -s tests/runtime -v`; installed SDKs and local controlled transports. For retained-source cases, set `CITADEL_EVIDENCE_DATA` to the already acquired pinned snapshot. Unset live opt-ins for a local-only run; these scenarios can wait/poll longer than units. See [runtime.md](runtime.md). |
| External-data evidence checks | `python -m unittest discover -s tests/evidence -v`; genuine-snapshot cases need `CITADEL_EVIDENCE_DATA` pointing to retained pinned data, otherwise skip. Dataset acquisition is a separate explicit network action, never a unit prerequisite. See [evidence.md](evidence.md). |
| Persistence/Blob SDK integration | `python -m unittest discover -s tests/operations -v`; controlled local storage transports unless live opt-ins are set. See [operations.md](operations.md). |
| Gateway and infrastructure contracts | `python -m unittest discover -s tests/gateway -v`; local ASGI checks. `python -m unittest discover -s tests/infra -v` additionally requires the existing verified Bicep 0.48.1 executable via `BICEP_EXECUTABLE`. See [infrastructure.md](infrastructure.md). |
| Operator lifecycle and legacy acceptance tooling | `python -m unittest discover -s tests/operator -v` or `python -m unittest discover -s tests/acceptance -v`; controlled CLI/HTTP/SDK fixtures and subprocess/probe harnesses, potentially long-running. No real deployment proof is supplied by these local suites. |
| Live runtime | Explicit `CITADEL_RUNTIME_LIVE=1`, deployed gateway and private Operator credential; dispatches paid APIM/model/storage calls. See [runtime.md](runtime.md#optional-diagnostics). |
| Live storage/release | Explicit `CITADEL_STORAGE_TESTS=1` / `CITADEL_RELEASE_STORAGE_TESTS=1` plus allocated workload identity, containers and exact artifact bindings. Creates retained probe blobs; see [operations.md](operations.md#errors-and-cloud-probes). |
| Legacy cloud acceptance/reporting | `python -m citadel.operator acceptance`, `--collect-only`, and `review-acceptance` require private deployment state and the actual evidence/review described in [acceptance.md](acceptance.md). Paid probes may mutate workload configuration; never run implicitly or during presentations. |

Do not enable live flags or acquire data just to satisfy the unit gate. Optional
diagnostic failures do not block the migration, and successful local diagnostics
do not establish cloud enforcement. When deploying/running/managing the demo,
retain real readiness and authorization checks, inventory/resource ownership,
explicit paid-action approval, private credentials, finite accounting and
inventory-scoped manual teardown. `azure.yaml` remains the guarded deployment
entrypoint, not a development/merge test workflow.
