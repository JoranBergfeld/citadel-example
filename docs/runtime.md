# Governed application runtime

Task [18](https://github.com/JoranBergfeld/citadel-example/issues/18) hosts four
Microsoft Agent Framework agents over official A2A 1.0 JSON-RPC, plus Reference
Data over official MCP 2025-11-25 Streamable HTTP. This is application
implementation, **not evidence of deployed APIM/Azure enforcement**.

## Standalone entrypoints and image

Each Container App uses the same locked image and this command:

```json
{"command":["python","-m","citadel.runtime"],"args":[]}
```

`CITADEL_TARGET` selects exactly one standalone application:
`candidate-planner`, `evidence-assessor`, `release-reviewer`, `briefing-author`,
or `reference-data`. No application hosts another team's identity. Listen port
is 8000; ingress and TLS/certificate configuration remain as in
[infrastructure.md](infrastructure.md). TCP health probes expose no business,
identity or data endpoint.

`python -m citadel.runtime --check-config` validates configuration without
network access. It does **not** validate credentials, quota, deployment or
authorization. Missing/invalid configuration exits unsuccessfully; production
startup failure never becomes a successful application endpoint.

The repository Dockerfile still defaults to its stack smoke tests. Deployment
must supply the application command above and an immutable image digest.
Its supported offline build remains:

```sh
docker build --network=none --platform linux/amd64 \
  --build-context "wheelhouse=$WHEELHOUSE" --build-arg OFFLINE=true \
  --tag citadel-runtime .
```

The wheelhouse must be the official hash-checked artifacts corresponding to
`requirements.lock`; no dependency pins or lock hashes were changed. The image
runs as 65532:65532. Only `.runtime-reference` and `.build` are prepared as
writable relative directories. The former holds Reference Data's verified
startup cache; the latter supports local container tests.

## Required configuration

Infrastructure supplies `AZURE_CLIENT_ID`, `CITADEL_TARGET`,
`CITADEL_GATEWAY_URL`, `CITADEL_BLOB_URL`, `CITADEL_VAULT_URL`,
`CITADEL_GATEWAY_CERTIFICATES`, `CITADEL_CONTEXT_KEYS`, `CITADEL_LIMITS`,
`CITADEL_BLOB_API_VERSION=2026-10-06`, and
`CITADEL_VAULT_API_VERSION=2025-07-01`. Trust keys are secrets, never CLI
arguments or logged configuration. HTTPS origins reject credentials, queries,
fragments, nonstandard paths and ports. Azure endpoints additionally require
their service DNS suffix.

The deployed Planner, Evidence Assessor and Release Reviewer also require trusted `CITADEL_DEPLOYMENT_ID` and
`CITADEL_OBSERVATION_BLOB_URL` (the inventoried platform accounting account).
The infrastructure supplies these to all workloads for later team projections;
they never select a workflow pool or authorize data access.

Agents additionally require:

| Variable | Contract |
| --- | --- |
| `CITADEL_MODEL_DEPLOYMENT` | Actual approved Azure model deployment name, routed only through APIM |
| `CITADEL_MODEL_TOKENS_PER_MINUTE` | Independently verified actual usable quota, integer 1–120000 |
| `CITADEL_SUBSCRIPTION_SECRET_NAME` | Exactly `subscription-<CITADEL_TARGET>` |
| `CITADEL_OPERATIONS_CONTAINER` | Planner: `planner-operations`; Assessor: `assessor-operations`; Reviewer: `reviewer-operations`; Author: `author-operations` |

The lifecycle's `applications.<target>.modelTokensPerMinute` field wires actual
verified quota into the app module. Omission produces **0 and startup failure**,
not an assumed 120000-TPM allocation. No new resource, route, permission or
shared storage identity is introduced.

Reference Data requires `CITADEL_REFERENCE_CONTAINER=reference`. It needs no
subscription/model credential. At startup it reads the eight exact prepared
bundle objects from that container, via the pinned Azure Blob SDK and assigned
managed identity. Each object has a bounded single GET, 30-second deadline and
hidden-download-retry guard. The existing `ReferenceData.from_bundle` validates
the independent source-row pin and all source/profile/fixture manifests.
Changed cached bytes fail instead of silently refreshing. No reference-dataset
write is available to Reference Data; its separate accounting-only marker role
cannot modify that dataset.

The lifecycle must prepare/upload that bundle and preinitialize six
`ledger-v1.json` blobs: the four operations containers plus Evidence Review's
`drafts` and `findings`. Use `empty_ledger()`/the existing deployment-only
initialization API. Runtime never creates missing state as evidence that work
did not happen.

Also preinitialize `planner-operations/active-run-slot.json` with `{}`. Its
infinite, run-specific Blob lease prevents concurrent new root admissions
without reading another run's ledger. Runtime releases it only after definite
root completion; crashes/ambiguity never trigger automatic replay or release.
Missing admission storage fails closed. Runtime creates immutable ticket/pool
objects only inside its already allocated operations container; no new identity,
container, permission, or HTTP proxy is needed.

### Retained-run observations

Planner's deployed `RunIndex` records immutable original owner/run/operation/input
bindings **before** root admission (also for CLI submissions), with a hard
256-run bound. Execution updates summary state. Refresh never creates records or
backfills old storage. Bootstrap initializes `retained-runs-v1.json` in
`planner-operations` using `empty_index()`; missing binding collections and
unavailable historical state remain unavailable, never confirmed empty.

Only the separate `operator-web` caller can GET `/operator/runs`,
`/operator/runs/page/{cursor}` and `/operator/runs/{run_id}` through Planner APIM.
The certificate/signed context remains required at the origin. Existing
workload status/GetTask ownership and 512 workflow reads are unchanged.

Reusable implementation seams:

- `runtime.observation.DeploymentReads.request(purpose, deadline=...)` opens a
  trusted deployment observation/proof context; `charge()` prepays a protocol
  dispatch. Capacities are 16,384/2,048, not supplied by requests.
- `runtime.state.ScopedLedger` prepays each actual storage GET; its request-local
  snapshots are free, not fictional physical reads. Do not use
  `control_plane=True` for observation/supporting reads.
- `RunIndex.resolve_in_scope(run_id)` returns the original internal binding to
  owning-service code. `observe` projects only safe summary/binding fields,
  never generic operation results, private drafts, receipts or paths.
- `operator.observation.ObservationClient` coalesces manual work and keys cached
  projections by deployment/run/projection/exact bindings. `invalidate(run_id)`
  is the seam for later explicit control actions.

Provisioning owns the two infinitely leased accounting descriptors; runtime
only renews their leases and creates conditional spent markers. No recursive
meter reads, read retries, refill, deadline extension, recovery or execution is
authorized by observation. The complete observation has a 30-second ceiling.

Evidence Review's owner implementation lives in
`runtime.evidence_observation.EvidenceObservations`; `agent_application`
installs its narrow Operator-only HTTP routes. It reads scoped owner ledgers,
verifies exact committed draft/release references and filters before HTTP
serialization. It never uses a workflow pool or private storage fallback.
Reviewer invocation admission retains an exact draft binding alongside the
original immutable input hash; observation never backfills old bindings.
New assessments persist `assessment_prose` separately from filtered private
notes. The release projection still excludes that prose from workload findings.
See [Operator Evidence Review](operator-web.md#evidence-review-private-drafts-and-exact-releases)
for routes, citation links and historical limitations.
These paths are locally tested; deployed APIM/Azure enforcement remains unverified.

Only explicit `ManagedIdentityCredential(client_id=...)` is used. Secret
acquisition reads the allocated subscription secret with the assigned identity,
zero automatic retries and a total timeout. There is no operator/developer
fallback, account key, SAS, privileged proxy or direct model endpoint.

## Application contract

Use the real Framework `A2AAgent`, the advertised gateway card and
`background=True`. Planner's one text part is JSON:

```json
{"operation_id":"opaque_run_id","run_id":"opaque_run_id","fixture":"base-source"}
```

The two root IDs must match; identities are 1–64 ASCII alphanumeric, underscore
or hyphen characters. Fixtures are `base-source`,
`missing-width-replacement`, or `no-alternative`. No caller identity is accepted
from message content.

Acceptance persists caller/action/input/run/deadline binding and claims a
fenced execution before returning, bounded by ten seconds. Follow up using
`GET /candidate-planner/operations/<operation_id>` every fifteen seconds;
retrieve a completed product with the official single-request
`A2AAgent.poll_task` (`GetTask`), not an SSE subscription. Agent cards and all
downstream URLs are gateway-only. Child invocations carry disjoint durable
budget grants over the existing approved A2A edges, not operator authority.

`GatewayTrust` wraps the entire application. It validates certificate and
signed request context before any router, MCP handler or application logic.
Status maps the validated gateway `status` action back to the original
`invoke` ownership key. Reviewer-hosted exact finding GETs are independently
authorized; they neither invoke the Reviewer nor grant status/draft access.
Finding reads carry `x-citadel-read-pool: <review-operation-id>`. A write-only
lease check verifies the durable binding of that funded pool to the exact
finding/version before any data GET. A locator is not caller authentication;
GatewayTrust still independently authorizes the caller and action. Exact
finding references/citations retain their original three-field schema.
OpenAPI/docs endpoints, task listing, cancellation, push callbacks and arbitrary
tools are not exposed.

Only three MCP tools exist: `search_airports`, `lookup_airport`, `list_runways`.
Their argument and evidence semantics are the existing evidence module's.
Optional MCP request `_meta` key `citadel-fixture` selects one of the verified
fixtures (omission selects base). The metadata is inside the signed request
body, not an unsigned routing header or an extra evidence-tool argument.

Planner explicitly visits the stable bounded pool, requests assessment and
review, reads exact released findings, replaces insufficient candidates, and
invokes Author only after three complete findings. Assessor submits an immutable
private draft before requesting Reviewer. Reviewer independently rereads MCP
evidence and applies the existing exact-version/hash projection and release
rules. A deterministic mismatch returns an explicit rejected decision without
publishing a finding. Author independently reads three exact released versions.
Products retain citations, provenance, overlay identity and mandatory caveats.
Exhausted pools never become completed briefs.

Every agent uses the real `Agent` and `OpenAIChatCompletionClient`; Azure model
inference goes through `/openai/v1/chat/completions`. Distinct role instructions
explain the application's restricted capabilities. Models receive no autonomous
network/tool execution loop. The deterministic workflow—not model discretion—
controls permissions, classification, publication and candidate selection.
Model prose is not a safety determination and still needs operator review.
Production has no fixture model response or simulated protocol success.

## Persistence, limits and incomplete work

`AzureBlobLedger` remains the production storage adapter. Operations/accounting
and atomic planning results use each workload's own operations ledger. Drafts
and release results use their existing authority-specific ledgers. The additive
outer-completion interface accepts only an exact public finding reference or
explicit rejection, plus the matching durably closed budget receipt; it cannot
publish findings or expose private prose. It exists because draft submission
must not complete an assessment before review.

The durable accounting baton transfers parent → child → authenticated closed
receipt. Parents cannot model/delegate while a child is unresolved. All real
workflow ledger reads and outgoing protocol read requests consume precharged
tickets; hidden Blob and model retry attempts are blocked at dispatch. Terminal
result `GetTask` charges its HTTP request plus one storage read, using one
storage snapshot. No process-global model/read counter is used.

All existing ceilings still intersect: 900-second inherited deadline,
20 candidates, 42 executions, 128/8 model attempts, 16000/2000 tokens per
attempt, one million aggregate tokens, 512 reads, one model request in flight,
12/minute and actual quota. UTF-8 byte bounds plus fixed message framing
conservatively bound prompt tokens. Model SDK retries are disabled, and an
HTTP-boundary single-dispatch permit blocks hidden Framework retries.
Model/A2A/read total deadlines are 60/180/30 seconds. Late/ambiguous model
responses never free model admission. Current networking does not automatically
retry failed reads; zero is within the maximum two automatic read retries.

Read admission is a finite durable ticket tree, not a process-local counter.
Before each physical GET or outgoing protocol read, a conditional
`If-None-Match: *` Blob PUT consumes a unique marker. Only a confirmed new
marker permits dispatch. Ambiguous creates burn capacity without authorizing a
read. Cursor hints may disappear or race: storage conditional creation remains
the authority. Marker/descriptor checks use bounded writes and never recursively
read a metering ledger. SDK retries are disabled.

Planner owns 512 tickets. Delegating an assessment irreversibly consumes 20
parent tickets and gives the Assessor exactly 20; 11 of those are similarly
delegated to its Reviewer. Author receives 16. There are no refunds, including
after authenticated closure. Thus disjoint descendant allowances plus the
parent's admitted reads cannot exceed 512. Closed pools retain only their
original finite remainder for status/exact finding reads, never a fresh quota.

External operator status/GetTask consumes its HTTP ticket and its actual
backend storage ticket. Admission retries and explicit recovery consume their
actual storage reads from that same caller-owned pool, including after restart.
Unknown pools fail before a ledger GET; exhausted operator status returns 429.
Agent HTTP reads are metered at `GatewayPeers`' physical request hook; their
backends independently meter actual storage GETs. No caller identity or
unverified request-body claim can select an unbounded control-read mode.

An execution/request-local snapshot avoids repeated reads of unchanged ledgers.
It advances only from a successful conditional write's returned ETag. Any
conflict/lost response invalidates it before a newly paid reconciliation GET.
Every commit still uses the existing storage lease, fencing and ETag checks.
Status may wait up to one second for a local completion event before one
durable read, within its ten-second handler bound; restart has no event to
wait for. Neither cached snapshots nor events establish durable authority.
Verified gateway agent cards are cached; MCP calls use the SDK's public typed
`send_request` to avoid redundant `tools/list` output-schema discovery for the
fixed evidence contracts. The actual twenty-member no-alternative fixture now
completes `bounded_pool_exhausted`, with all twenty assessments and 41 model
executions, under unchanged ceilings.

Restart never schedules persisted pending/running work. Identical submissions
return existing status; changed inputs conflict. Timeout, unavailable
infrastructure, rejection and insufficient evidence are distinct. Ambiguous
external effects stay incomplete; missing state is not proof of non-execution.
`mark_incomplete` fences local ownership without claiming `failed_no_commit`.
If no storage deadline/ticket remains, durable running state remains incomplete.
Existing explicit operations fencing/reconciliation/retry APIs are retained.
The hosted Operator now has a distinct, narrowly authorized recovery endpoint;
it is not a workload ownership bypass. See [hosted recovery](operator-web.md#explicit-check-and-recover).
The existing owner-bound `SendMessage` accepts metadata
`{"citadel_recovery": true}` to invoke explicit fencing of that same
input-bound operation. It never schedules persisted work and cannot recover a
different caller's operation or escape exhausted tickets.

Hosted `POST /operator/runs/{run_id}/recover/{request_id}` instead resolves the
original retained Planner binding and uses the deployment recovery-proof pool.
Parent services follow only exact recorded grants through separately authorized
`POST /operator/recovery/{operation_id}/{request_id}` control actions. Those
handlers never invoke `accept`, retry or workflow execution. Intent/proof/outcome
records share each owner's existing operation ledger; no UI team-data role or new
content store is introduced. Every physical ledger/protocol read is charged at
dispatch, including audit and supporting bindings, with a single 30-second total
deadline and no read retries. Quiescent partial work remains indeterminate and
retained; unresolved model admissions remain blocked.

## Development and merge gate

Use the installed project's pinned environment from the repository root:

```sh
python -m unittest discover -s tests/unit -v
python -m unittest discover -s tests/unit -p 'test_candidate_planner.py' -v
```

The full command is the development/merge gate; the second is a focused example
for iteration. The flat unit suite exercises agents independently and selected
shared boundaries without cloud, Docker, real models, external data or network.
See [testing.md](testing.md) for all focused areas and discovery/claim limits.

## Optional diagnostics

The broader suites below are **opt-in diagnostics**, not development/merge gates.
Neither all nested suites nor the legacy 278-check catalogue, two cloud passes,
fresh-deployment proof or human narrative signoff is required for development/
merge. Real deployment readiness and operational safeguards still apply to
explicitly running or managing the demo.

The broader local runtime suite uses real A2A/MCP/Framework/OpenAI/Blob SDK
serialization and ASGI hosts with controlled external transport adapters,
including in-process multi-agent scenarios and polling. Only tests provide
model fixtures and in-memory ledgers. With live opt-ins unset, the command
below stays local; set `CITADEL_EVIDENCE_DATA` to the already retained approved
snapshot to include both real-data workflow and Blob-bundle checks:

```sh
python -m unittest discover -s tests/runtime -v
```

`tests/runtime/test_live.py` is opt-in:
`CITADEL_RUNTIME_LIVE=1`, `CITADEL_LIVE_GATEWAY`, and `CITADEL_OPERATOR_KEY`.
It performs paid real workflow calls when enabled; ordinary validation never
enables it. It checks real acceptance, polling, exact caveated products and an
allowed/denied route control. The live runtime and storage probes and legacy
task20/21 reporting are optional investigations with distinct claim limits;
none replaces the offline development/merge gate.

Offline tests do not verify effective Azure authority/certificate/HMAC/policy
behavior, actual model inference/quota, storage fencing in the deployed topology, identity
rotation, deployed latency, telemetry export/collection, two full cloud passes,
operator narrative signoff, fresh deployment and teardown. SDK tracing and
sanitized local incomplete-work logs alone do not establish unsampled deployed
telemetry. Historical cloud evidence/status is unchanged; no outstanding
real-cloud verification is marked passed.
