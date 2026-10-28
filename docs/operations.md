# Durable operations and release persistence

Issue 16 supplies persistence/accounting interfaces, **not** an HTTP service, model
orchestrator, deployment, or proof of cloud authorization.

The development/merge gate is the offline unit suite in [testing.md](testing.md).
From the repository root in the installed pinned environment:

```sh
python -m unittest discover -s tests/unit -v
python -m unittest discover -s tests/unit -p 'test_operations.py' -v
```

The focused command is for iteration. The broader
`python -m unittest discover -s tests/operations -v` suite is an **opt-in
diagnostic**: local integration uses deterministic conditional storage and the
actual pinned Blob SDK with an offline HTTP transport. With live opt-ins unset,
cloud probes explicitly skip. This is not a requirement to run all nested
suites or prove deployed authorization before merging.

## Authority and storage

`citadel.operations.Operations(ledger, workload=...)` is an application interface.
Its `caller` and `action` arguments are **trusted adapter inputs**, never fields
copied from a request body. Runtime integration must derive caller from validated
gateway context and choose the action from its authorized handler. For status,
look up the original invocation action, not the gateway's `status` action label.
Status does not accept a body-claimed owner and does not invoke an agent.

Use exactly one inventoried ledger per capability, not a new ledger per process,
replica, operation, or restart. Workload names are `candidate-planner`,
`evidence-assessor`, `release-reviewer`, and `briefing-author`.

| Ledger | Container authority |
| --- | --- |
| Draft versions plus their local submission operations | Evidence Review `drafts`: assessor RW, reviewer R |
| Findings, uniqueness registry, release operations | Evidence Review `findings`: reviewer RW only |
| Agent execution/status and delegated budgets | Agent's own operations container, self RW only |
| Atomic planning results | Planner/author's own operations or planning-product container, self RW only |

No shared all-agent accounting container or identity is needed. A prefix is not an
RBAC boundary. Reviewer uses `DraftReader` on the separate **read-only** draft
client; planner/author never receive that client. Released reads run alongside
reviewer via the existing authorized capability, not direct planning storage reads.

`managed_ledger(account_url=..., container=..., client_id=...)` uses only the exact
allocated `ManagedIdentityCredential(client_id=...)`, Blob API `2026-10-06`, and
SDK retries disabled. No operator credential chain, shared key, SAS, or storage
account creation. Identity/container choices are nonsecret inventoried config.
Code-level workload checks complement, not replace, container-scoped Azure roles.
The pinned SDK also has a separate three-attempt truncated-body download loop.
A per-read HTTP hook blocks its second request **before dispatch**, even with
`retry_total=0`; an actual-SDK fault test verifies one GET, not three.

## Operation lifecycle

1. `accept(caller, action, operation_id, inputs, run_id=..., deadline=...)` persists
   `pending` before acceptance. Canonical input hash binds inputs **and** run/deadline.
   Same identity/input returns existing status; different input conflicts. Deadline
   is absolute Unix UTC, inherited unchanged, and cannot exceed 900 seconds.
   Other operations in the same ledger/run cannot reset it.
2. `claim(..., worker=..., lease_seconds=60)` atomically changes pending to running
   and returns an `Ownership` execution token. A second claimant conflicts.
   `renew(token)` requires the still-live owner; it never revives an expired owner.
3. Use `begin_external(token, request_id, downstream_input_hash)` **before** any
   side-effecting invocation. Dispatch only after its definite successful return.
   A lost admission response means query status, not dispatch again.
4. `reconcile_external(token, request_id, status)` consumes a response retrieved
   from the separately authorized downstream status capability. Missing, pending,
   running, and indeterminate remain unresolved; input hashes must match.
5. `complete(token, product=...)`, `submit_draft`, or `release` publishes result
   metadata and the artifact in **one conditional Blob commit**. Status exposes
   only state, IDs, input hash, deadline, generation, and opaque result references.
   Planning `completed_result(...)` returns content only after atomic success.
   Structured product content still requires downstream runtime semantic validation.

No automatic work enumeration, message broker, replay, or restarted worker takeover.
`status(...)` is read-only, including after restart. A missing operation returns
`missing`; a missing ledger raises `missing`. Neither proves non-execution.

Explicit `fence(...)` after ownership expiry increments the durable generation.
If all effects are proven absent, state becomes `failed_no_commit`; otherwise
`indeterminate`. Only the former permits `retry(...)`, retaining identity/input
and the **same deadline**. The old generation cannot commit. `recover_external`
can reconcile an already fenced indeterminate operation with authenticated
downstream receipts. Only all-fenced-no-commit receipts make it retryable.
Succeeded downstream effects remain partial/indeterminate locally after a crash;
recovery does not replay application logic or invent a completed result.

Legal transitions are pending → running; pending/running → fenced
failed_no_commit/indeterminate; running → succeeded; indeterminate →
failed_no_commit after explicit proven-no-commit recovery; failed_no_commit →
pending on explicit retry. Succeeded is terminal. Fences/recovery metadata may be
written after expiry; business artifacts may not.

An ambiguous write raises `OperationError(code="indeterminate")`. Do **not** retry
it. Read durable status/result using the same identity. A lost successful
completion response leaves durable `succeeded`, not an overwritten error state.
Only definitive storage precondition rejections are retried for competing release
approvals (maximum two, with one/two-second backoff). Other contention is explicit.

## Drafts and approved findings

Use existing `ReferenceData.shareable_projection` revalidation; persistence does
not redefine parsing, completeness, caveats, hashing or fixture semantics.

```python
# Authenticated caller is supplied by the trusted service adapter.
request = {"draft": draft, "expected_version": preceding_version}
await drafts.accept(caller, "submit-draft", draft["operation_id"], request,
                    run_id=run_id, deadline=inherited_deadline)
owner = await drafts.claim(caller, "submit-draft", draft["operation_id"], worker=worker_id)
status = await drafts.submit_draft(owner, draft, expected_version=preceding_version,
                                  reference=verified_reference)
draft_ref = {key: status["result"][key] for key in ("artifact_id", "version", "sha256")}
```

Local draft submission is a distinct operation from the outer assessment. It
does **not** complete that outer assessment or introduce a new network route.
Assessor must obtain release before completing its outer A2A assessment result.
Keep its execution ledger in `assessor-operations`, submission ledger in `drafts`.

Versions start at one. Corrections require the exact preceding version; incompatible
concurrent writers conflict, never overwrite. Prior versions retain their original
hash/content. Source/profile/fixture provenance is fixed within each ledger/run.

Reviewer accepts `{"draft": draft_ref}`, reads the exact persisted version/hash
through `DraftReader`, then calls `release(token, draft_ref, drafts=reader,
reference=rechecked_reference)`. The runtime must obtain that rechecked reference
through its allowed Reference Data MCP path; injecting `ReferenceData` locally is
not proof of MCP traffic. Reviewer identity is the configured executing workload,
not a claimed request field or model output.

Finding ID deterministically identifies the logical draft; finding version equals
draft version. Uniqueness is indexed by draft ID/version and checked against the
exact hash, independently of approval operation ID. Repeated/concurrent approvals
return the same committed projection. Private content is absent from findings.
An insufficient finding can be released, with all caveats intact. A later draft
version is not automatically released. `get_finding(id, version)` has no latest
default and returns only a committed exact projection.

## Persistence, fencing and boundedness

Each ledger is a single canonical JSON block blob, capped at 4 MiB. The sample's
bounded evidence fits this design; exceeding it fails explicitly, without pruning
immutable history. Scale-out/migration is not silently substituted.
Deployment/probe bootstrap calls `initialize()` once, with create-if-absent
semantics. Never initialize a missing ledger as operation recovery.

Every update has an ETag precondition **and a 15-second Azure lease**. The SDK
lease response's server Date, including its one-second precision allowance, must
place lease expiry before the operation/ownership deadline. The lease is never
renewed. Delayed writes carry the expired lease ID and are rejected by storage,
even without a competing writer. Storage requires more than 16 seconds remaining;
late work fails conservatively rather than pretending it can commit safely.
Local ownership renewal should happen well before this margin.

Azure documents writes with expired lease IDs as HTTP 412:
[Lease Blob state outcomes](https://learn.microsoft.com/rest/api/storageservices/lease-blob#outcomes-of-use-attempts-on-blobs-by-lease-state).
The opt-in real-service expiry test remains required; local transport tests do not
establish Azure behavior, timing, networking, or RBAC.

## Durable accounting interface

`citadel.operations.limits.Accounting` owns one durable root run on planner's
ledger. `start_run` admits one run at a time for 900 seconds. `start_agent` charges
one of 42 executions; a repeated execution ID cannot replay. `candidate` admits
at most 20 distinct pool identifiers (pool membership/order is the planner's job).

`model` reserves before sending: 128 attempts/run, 8/execution, maximum 16,000 input
and 2,000 output tokens/attempt, 1,000,000 aggregate tokens. Pass conservative upper
bounds including all prompt/tool/protocol overhead, never optimistic estimates.
Reservations are never refunded, including ambiguous/failed calls.
Only one outstanding model or child holds admission. Rolling admission enforces
12 requests/minute and at most 120,000 reserved tokens/minute, lowered by configured
actual quota. Five-second minimum spacing is conservative. Completed-model time
extends the rate-history entry so delayed dispatch cannot evade rate accounting.

`delegate` atomically precharges **disjoint** agent/model/token/read allowances.
It transfers exclusive model admission and rate history to one child on an
existing allowed A2A edge; no extra status/callback route or cross-team identity.
`adopt(grant, authenticated_issuer=...)` persists once on the child's own ledger.
Child may subdivide (assessor → reviewer); deadlines never restart.
Parent can poll with its remaining read allowance but cannot start another agent,
model, or delegation until a verified child `close` receipt is `settle`d.
Get receipts over existing response/status paths and verify the child transport;
never trust an operator-supplied grant, receipt, or claimed issuer. An unresolved
child/model blocks continuation conservatively. No restart reconstructs a permit
or silently dispatches a charged attempt. Unused delegated allowances are burned.

`model` returns a **60-second absolute attempt deadline** intersected with the run.
Only definite response completion calls `finish_model`; an ambiguous timeout keeps
admission occupied. Runtime must enforce returned deadlines at transport dispatch,
disable hidden framework/SDK retries, and reserve every new actual attempt.
`exchange_deadline` intersects A2A exchanges with 180 seconds.
Runtime acceptance must finish within 10 seconds; owner-status polling is every
15 seconds. Those scheduling requirements belong to downstream runtime handlers.

`safe_read` charges each actual safe-read attempt, at most 512/run, with a
30-second absolute timeout; `read_with_retry` allows at most two retries with
backoff. All discovery, polling, reconciliation and SDK attempts count.
`reserve_reads` durably prepays a finite `ReadAllowance` for transport-level reads,
including ledger/accounting reads, avoiding recursive per-read accounting writes.
Attach it as `AzureBlobLedger.read_allowance` or pass it to `managed_ledger`.
Every SDK GET burns a ticket **before** sending. Never serialize, copy, or recreate
ticket books after restart: unused reservations stay spent. Exhaustion blocks.

Normal Azure reads fail closed without an allowance. `control_plane=True` is for
bounded provisioning, run-admission bootstrap, fixed-purpose acceptance probes,
and separately bounded post-deadline recovery—not a runtime bypass. On a fresh
root, bootstrap `start_run` and `reserve_reads`, burn two tickets for those two
admission reads, attach the resulting pool, then set `control_plane=False` before
executing. Child adoption/reservation likewise burns its bootstrap reads. Meter
all subsequent accounting reads too; keep separate prepaid envelopes for other
transports. Renewing an envelope consumes the old envelope's metadata read and a
new durable reservation. Do not borrow another workload's unused tickets.

## Errors and cloud probes

`OperationError.code`: `invalid_input`, `conflict`, `forbidden`, `missing`,
`not_found`, `incomplete`, `indeterminate`, `fenced`, `deadline`, `exhausted`,
`rate_limited`, `unavailable`, `result_limit`, `data_integrity`,
`unsupported_version`. Existing evidence validation preserves `EvidenceError`.
Storage errors deliberately omit credentials, request bodies and service messages.

Real-storage tests are **opt-in paid diagnostics**, never part of the contributor
gate. Run them **inside the explicitly allocated workload identity
environment**, only after authorized paid provisioning by the operator:

* `CITADEL_STORAGE_TESTS=1`
* `CITADEL_STORAGE_ACCOUNT_URL`, `CITADEL_STORAGE_CONTAINER`,
  `CITADEL_STORAGE_CLIENT_ID`, `CITADEL_STORAGE_WORKLOAD`
* `python -m unittest discover -s tests/operations -p test_storage_live.py -v`

These create isolated, retained acceptance blobs in the allocated container;
record them in the deployment inventory and remove only during manual teardown.
They test real ETags, races, reconstruction, dropped committed responses and
server-side expired-lease rejection. No account/role creation, token printing,
credential fallback, or automatic deletion.

For reviewer release concurrency, additionally enable
`CITADEL_RELEASE_STORAGE_TESTS=1`; provide `CITADEL_DRAFT_CONTAINER`,
`CITADEL_DRAFT_ID`, `CITADEL_DRAFT_VERSION`, `CITADEL_DRAFT_SHA256`,
`CITADEL_REFERENCE_BUNDLE`, `CITADEL_RUN_DEADLINE`, and optional
`CITADEL_FIXTURE` (default `base-source`). Use reviewer's own identity with
read-only draft/RW findings roles. Assessor must already have committed the
known disposable draft to `ledger-v1.json` through the public submission interface.
The test never grants reviewer draft-write authority or fabricates authorization.
Local success/skipped cloud tests do not satisfy deployed acceptance.
