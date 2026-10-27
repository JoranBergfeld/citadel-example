# Observable acceptance: implementation checkpoint

**Task 20 is not complete. Do not start task 21 or claim cloud acceptance from
the local tests.** The required coverage catalogue deliberately includes checks
whose deployed drivers/proofs are still absent. Such checks remain `blocked`;
rotation retirement cannot pass through placeholders. Denied-bypass continuation
requires its four independently verified, actually executed storage denials.

## Implemented public boundaries

Runtime acceptance covers the deployed sample, not Event Grid or subscription
security services. Externally classified Event Grid resources are reported but
neither validated nor adopted. Their presence does not block agent runtime
checks; it still blocks resource-group deletion. This exclusion does not relax
agent authorization, data-boundary, model, protocol or telemetry evidence.

- `citadel.acceptance.operator_hooks.run(lifecycle=..., check_id=..., run_id=...)`
  handles the documented operator hooks and `collect-evidence`. Existing private
  API Center human-plan evidence and deployed-runtime gates still apply.
- The full harness invokes the existing operator scenario path, not agent internals.
  The independent semantic oracle compares the immutable source, labelled fixture,
  exact ordered candidates, assessments, released-version/hash shapes and caveats.
  It rejects fabricated completed briefs for pool exhaustion.
- Each completed scenario is independently observed through six operator Blob
  reads (four operation ledgers, drafts and findings), under its original run
  deadline and a persisted six-read allowance. No workload read pool is refilled,
  no model call is added and interrupted observation intent is not replayed.
  Exact returned products, draft hashes, immutable findings, every completed
  assessor/reviewer execution and the author's citations/funded scopes must agree.
  Expected source/fixture and tool-result hashes come independently from the
  pinned Reference Data bundle and are bound into the deployment fingerprint.
- Actual Reference Data MCP handlers emit only tool-result/provenance hashes,
  using their authenticated HTTP caller/run/operation/request context. Scenario
  collection requires each real search/lookup/runway trace from application
  ingestion, the matching APIM subscription/request/target, all actual accepted
  A2A input bindings and all six observer Blob service receipts. Missing or
  substituted sources block; observed source/projection mismatches fail. Console
  logs, a semantic pass label or a successful export cannot substitute.
  Denied-bypass additionally re-evaluates all four earlier real denials/no-effects
  from its exact bound control attempt before the subsequent normal run.
- The private-field projection gate re-evaluates all four distinct scenario
  executions. Exact root/brief/finding field sets, nested source evidence and
  private-draft projections are checked without exporting drafts or prose.
  The sanitized report repeats these oracles; human narrative review still binds
  the exact private returned product, never a synthesized or inferred signoff.
- Inventory checks consume the actual ARM documents already queried by the
  lifecycle; they do not infer proof from `inventoryMetadataVerified`. Exactly
  five truthful environment records, actual attached identities, assigned
  principal/client configuration, immutable image/command and real REST findings
  metadata are independently compared with fingerprint-bound expectations.
  Duplicated environments or Agent-ID mislabelling fail. The Free-plan check uses
  only the existing validated private human portal proof, its evidence hash,
  request/resource-incarnation binding and observation time. An absent SKU,
  a template label or provider provisioning success cannot establish Free.
- Application ingestion has a count proof, not an SDK-acknowledgement assertion.
  Each process emits bounded per-run event streams with unique IDs and sequence
  numbers. Metadata-only health checkpoints hash every preceding event ID and
  retain the actual official exporter's submitted/acknowledged/failed/dropped/
  queued/in-flight counters. Quiescent streams retire rather than requiring
  unbounded deployment history. Checkpoints run off the request path every
  fifteen seconds; final draining and checkpoint delivery share the original
  single fifteen-second shutdown flush allowance.
  The collector requires every prefix event in actual application ingestion
  across all five assigned identities, including emitted events also observed in
  supplemental console logs. Missing prefixes/checkpoints, duplicate events or
  console-only records block; observed loss/hash conflicts fail. SDK acknowledgement
  remains explicitly `ingestion_verified=false`. Only health metadata may be
  queried for the extra fifteen-second checkpoint interval after the ordinary
  five-second correlation tolerance; business windows, run/read/model allowances
  and the persisted 600-second collection deadline do not change.
- `denied-bypass-controls` executes the actual storage providers and their permitted
  controls. It independently re-evaluates both planning identities' private-draft
  reads and finding overwrites, including unchanged targets and queried application/
  storage correlations. Only then can the existing `demo --scenario denied-bypass`
  dispatch a separate normal APIM collaboration. Genuine prior draft/finding
  products are required; on a fresh deployment run `comparison` first rather than
  seed fabricated artifacts. Interrupted/ambiguous probes are never resubmitted.
  Missing telemetry is polled at most forty times, fifteen seconds apart, within
  the persisted collection deadline. A full suite shares one total 600-second
  outstanding-telemetry allowance with these embedded controls; collection windows
  survive interruption. A passing four-control report is not full acceptance.
- `GatewayProbe` uses real HTTPX requests with the executing agent's allocated
  subscription. Discovery, forbidden `SendMessage`, `GetTask`, owner-status, exact
  finding reads, MCP initialization and the three reference tools are fixed-purpose
  methods, not a public proxy. MCP error envelopes cannot be allowed controls.
  Missing actual service request IDs remain missing.
- `RevisionProbe` temporarily selects `python -m citadel.acceptance.worker` in
  an existing application, preserving its exact image and identity. It persists
  dispatch intent before the ARM `2025-01-01` update; ambiguous dispatch is never
  replayed. Normal template restoration is verified and refuses concurrent edits.
- The worker is disabled unless explicitly selected and enabled. It validates
  its run, workload, assigned client ID, fixed mode and absolute deadline before
  accessing any SDK. It obtains only its allocated Key Vault subscription secret
  using explicit `ManagedIdentityCredential`; no operator fallback.
- `gateway-matrix` runs four-agent discovery/forbidden-invocation, owner-status,
  actual A2A `GetTask`, exact finding, MCP initialization and all three reference-tool
  probes. `OperatorProbe` separately obtains only the operator's own allocated key;
  the workload provider still refuses operator impersonation.
- Read observations have individual deterministic oracles,
  rather than remaining raw catalogue entries. Each binds an exact allocated
  subscription, actual destination hash, actual service ID, measured window and
  digest-bound workload probe trace. Allowed controls also require the destination
  application's actual method/identity trace. The boundary driver independently
  snapshots real draft/finding ledgers around each worker and the operator control.
  A denial needs the gateway's explicit `route_denied` response metadata and
  explicit no-backend-dispatch evidence, not just HTTP 403. Null/unknown backend
  fields remain blocked. These gates cover all 85 caller/read-capability obligations.
  Model routes have separate receipt/usage oracles, including the operator's
  forbidden inference route under its own allocated subscription.
- Invocation controls come from actual successful normal-workflow `SendMessage`
  responses, not additional probe invocations or manufactured accepted tasks.
  The actual SDK response must contain the matching protocol task/run identity.
  Caller-side receipts, APIM subscription/target/service ID, backend acceptance
  input hash and independently read completed operation must agree. Caller-parent
  correlation and accepted-child execution identity are checked separately.
  The operator persists only its own receipt in private run state; agent receipts
  use the unsampled assigned-MI exporter. Four permitted invocation edges and
  sixteen actually executed forbidden-invocation probes are independently evaluated,
  including gateway no-dispatch and unchanged business state for denials.
  Missing source reads, unrelated child/input bindings or malformed task envelopes
  cannot pass. Sanitized proofs preserve the same checks without input or task prose.
- Owner controls derive bounded IDs and hashes from five actual ledgers in the
  completed comparison. They never export private products, invent completed tasks,
  seed findings or create/refill operation pools. Exact final ticket-marker reads
  identify existing remaining capacity; absence requires an actual Blob 404, not
  an exception-only assertion. Pool use is observed, never an assumed invariant.
  The additional assessor/reviewer task reads consume one existing ticket each.
  Two exact finding controls use distinct released findings and reviewer pools;
  the task control uses a third reviewer pool.
- Assessor/reviewer status controls reuse actual successful in-workflow HTTP
  responses. Unsampled `status.observed` records bind the returned service ID,
  measured window, owner/run/input/result hashes and a digest of the reconstructed
  observation. They consume no additional reads. Collection requires the actual
  caller's application trace, matching APIM subscription and destination backend
  trace, plus independently observed immutable state. Console records cannot
  substitute. Missing capacity, old/out-of-window controls or missing correlations
  block; no probe changes the original operation's allowance.
  Invalid receipt metadata (including a backward wall-clock interval) produces no
  acceptance control, without aborting otherwise valid workflow work. Timestamps
  are never clamped into a passing interval, and missing receipts are not retried
  by the observer. Normal protocol/state validation still applies independently.
- Owner/task/finding proofs survive sanitization and are re-evaluated from the
  exact comparison context and correlated operator reads. A2A controls validate
  the real direct `Task` JSON result, task/context/artifact IDs and committed hash;
  MCP controls also bind the actual JSON-RPC response ID. Malformed response bodies
  retain their real service receipts rather than becoming untraceable failures.
  The local five-application integration test executes a genuine comparison,
  observes its status controls, then performs the eight remaining successful
  owner/finding reads and real MCP tools. Existing pool identities/capacities and
  business products remain unchanged; consumed tickets are not returned.
  No live Azure execution is implied.
- Executing-identity and status-owner aggregate checks reuse those real providers,
  not new requests or grants. The former independently re-evaluates all ninety
  storage capabilities against each allocated MI and actual service receipts;
  the latter re-evaluates all forty-five owner-status/task/exact-finding proofs.
  Both require the entire canonical dependency set, preserve failures and reject
  missing/duplicate controls, pass labels without evidence, substituted identities
  and incomplete service correlations. Sanitized exports repeat the same checks.
- Protocol checks reuse actual successful wire operations, not a manifest version
  or a passing route label. A2A requires all four observed `1.0`/JSONRPC cards,
  genuine workflow invocation receipts and exact completed tasks; the package
  contract remains `1.0.0`. MCP requires actual `2025-11-25` negotiation and all
  three successful tools for each authorized caller. Safe wire metadata is bound
  into each published observation hash and independently rechecked after export.
  Model-v1 requires all four real framework usage receipts, five own-MI direct
  controls and queried APIM backend target/method/status. The backend target is
  hashed after removing its query and must match the inventoried v1 target used
  by the direct providers. No raw URL, headers, prompt or response content enters
  the report. Missing backend metadata blocks; a different observed route fails.
  These are application/APIM/storage ingestion proofs, not a separate model-account
  diagnostic source. No new requests, grants or dependencies are needed.
- The full hook runs the origin/read/invocation boundary phase immediately after
  the genuine comparison, before the other scenarios or slower fault phases.
  It inherits that comparison's remaining absolute deadline instead of allocating
  a new 900-second window to old controls. Expired controls block before provider
  or credential access; original operation read pools are never refreshed.
- Fixed APIM authorization branches return only a nonpayload denial code and
  the actual gateway `context.RequestId`. Normal outbound policy removes any
  backend-supplied denial marker and replaces the response correlation ID.
  Authorization conditions, caller graph, request bodies, log-header settings
  and privileges are unchanged. MCP working controls require a shaped real
  Reference Data response; an empty JSON-RPC success envelope is not a control.
  Gateway workers disable ambient HTTP proxy settings and fetch only their
  assigned subscription secret through their explicit MI.
- The full suite dispatches `operation-faults` under Candidate Planner's actual
  identity against an isolated real Blob ledger. Six fixed drivers cover committed
  response loss/identical-input reuse; pending/running/indeterminate/missing and
  partial-not-completed states; changed-input conflict; fenced explicit retry and
  stale-generation refusal; actual safe-read response drops with recovery/exhaustion;
  and an actual delayed post-deadline commit attempt. They produce thirteen
  independently evaluated obligations, **not** release/concurrency/restart proof.
  Read faults discard actual successful provider responses; they never manufacture
  successful responses or authorization outcomes. Real one-/two-second backoffs
  and the three-target-read ceiling are checked separately from the shared durable
  512-ticket control envelope. Lease/deadline probes observe the actual wall-clock
  boundary rather than assuming one monotonic sleep crossed it. Their finite
  condition waits also retain the original phase's monotonic time ceiling;
  stalled clocks block without replaying an operation or extending its deadline.
  Physical safe-read durations and one-/two-second backoffs use recorded monotonic
  instants; raw wall instants remain unchanged for service correlation within the
  existing five-second correlation tolerance. Neither clock is substituted for
  the other. Missing elapsed timing blocks; a measured short backoff fails.
- Each fault publishes its metadata once through the actual Blob SDK; its service
  receipt, physical client-request ID and hash-bound application record correlate
  with storage logs. The operator independently reads the persisted ledger and
  exports only bounded status/count/hash metadata. Report gates re-evaluate all
  thirteen obligations after sanitization. A missing publication, wrong identity,
  altered state, unobserved source or incomplete driver cannot become pass.
  Incomplete-state exports retain the fixed changed-input conflict outcome,
  never the changed input itself, so their published observation hash stays valid.
  Root accounting accepts an optional **shorter** inherited probe deadline;
  omission retains 900 seconds and no argument can increase that ceiling.
- `admission-limits` uses the actual Candidate Planner MI and Blob SDK, without
  subscription-secret access or model calls. Production accounting admits twenty
  fixed-purpose candidate labels and forty-two execution identities, then actually
  rejects candidate twenty-one and execution forty-three. These are **budget
  admissions**, not fabricated agent completions or an alternative airport fixture.
  An overlapping accounting run is rejected without changing persisted state.
  The same worker also exercises the real shared `active-run-slot.json` lease:
  current-owner renewal succeeds, a different owner gets the actual service 409,
  and current-owner renewal still succeeds. A failed initial ownership control
  stops before attempting another acquisition. Each physical lease request has
  its own service/client IDs, destination and measured window; the oracle requires
  actual `LeaseBlob` correlation, not just the isolated budget's rejection.
  The controller independently observes the closed isolated budget, exact counters,
  unchanged business state and absent overlapping run. Model/token/read allowances
  remain unused, control reads stay within their existing 512-ticket envelope, and
  no pool is preallocated or refilled. Three limit checks are wired through the
  full hook and re-evaluated after sanitization. Other numeric boundaries remain
  incomplete; these checks do not assert model usage or actual executed agent work.
- `read-limit` spends the existing 512-ticket pool on 512 actual SDK reads of
  an isolated empty ledger, then observes refusal before request 513. Tickets
  are consumed immediately before each read, never bulk-prepaid or refilled.
  Each read has its own client/service IDs, hash and measured window. The oracle
  requires all 512 matching service records, rejects an additional observed read,
  and checks an independent operator snapshot for unchanged state. The mode uses
  the Candidate Planner MI without a subscription secret or model call. Its
  same-image controller persists intent, restores the normal revision and refuses
  replay. The numeric two-retry obligation also reuses the genuine three-attempt
  safe-read exhaustion driver and independent accounting proof, not a configured
  constant. Normal workflow counts such as 400/402 are not invariants.
- `release-faults` runs only as the actual Release Reviewer in its existing image
  and identity. The controller derives an exact draft reference from a genuine
  completed comparison finding. The worker reads that immutable source through
  the reviewer's read-only draft authority and retrieves its reference evidence
  over real MCP/APIM using only the allocated reviewer subscription.
  Four fixed drivers execute real conditional release writes in separate
  same-container disposable ledgers: response loss after committed release,
  simultaneous same-operation release, and simultaneous different-operation
  release, and wrong-draft-hash rejection followed by a working exact-hash release.
  The hash-denial attempt happens before any finding exists; an existing version
  cannot conceal a defective source-hash check. The race barrier delays dispatch;
  it never supplies provider results.
  Both participants settle before a failed race can be reported. Normal drafts,
  findings, permissions and operation budgets are not modified.
- Release evidence binds actual Blob publication receipts, a digest-bound reviewer
  application record, three real MCP response IDs with gateway/backend identity
  and allocated-subscription correlations, independent final-state reads and
  before/after business-ledger snapshots. Oracles verify exact input/deadline/run
  bindings, one immutable finding, matching released projection and definitive
  conditional conflicts. Sanitized exports are independently re-evaluated.
  Missing layers or source bindings block; changed business state fails.
  These four reviewer drivers do **not** by themselves establish draft-version
  contention, immutable multi-version findings or actual process-restart proof.
- `draft-versions` separately runs as Evidence Assessor, never as Reviewer or
  Operator. It reads a genuine comparison draft and reference evidence using
  the assessor's allocated MI/key, then copies its unchanged content into an
  isolated private draft ledger with fresh control identities. Actual conditional
  writes race for version two. Exactly one succeeds and the other receives a
  definitive conflict; version one's exact bytes remain readable and unchanged.
  Ambiguous responses block instead of being interpreted as expected conflicts.
  Independent operator reads verify source-content lineage, immutable hashes,
  exact operation/input/deadline bindings and one version-two winner. This
  implements `fault.concurrent-version-conflict`.
- `immutable-versions` hands those two exact, actually committed versions to the
  Release Reviewer using its own MI/key and real MCP reference reads. The reviewer
  can read but cannot write the assessor's isolated source ledger. It inherits
  the original assessor deadline; neither controller nor worker can extend it.
  Two real releases produce independently read public findings. The first finding's
  exact hash remains unchanged after the second release. Independent before/after
  reads bind the unchanged private source and normal business ledgers.
  The per-check oracle and sanitized export gate re-evaluate the entire assessor
  source proof, source/child operation membership, both runtime identities,
  allocated subscriptions, exact draft and public projection hashes, permitted
  finding fields and actual application/gateway/storage correlations. Missing or
  unrelated source proof blocks. Changed content, extra findings or malformed
  versions fail. Interrupted handoff cannot automatically replay. These providers
  do not establish actual process-restart proof.
- Writable workloads persist one-shot admission and finite 512-ticket read pools
  in their existing operations container. Candidate Planner also acquires its
  existing active-run slot. Failed probe admissions/results are retained; repair
  is explicit. These probes add no resource, data role or fixture.
- `storage-boundaries` uses the actual Blob SDK and assigned workload MI, before
  the worker's subscription-secret branch. Normal application hosting still
  initializes its allocated runtime. The operator seeds isolated same-container
  copies of real ledgers; real draft/finding products are prerequisites, never
  fabricated controls. Each writable workload performs the fixed read/write
  matrix with independent permitted controls and conditional writes. Operator
  snapshots verify unchanged content; runtime and storage records must agree on
  service ID, physical client-request ID, identity, method, target and time.
  Shared 900-second orchestration and durable 512-ticket envelopes remain bounded.
  Reference Data uses the separately approved bounded one-shot console path.
- `origin-boundary` derives the actual HTTPS origin from the inventoried app's
  ARM response. It sends only protected discovery (or MCP initialization) using
  missing certificates, freshly generated unrelated certificates, or forged
  context/certificate headers. TLS chain/name checks stay enabled; no gateway
  private key is read or exported. Ephemeral unrelated-key files are private and
  removed. Normal middleware issues its own denial response ID and logs a fixed
  rejection reason without attributing forged headers to a trusted caller.
- The full boundary phase dispatches these real workers, preserves per-request
  observations, reads actual draft/finding ledgers before and after, and runs
  allocated gateway controls under one 900-second envelope. Its operator
  discovery control uses only the operator's own key. Origin oracles require
  actual client/server correlation, authorized APIM/application controls and
  unchanged independently observed business products. Transport failures and
  missing ingress request IDs remain inconclusive, never passing denials.
  - Pre-application origin rejection can instead correlate actual
    `ContainerAppHTTPLogs` ingress evidence. The probe captures the returned
    `x-request-id` without supplying that header. Queries restrict ingress rows to
    observed IDs, hashed destinations and individual measured windows (at most
    30 seconds, with five-second correlation tolerance). A documented Envoy RBAC
    denial and zero upstream attempts are required, together with the actual
    workload's probe trace, working APIM control and independent unchanged products.
    Generic `direct_response`, TLS errors, missing counters and ordinary 403s
    cannot pass. No platform identity is invented for the ingress record.
- `DirectModelProbe` has a tested actual-MI, one-shot HTTPX2 provider using the
  cognitive-services token scope, fixed v1 inference path, bounded nonprivate
  prompt and 2,000-output-token maximum. It exports no token or response prose.
  The full suite now dispatches all five actual workload identities in a separate
  `direct-model` phase. The operator acquires the existing global active-run lease
  before dispatch, persists finite private reservations before each actual call,
  and waits sixty seconds under that lease at both phase boundaries to isolate
  normal workflows' rolling model quota. The existing 900-second deadline,
  512 controller reads, 42 executions, 128 attempts, aggregate token ceiling,
  one in-flight call, five-second spacing and independently verified actual TPM
  quota are enforced without creating workload grants or increasing normal grants.
  Each actor receives at most one one-shot control; no reservation is refunded.
  Ambiguous dispatch/result/restoration retains admission and requires explicit
  reconciliation rather than automatic replay or lease retirement.
  Reference Data uses its approved read-only console path without a storage grant
  or subscription secret; the four agents use immutable dispatch markers and
  their existing result containers. They never borrow the operator's model token.
- Direct-model oracles require the actual own-MI denial receipt in queried
  application ingestion, a normal successful APIM model response with actual
  bounded usage, allocated-subscription/backend-dispatch correlation, both actual
  global lease receipts and independent unchanged draft/finding snapshots.
  Reference Data uses Candidate Planner's permitted APIM model control, not an
  invented Reference Data model subscription. Missing receipts, generic errors,
  unknown usage or missing no-effect observations block; observed unauthorized
  inference fails. Exports independently re-evaluate all five obligations.
  Normal Agent Framework responses export only actual token counts, request
  destination hash and measured times; no prompt, response prose or credentials.
  The four allowed model-route obligations independently reuse genuine normal
  Agent Framework/APIM receipts and exact usage, without extra paid requests or
  altered normal grants. These are queried application/APIM/storage correlations,
  **not** a claim of separate model-account diagnostic ingestion. Remaining
  numeric model-boundary obligations are unfinished.
- The same globally excluded phase reserves a separate operator model control.
  Its fixed-purpose provider reads only the operator's allocated subscription;
  it never supplies that credential to a runtime actor or claims a runtime MI.
  A conclusive denial needs the actual `model_caller_denied` gateway response,
  queried operator subscription/request/target correlation, explicit zero backend
  dispatch, a working normal model control and independently unchanged products.
  Successful unauthorized inference fails; ambiguity retains the lease/ticket.
  All ten model route/direct-origin obligations now have executable providers
  and independent exported-proof evaluators, not asserted cloud passes.
- `ConsoleProbe` selects only the inventoried Reference Data app's actual ready
  revision/replica/container, pinned image and assigned identity. Its CLI 2.91.0
  process uses a real PTY and the approved console-only ARM `2025-07-01` exception.
  Private descriptor input keeps target arguments out of the process command line;
  only one hash-framed result is retained, not raw console output. No template,
  identity grant, operations container or subscription secret is added.
- The Reference Data process explicitly requires `--enabled`, validates an
  immutable bounded manifest, and executes real storage/origin providers under
  its read-only MI. It has at most 512 attempts and the inherited 900-second
  deadline. Durable private operator intent precedes dispatch; incomplete,
  conflicting or ambiguous outcomes cannot automatically replay. The controller
  charges a conservative 186-request CLI allowance (six pinned requests, each
  with the underlying client's 30-redirect ceiling) to the existing operator
  control budget in one local reservation, not Azure prepaid ticket writes.

## Evidence and human review

```sh
python -m citadel.operator acceptance --state-dir "$CITADEL_STATE_DIR" --run-id acceptance001
python -m citadel.operator acceptance --state-dir "$CITADEL_STATE_DIR" \
  --run-id acceptance001 --collect-only
python -m citadel.operator review-acceptance --state-dir "$CITADEL_STATE_DIR" \
  --run-id acceptance001 --review "$CITADEL_STATE_DIR/review.json"
```

Do not run the paid/deployed suite until the missing facilities below are resolved.
These commands are implemented interfaces, **not evidence that deployment has run**.
`collect-only` does not resubmit business work or reset the persisted 600-second
collection deadline. Native queries share its remaining time allowance.

`review.json` is a private, owner-only file containing exactly:

```json
{
  "scenario": "comparison",
  "product_sha256": "<hash of the exact observed product>",
  "supported": true,
  "gaps_visible": true,
  "fictional": true
}
```

The human must inspect each scenario's narrative/partial narrative for unsupported
claims, hidden gaps and operational-suitability claims. Record the actual answers;
`false` is rejection, not approval. An automated test never writes human approval.
The hash must match the stored scenario product. Missing review is
`pending_human`; one reviewed complete cloud pass is `pending_second_pass`.
Two consecutive complete passes require the same pinned fingerprints, matching
deterministic semantics and disjoint operation/run IDs. An intervening failed
attempt breaks the pair. Local mode, missing checks or skipped checks cannot pass.
The required set is the shipped catalogue, not a report's self-declared subset.
All four scenario products and application/gateway/storage evidence are mandatory;
malformed identities, hashes or review records block before human confirmation.
Report gates re-run independent storage/origin/read/invocation/durable-fault oracles using the fingerprinted
workload identities and allocated-subscription hashes. Generic all-pass labels,
even with application/gateway/storage rows, cannot certify acceptance. Check
families without a registered independent oracle remain blocked. Human narrative
decisions are independently inspectable but do not certify missing automation.

Reports are immutable hash-named JSON and Markdown under private
`STATE/acceptance/`, **outside every Git checkout**. Report directories inside a
checkout are rejected even if ignored. Prior exports and failures are retained.
Unknown payload fields are removed; prompts, private notes and credentials are
not evidence. Caller credential mapping and executing identity hashes are distinct.
No automatic publication or deletion occurs.

## Actual telemetry versus assertions

Application instrumentation emits only allowlisted metadata, actual service request
IDs and hashes. The existing Container Apps diagnostic path can export those records
to the dedicated `ContainerAppConsoleLogs` table (`Log` column); these records are explicitly `console`, not
`application` evidence. The collector queries `AppTraces` for application records,
and actual `ApiManagementGatewayLogs` and `StorageBlobLogs`. Provider query errors, incomplete
tables, mismatched request/identity/window/status correlation and excessive results
block. Retention checks require the effective 30-day Analytics settings and no
daily ingestion cutoff.
Collection merges prior evidence on resume and rejects contradictory records.
The resource-specific storage table exposes `CorrelationId` and `ClientRequestId`,
not `RequestIdHeader`. The former must match the actual response service ID;
the latter remains a separate physical request binding. Targets are query-free
URL hashes. That live storage-ID correspondence has not been observed locally.
Gateway evidence retains a logical caller and a hash of its actual service-scoped
subscription ID, separately from workload managed-identity hashes. It uses the
published `ApimSubscriptionId` column (not a nonexistent `SubscriptionId` or the
Azure account's `_SubscriptionId`). Actual gateway GUIDs are represented without
hyphens in both collected records and client observations, matching the signed
backend context's `context.RequestId.ToString("N")`. No new ID is generated;
missing response IDs stay missing, and model-provider IDs do not substitute for
gateway IDs.
The APIM query hashes `Url` and derives bounded dispatch metadata from
`BackendUrl`, `BackendMethod`, `BackendResponseCode` and `BackendTime`. It exports
no raw URL, headers or body. Explicit zero/empty no-backend fields are required;
missing values are not interpreted as zero.

Managed-environment diagnostics also enable the documented
[`ContainerAppHTTPLogs` category](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-logs/microsoft-app-managedenvironments-logs)
using the existing diagnostic-settings API and workspace, with 30-day Analytics
retention. The [published ingress schema](https://learn.microsoft.com/en-us/azure/container-apps/log-monitoring)
supplies response `RequestId`, `StartTime`, `ResponseCodeDetails` and
`UpstreamRequestAttemptCount`. Only the
[documented RBAC denial detail](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/rbac_filter)
is recognized as ingress authorization evidence; no certificate-specific Azure
reason is assumed. Reports omit raw authority/path/query, client addresses,
user agents and policy names. The category's availability, effective table
mapping and actual rejection detail remain deployed-validation gates; a
missing table fails the real query rather than falling back to console output.

**Console export is supplemental, not assigned-MI Application Insights proof.**
The approved official `azure-monitor-opentelemetry-exporter==1.0.0b58` now runs
under the hosting workload's explicitly selected synchronous managed identity.
It sends only sanitized metadata to the configured regional `/v2.1/track` endpoint
using `https://monitor.azure.com//.default`. All pre-existing dependency versions
were retained; exactly seven approved packages were added and hash-locked.

The exporter has no trace-based sampling, client-side drop cap, automatic
instrumentation, offline spool, Statsbeat, SDKStats or OneSettings channel.
Its bounded queue holds 4,096 records (4 KiB maximum each), with at most 128 per
batch. Overflow, rejected/partial acknowledgements, exceptions and unfinished
delivery remain visible counters; failed batches are not replayed. SDK raw
exception/body logging is suppressed. The normal hosting lifecycle owns one
exporter and a bounded shutdown drain; workers do not create duplicate exporters.
Acknowledgements include only actual response IDs/status and never claim queried
ingestion. Actual cloud delivery, sender/query authority, effective sampling and
complete per-check correlations remain unverified locally.

## Remaining implementation gates

Retention and unsampled-configuration evaluation now reads the allocated workspace,
all thirteen configured tables, Application Insights and the APIM diagnostic.
The exported oracle binds actual resource IDs by hash and requires 30-day Analytics
retention, no daily cap, 100% sampling, disabled Insights local authentication,
and zero request/response body or header logging. It additionally re-evaluates
queried application event prefixes and actual exporter loss counters; configuration
or export acknowledgement alone cannot pass. These ARM reads share the original
600-second collection deadline. Local REST fixtures do not establish cloud settings.

The gateway/storage correlation aggregates independently re-evaluate all 110
route controls (including model, MCP and owner-scoped reads) and all 90 storage
matrix controls. Their summaries count and hash distinct actual service receipts,
including allowed controls and storage observer reads. Exact request/target/status,
subscription or principal, method, time window and backend dispatch must agree;
conflicting duplicate service receipts block. Pass labels or unrelated source rows
cannot supply either census. Other canonical scenario/fault checks separately
require their own service receipts.

The fixed Candidate Planner `model-limits` worker now exercises exact 16,000-input/
2,000-output conservative admission through the real framework, an overlapping
reservation refusal, and 16,001-/2,001-token refusals without another dispatch.
It uses only its assigned MI, its own Key Vault subscription secret and its existing
private operation container. The shared run lease remains held through real
60-second isolation windows before and after inference; a competing lease must
actually fail. The private intent, 512-read pool and original 900-second deadline
are not replenished. Independent raw-ledger counters, queried model/Blob/APIM
receipts and immutable publication hashes are required for all three exported
limits. Malformed usage leaves admission unresolved; no automatic retry occurs.
The remaining timeout/deadline and restart controls are described below; source
implementation is distinct from their still-required deployed proof.

Three further fixed counter modes spend actual model attempts: eight responses
before the ninth per-execution refusal; 128 responses across bounded executions
before the 129th run-attempt refusal; and 55 conservative 18,000-token attempts
before the next attempt exceeds the one-million-token budget. Counters are never
seeded or edited to reach a boundary. Every successful attempt needs its own queried
application/APIM receipt and the independently read final budget. The existing
global lease, 60-second isolation, 512 reads and 900 seconds apply to each fresh
control run. Insufficient actual quota or excessive service latency blocks the
control rather than raising a ceiling or issuing a replacement run automatically.
Local counter tests use the real framework with external wire fixtures and a
simulated rate clock; the worker integration also tests real isolation windows.

The run counter also attempts a reservation immediately after a real completed
response; the token counter attempts one when actual rolling history would exceed
its configured quota, with the five-second spacing satisfied and fewer than twelve
requests. Both must return `rate_limited` without another physical model request or
any ledger change. The exported oracle reconstructs those histories from actual
durable settlement timestamps and queried response receipts, and checks every
rolling minute against twelve requests and the allocated token ceiling.
Two admitted ARM GETs independently obtain regional model rate metadata and the
exact deployed Standard SKU/capacity before either worker starts. Pagination,
missing metadata, changed model/capacity or unverified quota block; configured TPM
alone cannot pass. These reads, additional settlement observations and refusals
retain the existing finite read and time budgets.

The 15-second polling provider reuses the completed comparison run. It makes two
actual owner-authorized status reads, attempts an immediate intervening poll
through the production operator admission path, and requires refusal before any
dispatch or durable read-counter change. Twelve bounded operator Blob reads
independently compare all six business ledgers before and after. No invocation,
model attempt, grant, read-pool refill or replacement run is created.
Workload clients also emit payload-free receipts for every pending/completed
owner poll. The exported gate requires the complete queried backend/client census,
actual gateway and runtime identity bindings, and at least 15 seconds after the
actual accepted invocation and each preceding poll response. Missing peer receipts
cannot be replaced by successful operator timing alone. The fixed provider retains
the original run deadline and the existing 64-read operator allowance.

The 30-second safe-read control obtains three successful real Blob reads but
withholds each callback until the unchanged production timer expires. Its public
gate requires all three actual application/Blob receipts, queried timer-expiry
records, exact scheduled deadlines, 1/2-second backoff, independently observed
509 remaining reads, and unchanged business state. Wall timestamps correlate
service observations; actual event-loop deadlines prove expiry even when wall
and monotonic clocks diverge. No deadline is reset after backoff, no timer is
increased, and missing expiry/service evidence blocks.

The 60-second model control first completes a real Framework inference, then
fully receives another genuine successful model response but withholds its
callback until the unchanged production guard expires. The second reservation
remains outstanding in its private control ledger; no settlement, refund, closure
or replay is invented. A further real admission attempt must conflict without
changing that ledger or sending another request. Independent raw state and
queried model/API/timer receipts must match both responses and the retained
permit. Global exclusion is released only after both definite responses, client
closure and the existing quiet window; missing/ambiguous response data retains
exclusion. Normal workflow grants remain unchanged.

The A2A HTTP control reuses the completed comparison through two actual
authenticated cached `SendMessage` responses under the operator's own key.
It receives the complete second response, then withholds its callback until the
unchanged 180-second production client timer expires. Twelve independent Blob
SDK reads bracket the traffic; original operation tickets and deadline are never
replenished. A persisted local control intent blocks another run or ambiguous
replay. Cached backend observations are explicitly separate from new execution
acceptances. The sanitized oracle requires both gateway/backend receipts,
independently observed root bindings, the actual monotonic timer and unchanged
business state. A shorter inherited timeout or a transport error is not proof
of the full 180-second boundary.

The 10-second backend control first obtains a real completed cached response,
then temporarily enables one exact cached-root hold in the existing pinned
Candidate Planner application. It preserves the normal command, identity,
credentials and original operation pools. The application only holds an already
succeeded, input-bound root; its actual production `SendMessage` guard expires
after ten seconds. No new execution is scheduled. Configuration is private,
fixed-purpose and disabled by default; arbitrary durations and other workloads
are rejected. Both enabling and restoring wait for the exact named ready
revision, with at most 94 total operator reads under the original run deadline.
The public oracle requires the independently queried backend timer, actual
indeterminate protocol response, earlier allowed control and unchanged snapshots;
a client timeout or successful revision update alone cannot pass.

The fixed `process-restart` worker starts two exact
`python -m citadel.acceptance.process_restart` children under Candidate Planner's
existing managed identity. The first admits one disposable planning operation and
one agent execution, publishes its immutable process receipt, drains telemetry,
then exits with code 73 without business-state cleanup. The parent must observe
that exact PID/exit before starting the second interpreter. The second reuses the
same finite read-ticket pool and original deadline; it waits a real sixty seconds,
then attempts identical acceptance, claim, retry and root-budget admission.
The running operation must remain incomplete; identical acceptance returns its
original status, while claim, retry and root-budget admission must conflict
without a ledger change. No model, peer, production business-ledger
write, new permission, arbitrary executable or operator runtime credential is used.
Only the exact disabled-by-default planner manifest admits this control.

Both child publications require actual queried Blob and application receipts.
An independent operator Blob read must match the entire original ledger,
generation, absent product and unchanged one-agent budget. The sanitized export
rechecks both distinct process/boot bindings, exact exit statuses, the sixty-second
observation, original deadline and all remaining counters. Missing either service
receipt or a replenished allowance blocks/fails proof. The public worker's local
wire test fakes the external OS/Blob transports while executing both production
child routines; it is **not** a deployed process-termination or cloud-outcome claim.
This control kills the disposable operation-owning child, not the Container App
host, and does not claim a Container Apps platform restart.

Implemented providers now cover all 278 canonical checks; this is source-provider
coverage, **not a cloud pass count**. The three rotation families and actual
900-second workflow boundary have fixed-purpose drivers and fail-closed exported
proof oracles. Missing deployed observations still block the full gate.

1. Perform deployed validation of the implemented telemetry configuration,
   application ingestion counts and gateway/storage correlation proofs.
   Dependency approval is settled; no existing pin was changed and no cloud
   delivery is inferred from local SDK wire tests.
2. Execute/verify the implemented storage/origin providers and read-only
   Reference Data execution; observe the implemented pre-application ingress evidence path,
   and collect deployed proof for the implemented direct-model/model-route controls.
   Execute the implemented credential/certificate/context rotation providers and
   collect their independent deployed proof.
3. Complete remaining deployed accounting/time boundaries and actual
   deployed verification of the process-restart probe. Implemented release-response-loss, concurrent release,
   version-conflict, exact-hash and immutable-version providers still require
   their actual deployed proof; local execution does not supply it.
4. Connect validated independent service correlations/no-effect proofs to each
   required check. The partial harness intentionally cannot produce a complete
   pass merely because its available probes ran.
5. Validate the implemented Reference Data console path against deployed services.
   Its local tests cover a real PTY, the actual Blob/MCP wire, immutable request
   bindings and no automatic replay. All other application deployment/revision
   APIs remain `2025-01-01`; no live console connection has run locally.

Fresh deployment, safe repair, manual teardown/residue evidence and actual portal
plan observation remain operator/task-21 evidence conditions. Ordinary managed
identities are not Entra Agent IDs. Agent 365, Conditional Access, Defender and
Purview remain explicitly unexercised.

### Resume validation and approved control contracts

The resumed work preserved all checkpoints at `c205a91`; integration
`6fb4c89` is an ancestor and merging `integrate/citadel-sample` was already
up to date. Docker was initially unavailable in WSL and the existing Windows
client could not reach Docker Desktop's Linux engine. After the operator started
Docker Desktop, the existing client/server 29.8.2 became responsive. The exact
pinned image was then built successfully with the existing hash-locked offline
wheelhouse and installation networking disabled. Its stack suite, restart proof
subset and all five configuration entrypoints passed as UID/GID 65532:65532,
with networking disabled, read-only root, dropped capabilities and
`no-new-privileges`. Docker is **no longer a blocker**. No deployment, account
configuration, credential rotation or resource creation was performed.

The three rotation hooks block retirement without independent live controls.
Their implemented providers use the existing staged lifecycle interface, actual
allocated caller identities, queried gateway/backend rejection reasons and
independent unchanged-state reads.
Do not move a gateway private key into a workload or use operator authority as
a workload identity. The workflow control still requires the unmodified
production 900-second timer, its original nonreplenished accounting, independently
queried expiry/refusal observations and unchanged business state. A shorter
inherited deadline or the existing 45-second fencing probe is not that boundary.
The two previously unresolved contracts were explicitly approved in
[issue #7, comment 6265896306](https://github.com/JoranBergfeld/citadel-example/issues/7#issuecomment-6265896306)
and recorded on
[task #20, comment 6265897033](https://github.com/JoranBergfeld/citadel-example/issues/20#issuecomment-6265897033).
Approval authorizes these fixed-purpose implementations, **not deployment now**.
No live material has been rotated and no cloud success is inferred.

1. **Retired certificate/context signer selection.** The existing
   `operator.rotation` interface replaces active APIM material and backend trust
   together. Its acceptance hooks now provide a narrowly bounded, quiescent test
   that selects the owned retired certificate **inside APIM** (using its exact owned Key Vault secret
   version), or the exact retired context key/key-ID pair, while keeping backend
   trust retired. This entails new temporary gateway signer-selection writes
   outside the existing prepare/finalize reconciliation, not an ordinary read-only
   probe. The approved selector is implemented in `rotation_selector.py`; it
   never exports the platform private key or copies it into a workload.

   Enforced constraints: only the pending rotation's owned material, exact
   inventoried APIM resource/API, existing allowed read-only capability and actual
   allocated caller; one persisted intent; at most 512 control reads and 900
   seconds; no caller/route/role/API-pin changes, arbitrary XML, URLs, durations or
   payloads. Verify the original selector/policy fingerprints before dispatch,
   restore that exact state and prove a fresh current-material allowed control.
   Certificate capture lists secret-version metadata only; the selector verifies
   APIM's public certificate fingerprint against already-owned lifecycle material.
   It never fetches a platform secret value. Context selection accepts only the
   pinned policy with its exact current key-ID substitution and allocated callers.
   Absent or ambiguous restoration retains the intent and blocks further work.
   Required independent evidence: allowed current-material gateway/backend
   receipts, actual retired-material certificate/context rejection reason with
   no backend execution, independently unchanged business ledgers and no
   unrelated configuration changes. A successful ARM update alone is not proof.
   Subscription rotation uses the ordinary lifecycle interface, not signer
   selection. Its actual allocated caller reads only its own current or exact
   captured retired secret version. An APIM 401 alone is insufficient:
   `SubscriptionKeyInvalid` and no backend dispatch must be independently queried.
   All three oracles require unchanged planner/assessor/reviewer/author operation,
   draft and finding ledgers, and independently correlated allowed, retired and
   fresh restored controls. Ambiguous intents retain local run exclusion.

2. **A full workflow lifetime versus the probe envelope.** `RevisionProbe.execute`,
   `worker.validate_request`, `worker.serve`, `ProbeLedger` and `publish_operation`
   retain their same at-most-900-second deadline, beginning before the
   revision is deployed. A newly admitted real 900-second workflow cannot both
   exhaust its full production lifetime and publish/collect its terminal
   observation inside that earlier envelope. Shortening the workflow or resetting
   any budget would violate the required boundary.

   The approved provider uses a separate fixed control-plane envelope: at most 120 seconds for
   setup; one newly admitted production workflow with its unchanged original
   900-second deadline, run identity and finite tickets; then at most 120 seconds
   of independent operator observation/restoration. The existing 600-second
   telemetry-collection budget remains separate and nonreplenished. No runtime
   business dispatch or original deadline extension is allowed during the
   post-expiry interval. Missing/ambiguous evidence retains exclusion. Any explicit
   terminal fencing/lease recovery must be separately observable through the
   existing recovery semantics, never a new run, refund or automatic replay.
   Required evidence: actual production timer expiry, independently observed
   original admission/deadline/accounting, real post-expiry admission refusal,
   complete queried application/service receipts and before/after unchanged
   business state. `workflow_harness.py` installs only the owned, ready normal
   Candidate Planner revision with a private disabled-by-default hold; it invokes
   one fresh authenticated root through the real A2A client, then observes storage
   independently. `workflow_timeout.py` holds that root under the unchanged
   production timer in `Runtime._run`. On actual expiry it attempts accounting
   admission against the original expired budget (which must refuse), then uses
   existing definite metadata-only fencing/lease recovery. It never invokes a
   model/peer or retries the root. The operator verifies exact revision restoration.
   `workflow_oracle.py` rechecks original 900-second admission, monotonic timer
   expiry, refusal/fence telemetry, unchanged budget and all six business ledgers.
   Missing service rows, shortened lifetime, changed accounting, extra effects,
   unverified restoration or an ambiguous terminal state cannot pass.

The accepted exporter and read-only Reference Data console exceptions remain
settled; neither is being reopened. No additional permission, dependency or API
pin change is requested. All four providers are now wired into full acceptance;
the full gate remains blocked until actual deployed evidence, the two complete
consecutive passes and required human review are obtained.

Prior checkpoint local resume checks (CPython 3.12.15, retained exact source dataset;
these historical results predate the four approved providers):

| Check | Result |
| --- | --- |
| Complete acceptance suite | 222 tests passed in 2158 seconds; no skips |
| Complete operator suite | 42 tests passed |
| Complete operations suite | 30 tests; four explicit live-cloud tests skipped |
| Complete runtime suite | 27 tests; two explicit live-cloud tests skipped |
| Complete evidence suite | 18 tests passed |
| Complete gateway suite | 16 tests passed |
| Complete installed-stack suite | Six tests passed |
| Infrastructure/policy suite | 13 tests passed with existing exact Bicep 0.48.1 |
| All five runtime `--check-config` entrypoints | Passed without provider access |
| Source/wheel package build | Passed with uv/uv-build 0.12.21; wheel bytes match the final restart sources |
| Whitespace / Python syntax | `git diff --check` / `compileall` passed |
| Actual fresh child refusal entrypoint | Unallocated request exits 2 without provider access or output |
| Pinned offline image build/run | Passed after Docker Desktop was started |
| Actual image SDK/restart proof suites | Six stack tests and three restart tests passed |
| All five actual image configuration entrypoints | Passed without provider access |

The locked build backend was restored only after its missing-module failure;
no dependency manifest, version, permission or API pin changed. An initial
operator fixture run observed a concurrent source-fingerprint change during
proof refinement and failed closed; the full retained-data rerun passed with
the source fingerprint checked unchanged before/after. These local results do
not establish live controls or satisfy either cloud acceptance pass.

Approved-provider local validation (CPython 3.12.15; same retained exact dataset):

| Check | Result |
| --- | --- |
| Complete acceptance suite | 236 tests passed in 3154.822 seconds, no skips; discovery preceded the two final rotation regressions, covered below |
| Final focused regressions / complete rotation suite | 32 / 10 tests passed |
| Actual production 900-second workflow | Passed on the host and in the final immutable image; neither substitutes a shortened timer |
| Complete operations / runtime suites | 30 / 27 tests; four / two explicit live-cloud skips |
| Complete evidence / gateway / installed-stack suites | 18 / 16 / six tests passed |
| Infrastructure/policy suite | 13 tests passed with unchanged Bicep 0.48.1 |
| Complete operator suite | Earlier ordinary run: 42 passed; final consistent fake-external-clock run: 42 passed; raw-host reruns have the clock limitation below |
| Final immutable image | Pinned offline build passed; six stack and seven provider tests passed, including the genuine production timer |
| Host / final-image entrypoints | All five runtime configuration checks passed; actual unallocated child exits 2 without provider access or output |
| Locked package build | Passed; wheel Python bytes match the final sources |
| Whitespace / Python syntax | `git diff --check` / `compileall` passed |

The final image is
`sha256:22ce05c145ea6a64c06ca6587b3043a92c6b49f68f3105f4892acbaccbea1aff`,
tested as `65532:65532`, network-disabled, read-only and without capabilities.
Local provider tests fake external transports and, where explicitly needed,
external clocks; they are implementation checks, not independent Azure evidence.
The genuine timer tests retain the production 900-second runtime boundary.

This host's UTC clock demonstrably moved backward between an operator fixture's
observation and validation (observation `12:15:49.293741`, subsequent current time
`12:15:48.680432`, both UTC on 2026-10-19). Final ordinary operator reruns therefore
fail varying existing future-observation guards. Production guards remain
unchanged. The complete 42-test fixture suite passed with one consistent
monotonic-backed fake external UTC clock, including independent inventory
timestamps; this does not claim that raw-host clock failures disappeared.

Pre-review local artifacts are indexed by `.build/approved-verification-index.json`
and `.build/approved-provider-coverage.json`; the historical `resume-*` artifacts
are preserved. All 278 canonical checks have source providers; zero cloud passes
are claimed. No Azure resource deployment, live material rotation, two-pass cloud
acceptance or human signoff was performed.

### Integration-review corrections

The subsequent review corrected deployed account ownership across every
acceptance driver and exported target binding: containers resolve to their
actual Reference Data, Evidence Review or Exercise Planning storage account,
not a fictitious shared account. Missing, duplicated or inconsistent ownership
fails closed. Cross-team disposable SDK probes use only those fixed deployment
accounts, validated against their own application's account.

Certificate selection/restoration now uses the pinned APIM 2024-05-01
[`Certificate_CreateOrUpdate` PUT contract](https://github.com/Azure/azure-rest-api-specs/blob/main/specification/apimanagement/resource-manager/Microsoft.ApiManagement/ApiManagement/stable/2024-05-01/apimcertificates.json);
fixtures reject unsupported PATCH.
Briefing Author subscription controls use only an exact, hash-verified finding
with its already-funded Reviewer read pool, never forbidden discovery. Embedded
rotations and subsequent parent collection share one persisted, nonreplenished
600-second allowance; standalone rotations retain their separate original cap.

Authenticated runtime recovery releases the global lease only after definite
fenced no-effect reconciliation. Explicit A2A retry requires a separate
`citadel_retry` request with the same owner, identity and inputs, original
unexpired budget and remaining finite tickets. Each retry charges an additional
agent attempt, preserves previous model/read/token charges and acquires a
generation-owned global lease that stale cleanup cannot release. Ambiguous
model/child admissions retain exclusion and forbid retry. No automatic replay
or caller-claimed downstream reconciliation was added.

Retrieved MCP evidence now implements only the narrow assessment/projection
rules over exact airport/runway reads; it no longer inherits uninitialized full
dataset capabilities. Operation modes have one local registration for phase,
coverage and evaluator selection; independent proof validators remain unchanged.

Review validation retains fake external cloud transports and uses
monotonic-backed external UTC for acceptance/operator fixtures, without
shortening real elapsed timers or relaxing production observation guards.
A raw-host acceptance run passed 242 checks but lost one timing-bound owner-status
receipt; that test passed nine isolated repeats. Independent native-clock sampling
observed UTC move backward by 2.790330648 seconds. The raw run, repeat diagnostics
and clock sample remain in `.build/review-acceptance-raw-clock.log`,
`.build/review-owner-clock-diagnostic.log` and
`.build/review-host-clock-sample.json`; the missing receipt was not accepted as
proof or converted into a pass.

The unchanged genuine production 900-second timer test is excluded from the
review rerun by explicit request; its previous host/image results remain
historical evidence under the preceding commit, not new cloud proof. The
current-source fake-clock cancellation/deadline controls still verify refusal,
nonreplay and original-budget preservation.

Coherent review validation against the unchanged source fingerprint:

| Host suite | Tests run | Explicit live-cloud skips |
| --- | ---: | ---: |
| Acceptance | 243 | 0 |
| Operator | 43 | 0 |
| Runtime | 38 | 2 |
| Operations | 30 | 4 |
| Evidence | 18 | 0 |
| Gateway | 16 | 0 |
| Stack | 6 | 0 |
| Infrastructure/policy | 13 | 0 |

All other host checks passed. The pinned offline image additionally passed
55 focused review-control tests and six stack tests with networking disabled,
read-only root, UID/GID 65532, dropped capabilities and no-new-privileges.
Read-only repository test/policy fixtures were supplied separately; only
`/app/.build` was writable. Both host and image validated all five configuration
entrypoints and refused an unallocated child before provider access. Wheel and
image bytes matched all 95 current Python source files; syntax and whitespace
checks passed. Pins, permissions and production timeout durations are unchanged.

Current review artifacts are `.build/review-verification-index.json` and
`.build/review-provider-coverage.json`, binding the source commit/fingerprint,
immutable image ID, exact suite counts, qualifications and retained failure
diagnostics. They report 278/278 source providers, not cloud passes. No Azure
deployment, live rotation, two-pass cloud acceptance or human signoff occurred.
