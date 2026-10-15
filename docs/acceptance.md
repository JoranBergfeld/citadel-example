# Observable acceptance: implementation checkpoint

**Task 20 is not complete. Do not start task 21 or claim cloud acceptance from
the local tests.** The required coverage catalogue deliberately includes checks
whose deployed drivers/proofs are still absent. Such checks remain `blocked`;
rotation retirement and denied-bypass continuation cannot pass through placeholders.

## Implemented public boundaries

- `citadel.acceptance.operator_hooks.run(lifecycle=..., check_id=..., run_id=...)`
  handles the documented operator hooks and `collect-evidence`. Existing private
  API Center human-plan evidence and deployed-runtime gates still apply.
- The full harness invokes the existing operator scenario path, not agent internals.
  The independent semantic oracle compares the immutable source, labelled fixture,
  exact ordered candidates, assessments, released-version/hash shapes and caveats.
  It rejects fabricated completed briefs for pool exhaustion.
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
- `gateway-matrix` runs four-agent discovery/forbidden-invocation, MCP
  initialization and all three reference-tool probes. `operation-faults` runs committed-product response loss,
  pending/running/indeterminate/missing status, changed-input conflict and fenced
  explicit retry against a disposable real Blob ledger. These are **not** complete
  release/concurrency/accounting probes.
- Writable workloads persist one-shot admission and finite 512-ticket read pools
  in their existing operations container. Candidate Planner also acquires its
  existing active-run slot. Failed probe admissions/results are retained; repair
  is explicit. No new resource, data role, package pin or fixture was introduced.
- `storage-boundaries` uses the actual Blob SDK and assigned workload MI, before
  the worker's subscription-secret branch. Normal application hosting still
  initializes its allocated runtime. The operator seeds isolated same-container
  copies of real ledgers; real draft/finding products are prerequisites, never
  fabricated controls. Each writable workload performs the fixed read/write
  matrix with independent permitted controls and conditional writes. Operator
  snapshots verify unchanged content; runtime and storage records must agree on
  service ID, physical client-request ID, identity, method, target and time.
  Shared 900-second orchestration and durable 512-ticket envelopes remain bounded.
  Reference Data execution is still pending the narrow console decision.
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
- `DirectModelProbe` has a tested actual-MI, one-shot HTTPX2 provider using the
  cognitive-services token scope, fixed v1 inference path, bounded nonprivate
  prompt and 2,000-output-token maximum. It exports no token or response prose.
  **It is not yet dispatched by the full suite:** asserted control IDs cannot
  enable a worker model mode without integrated global admission and working
  APIM controls. Normal delegated model grants have not been expanded to hide
  that missing orchestration.

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

Reports are immutable hash-named JSON and Markdown under private
`STATE/acceptance/`, **outside every Git checkout**. Report directories inside a
checkout are rejected even if ignored. Prior exports and failures are retained.
Unknown payload fields are removed; prompts, private notes and credentials are
not evidence. Caller credential mapping and executing identity hashes are distinct.
No automatic publication or deletion occurs.

## Actual telemetry versus assertions

Application instrumentation emits only allowlisted metadata, actual service request
IDs and hashes. The existing Container Apps diagnostic path can export those records
to `ContainerAppConsoleLogs_CL`; these records are explicitly `console`, not
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

**Console export is supplemental, not the required assigned-MI Application
Insights exporter.** No SDK exporter exists in the approved application lock:
`opentelemetry-api` alone cannot export. The required ingestion/sampling proof
therefore remains blocked. No local stdout fixture or diagnostic setting can
substitute for that proof. Actual exporter delivery, all sender/query authority and
effective sampling must be established before any full acceptance.

## Remaining implementation gates

1. Select an approved exact assigned-MI exporter/ingestion protocol. Public PyPI
   inspection found `azure-monitor-opentelemetry-exporter==1.0.0b58` is a **beta**,
   requiring additional `opentelemetry-sdk`, `msrest` and `psutil`. It was inspected,
   not selected or installed. Existing approval of the beta A2A adapter does not
   approve another beta or an arbitrary new dependency graph.
2. Execute/verify the implemented storage/origin providers and finish read-only
   Reference Data execution; establish pre-application ingress-denial evidence,
   and complete direct-model probes, all route
   capabilities and credential/certificate/context rotation proof.
3. Complete all deployed accounting/time boundaries, safe-read retry probes,
   release-response loss, cross-operation release uniqueness, incompatible version
   updates, inherited deadline/post-effect and actual restart probes.
4. Connect validated independent service correlations/no-effect proofs to each
   required check. The partial harness intentionally cannot produce a complete
   pass merely because its available probes ran.
5. Resolve one-shot execution for the read-only Reference Data identity without
   granting write authority. Pinned CLI `containerapp exec` exists, but its
   implementation uses a TTY and ARM `2025-07-01`; the approved application ARM
   matrix uses `2025-01-01`. No console/API exception or broad proxy was introduced.

Fresh deployment, safe repair, manual teardown/residue evidence and actual portal
plan observation remain operator/task-21 evidence conditions. Ordinary managed
identities are not Entra Agent IDs. Agent 365, Conditional Access, Defender and
Purview remain explicitly unexercised.
