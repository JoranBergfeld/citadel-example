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
Changed cached bytes fail instead of silently refreshing. No runtime Blob
write is available to Reference Data.

The lifecycle must prepare/upload that bundle and preinitialize six
`ledger-v1.json` blobs: the four operations containers plus Evidence Review's
`drafts` and `findings`. Use `empty_ledger()`/the existing deployment-only
initialization API. Runtime never creates missing state as evidence that work
did not happen.

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
result `GetTask` conservatively charges its HTTP request plus both storage
reads. No process-global model/read counter is used.

All existing ceilings still intersect: 900-second inherited deadline,
20 candidates, 42 executions, 128/8 model attempts, 16000/2000 tokens per
attempt, one million aggregate tokens, 512 reads, one model request in flight,
12/minute and actual quota. UTF-8 byte bounds plus fixed message framing
conservatively bound prompt tokens. Model SDK retries are disabled, and an
HTTP-boundary single-dispatch permit blocks hidden Framework retries.
Model/A2A/read total deadlines are 60/180/30 seconds. Late/ambiguous model
responses never free model admission. Current networking does not automatically
retry failed reads; zero is within the maximum two automatic read retries.

Admission and owner-status/finding handlers use bounded fixed-purpose
control reads, including after restart. During collaboration, the calling
agent prepays both the protocol read and its downstream storage read.
External operator status/recovery probes are control-plane operations, not
unlimited agent-work allowances; the downstream operator lifecycle must bound
its polling and report those attempts. This is **not** proof that arbitrary
credential holders cannot generate unlimited control-plane requests.

Read reservations are intentionally conservative and unrecoverable after a
crash: Planner reserves 96, each assessment reserves 72 split into Assessor's
40 and Reviewer's 32, and Author reserves 24. One already charged ticket is
withheld for recording incomplete execution. No unused child quota is refunded.
Consequently, a run cannot admit more than five assessment pairs with these
reservations. The actual approved normal and missing-width replacement cases
fit (three and five candidates). The actual twenty-member no-alternative case
reaches **explicit read-budget partial failure**, not a fabricated exhausted-pool
success. A smaller exhausted pool is tested. Completing the full twenty-member
demonstration needs a more economical prepaid-read/storage design or an approved
contract decision; do not raise the 512 ceiling or claim full scenario acceptance.

Restart never schedules persisted pending/running work. Identical submissions
return existing status; changed inputs conflict. Timeout, unavailable
infrastructure, rejection and insufficient evidence are distinct. Ambiguous
external effects stay incomplete; missing state is not proof of non-execution.
`mark_incomplete` fences local ownership without claiming `failed_no_commit`.
If no storage deadline/ticket remains, durable running state remains incomplete.
Existing explicit operations fencing/reconciliation/retry APIs are retained;
this host adds no privileged HTTP recovery endpoint.

## Validation and cloud gates

Local tests use real A2A/MCP/Framework/OpenAI/Blob SDK serialization and ASGI
hosts with bounded external transport adapters. Only tests provide model
fixtures and in-memory ledgers. Set `CITADEL_EVIDENCE_DATA` to the retained
approved snapshot to run both real-data workflow and Blob-bundle tests:

```sh
python -m unittest discover -s tests/runtime -v
```

`tests/runtime/test_live.py` is opt-in:
`CITADEL_RUNTIME_LIVE=1`, `CITADEL_LIVE_GATEWAY`, and `CITADEL_OPERATOR_KEY`.
It performs paid real workflow calls when enabled; ordinary validation never
enables it. It checks real acceptance, polling, exact caveated products and an
allowed/denied route control. These probes supplement—not replace—the four
existing live storage probes and downstream comprehensive task20/21 acceptance.

Unverified: effective Azure authority/certificate/HMAC/policy behavior, actual
model inference/quota, storage fencing in the deployed topology, identity
rotation, deployed latency, telemetry export/collection, two full cloud passes,
operator narrative signoff, fresh deployment and teardown. SDK tracing and
sanitized local incomplete-work logs alone do not establish unsampled deployed
telemetry. No deployment, secret access or paid inference was performed for
local implementation.
