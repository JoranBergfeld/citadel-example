# Operator lifecycle — issue 19

Run all commands from this checkout with the exact environment in [stack.md](stack.md).
Public entrypoint: **`python -m citadel.operator`**. Deployment uses native CLI/Bicep;
one approved human Azure portal observation verifies the actual API Center plan.
No hosted control plane, human-user creation, silent region/model replacement,
or automatic cleanup.
Certificate generation declares `cryptography==50.0.2` directly; that exact version
and all its artifacts were already in the accepted lock. No resolved version,
image/tool pin, requirement hash, or wheelhouse artifact changed.

## Approved manual gate: API Center plan verification

The approved API Center `2024-03-01` specification exposes only
`properties.provisioningState` on its Service GET, not a read-only plan/SKU.
There is no plan/SKU endpoint in that approved specification. A fake `sku: Free`
response is not a native-command contract test.

Primary evidence: [the approved immutable Service/ServiceProperties definitions](https://github.com/Azure/azure-rest-api-specs/blob/505d2b30d8ab3ac1d8d8bb262bae8945fe6631c0/specification/apicenter/resource-manager/Microsoft.ApiCenter/ApiCenter/stable/2024-03-01/apicenter.json)
and the [stable template reference](https://learn.microsoft.com/en-us/azure/templates/microsoft.apicenter/2024-03-01/services).
The published Free default/limits are not verification of an actual instance's plan.

The owner approved **manual portal verification with recorded evidence**. That is
approval of the process, **not proof that any resource exists or is Free**.
Ordinary preflight and explicitly confirmed foundation creation may proceed.
Deployment then stops with `api_center_portal_observation_required`, before data
bootstrap, image build or runtime activation. No provider plan field is fabricated,
and no API, SKU or policy is changed.

On same-ID retries, fresh protected inventory and an exact service GET must
verify the existing API Center's ID, ownership tag, region and successful
provisioning. The operator then skips only its service PUT, avoiding the live
provider's undocumented required-SKU update error. Initial creation and child
resource reconciliation remain enabled. A returned SKU is diagnostic metadata,
not a substitute for the approved portal observation.

The operator must observe the actual created resource, privately record the
observation and supporting evidence, then explicitly resume the same deployment.
There is no `--assume-free`/boolean bypass or automatic continuation. Local fixtures
exercise this same public command graph with clearly synthetic evidence, never a
production bypass. No real resource was created or observed during issue 19.

All other documented cloud commands below are implemented, but were **not run
against Azure** for issue 19. Deployment success must never be inferred from the
foundation, native exit zero without outputs, local tests, or fixture adapters.

## Prepare and initialize

```sh
# Exact Python 3.12.15 and uv 0.12.21, not the host's default interpreter.
uv sync --locked --python /absolute/path/to/python3.12
export PATH="$PWD/.venv/bin:$PATH"
umask 077
mkdir -p .citadel
chmod 700 .citadel

# DATA is the retained exact source directory described in evidence.md.
python -m citadel.operator prepare --source-dir "$DATA" --bundle-dir "$PWD/.citadel/bundle"
```

Preparation verifies the four-complete-candidate prerequisite before publishing
eight immutable JSON objects, with the existing independent row pin and SHA-256
manifests. Byte-identical repeats reuse files; changed bytes fail. It never widens
the first twenty or fabricates missing dimensions. Acquisition, if needed, remains
`python -m citadel.evidence acquire --source-dir "$DATA"`; it uses the fixed source.

Create **`.citadel/config.json` with mode 0600** in an editor. Replace every
placeholder; do not put target IDs, keys, or private certificates in shell arguments,
azd environment files, committed defaults, public issue logs, or shared evidence.

```json
{
  "deploymentId": "sample19",
  "subscriptionId": "<explicit-enabled-subscription-guid>",
  "tenantId": "<explicit-tenant-guid>",
  "publisherEmail": "<real-operator-contact>",
  "collectorPrincipalIds": ["<explicit-existing-collector-principal-guid>"],
  "location": "westeurope",
  "modelCapacity": 1,
  "modelTokensPerMinute": 1000,
  "createResourceGroups": true,
  "bundleDir": "/absolute/path/to/checkout/.citadel/bundle",
  "tools": {
    "azurePython": "/absolute/path/to/isolated-azure-cli-2.91.0/bin/python",
    "uv": "/absolute/path/to/uv",
    "azd": "/absolute/path/to/azd-linux-amd64",
    "bicep": "/absolute/path/to/bicep-linux-x64"
  }
}
```

Capacity/TPM above are example requested inputs, **not available quota**.
Capacity is strictly 1–120; actual usable TPM is independently checked, 1–120000.
Booleans cannot substitute for integer inputs. No actual subscription is a default.
`createResourceGroups=false` requires all four exact deployment-tagged groups:
`citadel-<id>-platform`, `-reference`, `-evidence`, `-planning`. No arbitrary-group adoption.

```sh
chmod 600 .citadel/config.json
export CITADEL_STATE_DIR="$PWD/.citadel/sample19"
python -m citadel.operator init --config .citadel/config.json --state-dir "$CITADEL_STATE_DIR"
python -m citadel.operator check --state-dir "$CITADEL_STATE_DIR"
```

`init` records immutable target/configuration/software fingerprints. Repeating it
with the same inputs preserves state. Changed inputs conflict, rather than silently
repointing an inventory. Do not reuse a deployment ID for another target or artifact.
`check` verifies the retained bundle/fixtures, interpreter/platform, exact uv/azd/
Bicep/Azure CLI versions, Docker engine, and actually compiles `infra/main.bicep`.
It runs only Azure CLI's local `version`, not account or token commands.

## Private state and authentication

`$CITADEL_STATE_DIR` is 0700, owned by the operator. State/configuration/credential/
request/evidence files are 0600. Symlink files and group/world-readable private
inputs are rejected. An exclusive operator lock serializes stateful CLI calls.

The Azure adapter uses **`$CITADEL_STATE_DIR/azure`**, never changes the host's default
Azure context, and never uses `az account set`. Establish the operator's existing
Azure CLI login in that private directory using the exact isolated CLI. Authentication
is a human prerequisite, not tenant administration or an automated elevation step.
No login/account/token/secret retrieval occurred during this implementation.

Azure CLI is invoked in its own Python environment. A fixed child entrypoint reads
arguments from stdin; subscription IDs, secure request payloads and tokens are never
OS-visible process arguments. ARM parameters/body documents use private, uniquely
named files, removed in `finally`; abandoned request documents are cleaned on the
next locked command. Child stdout/stderr are captured, never echoed on failure.
Only stable sanitized failure codes reach stdout; native failure never becomes success.
CLI logging/telemetry collection is disabled in the child. Docker registry login
uses password-stdin and a dedicated private Docker config, removed after push.
Host Docker/cloud CLI configuration is not modified.

`credentials.json` stores distinct caller/context keys and the exportable
passwordless self-signed certificate, generated with **exactly 90 × 86400 seconds**
validity. It is private operator recovery material; cloud persistence is only in
allocated vault secrets. Never copy it to telemetry/evidence/Git.
Applications always use the five allocated workload MIs, never the operator credential.
Generation backdates the start by 30 seconds to tolerate small clock regressions;
the end is start plus exactly 90 days. Validation is not relaxed and no grace
period is added to the signed interval.

## Preflight, deploy, repair

```sh
python -m citadel.operator preflight --state-dir "$CITADEL_STATE_DIR"
python -m citadel.operator deploy --state-dir "$CITADEL_STATE_DIR" --confirm-paid \
  --wheelhouse "$WHEELHOUSE"
```

Without `--wheelhouse`, the existing Dockerfile's hash-locked online installation
is used. With it, the real Docker build uses `--network=none`, the named wheelhouse
context, `OFFLINE=true`, the existing lock and immutable base; there is no pip fallback.

Preflight verifies explicit enabled subscription/tenant, group ownership, registered
providers, effective management/data permissions, identity attachment, role-assignment
rights, ACR push and workspace querying, inherited policies, pinned regional model/
version/Standard availability, actual rate-limit metadata and remaining quota.
It performs actual ARM **Provider** validation using secure resolved inputs.
Contributor alone is never assumed able to assign roles or load Blob data.
Policy conflicts, missing providers/permissions, unavailable pins, retired/absent
models or absent quota block. No automatic registration, role elevation, policy
exception, region/SKU substitution, or purge is performed.
Regional model and quota checks use raw ARM `2024-10-01` responses: the exact
`OpenAI` model's nested `model.skus` and the Standard SKU's actual `usageName`.
Azure CLI's model-list SDK projection drops token-rate keys and is not used as
quota evidence. Acceptance uses the same raw catalog interpretation.

The actual deployment graph is:

1. Recheck local/target gates; validate resolved gateway inputs in memory.
2. Deploy subscription Bicep with `deployRuntime=false`; retain all inventory outputs.
   This is explicitly **foundation pending runtime**, not readiness.
3. Read the created API Center using the pinned API, verify exact resource/group
   ownership, location and successful provisioning, and bind its actual read-only
   `systemData.createdAt`. Stop for the human observation below if matching proof
   is absent. Foundation resources remain inventoried, billable, and manually
   deletable. This is not overall deployment failure cleanup or permission to
   activate runtime.
4. After explicit resume with valid proof, load the eight exact reference objects with conditional create; initialize
   six existing `ledger-v1.json` blobs and `planner-operations/active-run-slot.json`.
   On repair, preserve live ledger bytes/leases. Missing previously initialized
   state blocks; it is never cleared or recreated as proof of nonexecution.
5. Build the real image, run the existing offline stack smoke suite, authenticate
   to the **created** ACR, push, compare remote digest to local RepoDigests, and
   lock image writes/deletes. Unrecorded existing tags conflict. Ambiguous pushes
   require matching recorded intent/local image/registry digest before adoption.
6. Validate/deploy the same Bicep with all five exact digest images and
   `["python","-m","citadel.runtime"]`; pass each app the verified TPM.
   The existing template configures identities, runtime/data/gateway, inventory,
   secrets, telemetry and all fixed limits.
7. Query actual workload identities/images and API Center environment/REST metadata.
   Five environment entries and one genuine REST findings API are checked. No
   native A2A/MCP inventory/import claim is made. Recheck the human observation
   against the current resource incarnation, never infer a plan from GET properties.

The same `deploy` command repairs the same ID, including its foundation; it does
not skip provisioning because a previous state file exists. Failures retain
resources, diagnostic state and intent. There is no failure cleanup or crash replay.

### Record the human observation; explicitly resume

Use the [short manual guide](api-center-plan.md); no wizard is required.

On the first foundation stop, open
**`$CITADEL_STATE_DIR/api-center-plan-request.json` in a private editor**.
Its `portalUrl` is the actual resource's Azure portal URL:
`https://portal.azure.com/#@<configured-tenant>/resource<actual-resource-id>/overview`.
The full target/URL is deliberately not printed by the CLI. The file also gives
`requestId`, `deploymentId`, `resourceId`, `resourceCreatedAt` and `requestedAt`.
These are actual inventory/provider bindings, not sample defaults.

1. Open that URL using the intended existing Azure account. Confirm the resource
   identity, then inspect its displayed pricing plan. Record **what is actually
   displayed**, not the documented default. If absent, ambiguous or non-Free, stop;
   do not change plan, grant rights or edit the proof to claim Free.
2. Save a screenshot or other supporting capture showing the resource context and
   displayed plan to a private file such as
   `$CITADEL_STATE_DIR/portal-capture.png`. No keys, tokens, certificates or unrelated
   account information. Capture is nonempty, at most 10 MiB, owned by you, mode 0600.
   Resource IDs are allowed only in this approved **private** observation material,
   not public logs, Git, shared lifecycle evidence or shell arguments.
3. Compute the exact capture SHA-256, then write mode-0600
   `$CITADEL_STATE_DIR/portal-observation.json` in the private editor:

```sh
chmod 600 "$CITADEL_STATE_DIR/portal-capture.png"
sha256sum "$CITADEL_STATE_DIR/portal-capture.png"
```

```json
{
  "requestId": "<copy from private request>",
  "deploymentId": "<copy from private request>",
  "resourceId": "<copy exact actual ID from private request>",
  "resourceCreatedAt": "<copy from private request>",
  "observedAt": "<actual observation time, ISO-8601 with UTC offset>",
  "observedPlan": "<actual displayed plan; only Free can unlock the gate>",
  "evidenceSha256": "<64-character lowercase SHA-256 of the capture>"
}
```

The observation must be after the request and actual creation time, not in the
future. Do not auto-fill a current time in place of the actual observation time.
There are no additional fields and no automatic Free confirmation.

```sh
chmod 600 "$CITADEL_STATE_DIR/portal-observation.json"
python -m citadel.operator record-plan-observation --state-dir "$CITADEL_STATE_DIR" \
  --observation "$CITADEL_STATE_DIR/portal-observation.json" \
  --evidence "$CITADEL_STATE_DIR/portal-capture.png"
# Recording performs ownership/incarnation reads only; it never deploys or starts runtime.
# After successful recording, explicitly resume the SAME ID/state:
python -m citadel.operator deploy --state-dir "$CITADEL_STATE_DIR" --confirm-paid \
  --wheelhouse "$WHEELHOUSE"
```

The CLI copies validated proof/capture to private 0600
`api-center-plan-proof.json` and `api-center-plan-evidence.bin`, recording the exact
observation, source (`human-azure-portal`), observation/recording times and SHA-256.
The locked state binds the proof hash. Capture contents are not printed/exported;
sanitized lifecycle evidence includes only timestamps and binding/proof/capture hashes.

Rechecks occur before bootstrap, each runtime ARM validation/create (including
rotation), inventory completion, and every task-20 acceptance/control hook.
Missing/tampered/public proof, wrong resource/deployment/request, non-Free, invalid
time or mismatched capture hash fails closed. Rejected replacement observations
invalidate prior authorization; an older proof file alone never unlocks deployment.
Same-ID repair preserves a valid observation for the same actual incarnation.
Deletion/recreation changes provider `createdAt`, rotates the request ID and requires
a new human observation—even when the ARM resource ID is unchanged. New private
deployment state cannot reuse another request's proof.

If actual `systemData.createdAt` is absent, the CLI reports
`api_center_creation_identity_unavailable`; do not substitute a local timestamp.
The pinned API inherits this read-only field from its
[common Resource schema](https://github.com/Azure/azure-rest-api-specs/blob/505d2b30d8ab3ac1d8d8bb262bae8945fe6631c0/specification/common-types/resource-management/v5/types.json).
Provider acceptance and actual portal contents still require task 21 verification.
The code cannot detect a later portal-only plan change; record a fresh observation
after any such change. The gate prevents new activation/acceptance; it does not
automatically shut down existing workloads or delete resources.

`inventory`, `collect` and exact-ID manual `teardown` remain available for partial
foundation resources without plan proof. Blocked plan evidence is reported, not
turned into a teardown dependency.

## azd interface

The exact azd 1.35.1 configuration delegates to the same public CLI, rather than a
second hidden deployment with unprotected parameters:

```sh
mkdir -p .citadel/azd .citadel/scratch
chmod 700 .citadel/azd .citadel/scratch
export AZD_CONFIG_DIR="$PWD/.citadel/azd"
export TMPDIR="$PWD/.citadel/scratch"
azd hooks run prepackage --no-prompt       # actual local check
export CITADEL_WHEELHOUSE="$WHEELHOUSE"   # optional supported offline path
export CITADEL_CONFIRM_PAID=yes           # explicit, only after reviewing preflight
azd up --no-prompt                       # same gated staged deployment
```

Direct `azd provision`/`infra create` and `azd down`/`infra delete` are deliberately
blocked by hooks. The custom `up` workflow invokes `predeploy`; hooks are real
supported azd hooks, not generated scripts awaiting manual execution.

## Four demonstrations and reconciliation

Once deployment/readiness and required live controls permit execution:

```sh
python -m citadel.operator demo comparison --state-dir "$CITADEL_STATE_DIR" --run-id compare001
python -m citadel.operator demo replacement --state-dir "$CITADEL_STATE_DIR" --run-id replace001
python -m citadel.operator demo exhaustion --state-dir "$CITADEL_STATE_DIR" --run-id exhaust001
python -m citadel.operator demo denied-bypass --state-dir "$CITADEL_STATE_DIR" --run-id denied001
python -m citadel.operator status --state-dir "$CITADEL_STATE_DIR" --run-id compare001
```

Only operator→Candidate Planner is exposed. The official A2A client emits
`SendMessage` with `returnImmediately`, never SSE. A configured pinned card avoids
an unfunded pre-run discovery request; this is not a discovery proof. Each run has
one persisted dispatch intent. Rerunning the CLI reconciles, never resends ambiguous
work or changes fixtures. Status polls use the authenticated gateway route every
15 seconds, then official `GetTask` retrieves the exact hashed completed product.

The runtime's durable finite tickets authorize incoming operator status/GetTask
reads in the same **512-read** run pool. The CLI additionally persists its local
finite poll count (maximum 64) and original 900-second deadline; it does not grant a
new allowance or equate 400 source reads with total wire reads. Exhaustion, missing
state, wrong ownership, changed hash, failure and indeterminacy are non-success.
No automatic invocation retries or crash replay are exposed. An authenticated
owner may send the **identical** nonblocking A2A `SendMessage` with metadata
`{"citadel_recovery": true}` to fence/reconcile existing work. Only definite
`failed_no_commit` releases global run exclusion; unresolved child/model
admissions retain exclusion. Recovery accepts no caller-supplied service receipts.
A separate identical message with `{"citadel_retry": true}` explicitly retries
only that fenced identity within its original active deadline and remaining
accounting. Recovery and retry flags cannot be combined. The demo CLI itself
still only reconciles; rerunning it never enables retry.

An explicit retry reacquires the global slot under its next fenced generation,
charges another agent attempt and retains all previous model/token/read charges,
per-execution counters and spent read tickets. It never recreates a budget,
extends a deadline or refunds a ticket. Delayed cleanup from a prior generation
cannot release a retried execution's lease. A fresh run may follow definite
no-effect recovery, but a concurrent fresh run prevents retry admission.

The first three cases map to the exact base/replacement/no-alternative fixtures.
Bounded exhaustion is valid evidence, not a completed three-candidate comparison.
The fourth invokes the task 20 fixed-purpose denied-bypass hook **before** a fresh,
separately correlated permitted Planner run. Without real target-identity deny/
allowed-control/no-effect evidence it is blocked, never simulated under operator rights.

## Rotation and revocation

Only while normal runs are quiescent:

```sh
python -m citadel.operator rotate subscription --target operator --stage prepare --state-dir "$CITADEL_STATE_DIR"
python -m citadel.operator rotate subscription --target operator --stage finalize --state-dir "$CITADEL_STATE_DIR"
python -m citadel.operator rotate context --target candidate-planner --stage prepare --state-dir "$CITADEL_STATE_DIR"
python -m citadel.operator rotate context --target candidate-planner --stage finalize --state-dir "$CITADEL_STATE_DIR"
python -m citadel.operator rotate certificate --stage prepare --state-dir "$CITADEL_STATE_DIR"
python -m citadel.operator rotate certificate --stage finalize --state-dir "$CITADEL_STATE_DIR"
python -m citadel.operator revoke --caller operator --state-dir "$CITADEL_STATE_DIR"
```

Subscription preparation preserves the old primary as secondary while installing
the new primary in the allocated vault, then restarts the actual workload revision.
Context rotation first installs dual verification keys, restarts that backend,
then changes APIM's active signing key. Certificate rotation deploys the dual
allowlist before switching the versionless vault secret and issuing the actual
APIM `refreshSecret` request. Refresh/restart alone is not live revocation proof.

Finalization requires task 20 evidence for new-material allowed controls, then
retires old material and requires genuine old-material denial. Old certificate
secret versions are disabled after those checks. Private old/new recovery records
remain operator-owned; no automatic permanent erasure is claimed. Suspension
patches only the exact inventoried APIM subscription and verifies its state.
There is no automatic role escalation or purge to make rotation pass.

The fixed acceptance controls are disabled on normal revisions. Finalization now
uses the actual allocated caller's read-only gateway capability and independently
queried APIM/backend receipts, plus unchanged business-ledger snapshots. For
certificate/context retirement only, the approved test temporarily selects the
pending deployment-owned retired signer **inside APIM**, leaving backend trust
retired. It persists intent, verifies exact selector/policy restoration and
requires a fresh current-material allowed control; it never exports the platform
private key. Missing evidence, concurrent changes or ambiguous restoration retain
exclusion and private diagnostics. A matching `finalize` may collect already
observed controls within their original allowance; it never replays an ambiguous
dispatch or authorizes unrelated changes. See [the approved control contracts](acceptance.md#resume-validation-and-approved-control-contracts).

Briefing Author subscription rotation uses only its existing exact
Release Reviewer finding-read route, with the genuine immutable finding hash
and already-funded read pool. It never uses forbidden Reviewer discovery or
allocates a replacement read grant. Missing source evidence or two remaining
control reads blocks finalization.

APIM certificate selection/restoration uses `PUT Certificate_CreateOrUpdate`
with only the owned Key Vault selector, as required by the pinned
[2024-05-01 certificate swagger](https://github.com/Azure/azure-rest-api-specs/blob/main/specification/apimanagement/resource-manager/Microsoft.ApiManagement/ApiManagement/stable/2024-05-01/apimcertificates.json).
The certificate entity supports HEAD/GET/PUT/DELETE, not PATCH.
Embedded rotations persist their owning acceptance run and charge that run's
single 600-second collection ledger, including failed collection. Standalone
rotations retain their own original bounded allowance; retry never resets it.

Acceptance resolves each fixed container from the exact deployed inventory:
Reference Data's account owns `reference`; Evidence Review's owns drafts,
findings and assessor/reviewer operations; Exercise Planning's owns candidate
lists, briefs and planner/author operations. Operator snapshots, target hashes,
disposable probes, rotation and workflow observation all use that same mapping.
Workload probes validate the three existing deployment-owned team endpoints
against their own deployed account before identity/provider access; manifests
cannot redirect them to another deployment or arbitrary destination.

The workflow acceptance provider separately allows at most 120 seconds of setup,
one unchanged production 900-second workflow and at most 120 seconds of independent
observation/restoration. Its existing 600-second telemetry allowance is separate,
shared with evidence collection and never replenished. No business dispatch,
deadline extension, budget refund or root replay is permitted after expiry.
These implementations do not authorize deployment or live rotation by themselves.

## Evidence, acceptance and manual teardown

```sh
python -m citadel.operator inventory --state-dir "$CITADEL_STATE_DIR"
python -m citadel.operator collect --state-dir "$CITADEL_STATE_DIR"
python -m citadel.operator acceptance --state-dir "$CITADEL_STATE_DIR" --run-id acceptance001
python -m citadel.operator teardown --state-dir "$CITADEL_STATE_DIR" --confirm-deployment sample19
```

`collect` exports lifecycle fingerprints and an allowlisted actual Log Analytics
query (no raw request bodies, prompt/message text, drafts or deliberation).
Missing tables/query authority/oversized results fail instead of silently passing.
Collection has a separate 600-second allowance. Empty/uncorrelated telemetry and
missing checks **do not prove acceptance**. Repeated reports retain prior exports.
The full task 20 oracle must still correlate identities/protocol/storage/model
facts and collect every required check, followed by operator narrative signoff.
Two complete consecutive cloud passes and fresh-deployment proof belong to task 21.

Task 20 interface: `citadel.acceptance.operator_hooks.run`, keyword
arguments `lifecycle`, `check_id`, `run_id`. Fixed check IDs:
`full-acceptance`, `denied-bypass-controls`, `rotation-new-material-allowed`,
`rotation-old-material-denied`. Return a versioned evidence-backed dictionary with
`status: "pass"`, the exact `run_id`, and `evidence_sha256`; fail/blocked/missing
hooks cannot pass. The lifecycle object exposes private state, exact inventory
and native adapters to trusted repository code; it is not a public authority proxy.
Before invoking any provider, task 19 rechecks the human plan proof against the
current resource incarnation and requires deployed runtime. Trusted providers can
call `lifecycle.require_plan_observation()` to obtain that validated private proof.
The partial harness, collection-resume and explicit per-product human-review
interfaces are documented in [acceptance.md](acceptance.md). Task 20 is not yet
complete: missing deployed probes, assigned-MI ingestion and no-effect/correlation
proof remain blocked. No canned acceptance provider or automatic prose approval
is included. `acceptance --collect-only` resumes evidence collection without
replaying the run or resetting its 600-second collection allowance;
`review-acceptance --review PRIVATE_FILE` records the human's explicit answers.

Teardown exports evidence **before** cloud-source deletion, rechecks ownership
before each group deletion, detects unrelated resources and role assignments,
and verifies absence. Managed infrastructure groups require an actual `managedBy`
relationship and inventory; unproven ownership blocks rather than guessing.
Active resources, failed deletions and actually listed recoverable vault/workspace
residue are separate. A deleted group does not establish immediate data erasure.
Partial failures return nonzero and can be inspected/reconciled with the same ID.

Vaults retain the existing seven-day soft-delete/no-purge-protection contract.
There is **no automatic purge command**. Any permanent purge requires a separate
explicit approval, actual permission and matching original vault ID in the saved
inventory; an operator must not use a name-only broad cleanup script. Conflicting
policy requires approval, not automatic relaxation. Log Analytics recovery and
delayed/residual charges still need review after deletion.

### Private state/log locations and exits

- `state.json`: configuration/software/bundle fingerprints, deployment outputs,
  inventory, run intents/read counts, bootstrap status, sanitized event history.
- `api-center-plan-request.json`: actual private portal URL/resource incarnation
  and request binding; `api-center-plan-proof.json` / `api-center-plan-evidence.bin`:
  validated private human observation/capture, never public raw evidence.
- `credentials.json`, `rotation.json`, `rotation-<id>.json`: private recovery
  material, never evidence.
- `template.json`: actual compiled Bicep; `request-<id>.json`: bounded-lived secure
  requests, cleaned on normal completion and next locked command after interruption.
- `<run-id>-product.json`: exact completed shareable product.
- `evidence.json`, `evidence.md`, `evidence-<hash>.json`: sanitized versioned exports,
  human summary and retained prior reports.
- `azure/`: isolated operator authentication cache; no shared host-context changes.

Exit 0 means the named local operation/export/stage completed, **not full acceptance**.
Exit 2 means blocked/conflict/required reconciliation; 1 means failure/partial
teardown; 130 means interrupted—reconcile before retry. Child errors are never echoed.
Use the stable event code and owning prerequisite to remediate; do not copy secure
parameter files or turn on body/debug logging to diagnose failures.

Costs are informational: APIM/ACR, all five warm apps, revisions, model attempts,
Blob/vault operations, unsampled telemetry/retention, probes, every acceptance and
failed run, and delayed/residual charges. Inventory warns after 24 hours.
There is **no financial ceiling**, automatic expiry deletion, or promise that all
recoverable residue is either billable or free.
