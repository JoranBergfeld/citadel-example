# Operator lifecycle — issue 19

Run all commands from this checkout with the exact environment in [stack.md](stack.md).
Public entrypoint: **`python -m citadel.operator`**. No GUI, hosted control plane,
human-user creation, silent region/model replacement, or automatic cleanup.
Certificate generation declares `cryptography==50.0.2` directly; that exact version
and all its artifacts were already in the accepted lock. No resolved version,
image/tool pin, requirement hash, or wheelhouse artifact changed.

## Current blocking contract: API Center plan verification

**Paid provisioning is blocked before target/account queries or resource creation.**
The approved API Center `2024-03-01` specification exposes only
`properties.provisioningState` on its Service GET, not a read-only plan/SKU.
There is no plan/SKU endpoint in that approved specification. A fake `sku: Free`
response is not a native-command contract test.

Primary evidence: [the approved immutable Service/ServiceProperties definitions](https://github.com/Azure/azure-rest-api-specs/blob/505d2b30d8ab3ac1d8d8bb262bae8945fe6631c0/specification/apicenter/resource-manager/Microsoft.ApiCenter/ApiCenter/stable/2024-03-01/apicenter.json)
and the [stable template reference](https://learn.microsoft.com/en-us/azure/templates/microsoft.apicenter/2024-03-01/services).
The published Free default/limits are not verification of an actual instance's plan.

`preflight`, `deploy`, and `azd up` return blocked
`api_center_plan_read_contract_unresolved`. **Do not remove this gate, grant wider
rights, assume Free, or upgrade the API/plan.** The decision owner must approve
an actual read interface and its verification contract. Implement that adapter,
then exercise live provider acceptance. Local Azure fixtures deliberately bypass
this one gate to exercise the downstream command graph; they do not prove it.
There is no operator flag that bypasses the production gate.

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

## Preflight, deploy, repair

After resolving the API Center read-contract gate:

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

The actual deployment graph is:

1. Recheck local/target gates; validate resolved gateway inputs in memory.
2. Deploy subscription Bicep with `deployRuntime=false`; retain all inventory outputs.
   This is explicitly **foundation pending runtime**, not readiness.
3. Load the eight exact reference objects with conditional create; initialize
   six existing `ledger-v1.json` blobs and `planner-operations/active-run-slot.json`.
   On repair, preserve live ledger bytes/leases. Missing previously initialized
   state blocks; it is never cleared or recreated as proof of nonexecution.
4. Build the real image, run the existing offline stack smoke suite, authenticate
   to the **created** ACR, push, compare remote digest to local RepoDigests, and
   lock image writes/deletes. Unrecorded existing tags conflict. Ambiguous pushes
   require matching recorded intent/local image/registry digest before adoption.
5. Validate/deploy the same Bicep with all five exact digest images and
   `["python","-m","citadel.runtime"]`; pass each app the verified TPM.
   The existing template configures identities, runtime/data/gateway, inventory,
   secrets, telemetry and all fixed limits.
6. Query actual workload identities/images and API Center environment/REST metadata.
   Five environment entries and one genuine REST findings API are checked. No
   native A2A/MCP inventory/import claim is made. Actual Free-plan proof remains blocked.

The same `deploy` command repairs the same ID, including its foundation; it does
not skip provisioning because a previous state file exists. Failures retain
resources, diagnostic state and intent. There is no failure cleanup or crash replay.

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
No automatic read retries, invocation retries or explicit failed-run replay are exposed.

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

Task 20 interface: implement `citadel.acceptance.operator_hooks.run`, keyword
arguments `lifecycle`, `check_id`, `run_id`. Fixed check IDs:
`full-acceptance`, `denied-bypass-controls`, `rotation-new-material-allowed`,
`rotation-old-material-denied`. Return a versioned evidence-backed dictionary with
`status: "pass"`, the exact `run_id`, and `evidence_sha256`; fail/blocked/missing
hooks cannot pass. The lifecycle object exposes private state, exact inventory
and native adapters to trusted repository code; it is not a public authority proxy.
The separate API Center plan-read decision must be resolved before paid preflight.

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
