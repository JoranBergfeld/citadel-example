# Scoped infrastructure and gateway trust

Issue 15 implements local templates and trust controls, **not a deployed
security claim**. No Azure authentication, paid deployment, role assignment,
secret retrieval or provider registration is part of its validation.

## Deployment boundary

`infra/main.bicep` is subscription-scoped. All names derive from a stable
3–12-character lowercase alphanumeric `deploymentId`; globally unique names
also use the subscription/deployment hash. Never reuse an ID for another
deployment. Four groups are created: `citadel-<id>-platform`, `-reference`,
`-evidence`, and `-planning`.

`createResourceGroups=false` supports those **exact pre-created groups**, not
arbitrary existing groups. The operator must verify inventory ownership and
effective permissions before choosing it. Group placement is not authorization.
Every explicit resource, role assignment and policy has a deterministic name.
Save all three inventory outputs: `inventory`, `teamInventory`, `appInventory`.
Nested ARM deployment records, managed-environment infrastructure, revisions,
provider-created resources and probes must also be enumerated by live lifecycle
inventory; declared outputs alone do not prove a complete cloud inventory.

For staged bootstrap, `deployRuntime=false` creates the foundation and allocated
secrets/roles, but **no applications or gateway APIs**. App inventory then states
`pending`, never success. Build/push images into the resulting Basic ACR, verify
their digests, and reconcile the same deployment with `deployRuntime=true`.
The full deployment requires actual images/commands; there are no placeholder
applications, origin URLs, fake certificates or success endpoints.

### Required inputs

| Parameter | Contract |
| --- | --- |
| `deploymentId`, `location` | Stable ID; only `westeurope` is permitted. |
| `publisherEmail` | Real operator contact for APIM; do not put it in public evidence. |
| `applications` | Exact five workload keys from `infra/workloads.json`; each has `image` (`<created-acr>.azurecr.io/<repository>@sha256:<digest>`), actual `command` and `args` string arrays. Empty only for foundation. |
| `callerKeys` **secure** | Four agents plus `operator`; distinct `primary` and `secondary` subscription keys. No Reference Data outgoing credential is needed. |
| `callerStates` | Same five callers, each `active` or `suspended`; explicit suspension/revocation hook. |
| `contextKeys` **secure** | Each of five targets: `{activeId, keys: {keyId: secret}}`. Per-target keys must differ; 32+ random bytes encoded unpadded base64url. Public key identifiers are alphanumeric/underscore/hyphen. |
| `gatewayCertificatePfx` **secure** | Externally generated exportable, self-signed, passwordless base64 PKCS12, exactly 90 days. Platform vault only. |
| `gatewayCertificates` | Public allowlist: `{sha256, not_before, not_after}`; timezone-aware ISO timestamps. No certificate/private-key values in output. |
| `collectorPrincipalIds` | Explicit human/service principals requiring workspace Log Analytics Reader; no runtime grants. |
| `modelCapacity` | Validated regional Standard capacity 1–120, constrained by actual quota. A value is not a reservation or verified TPM/RPM allocation. |

Lifecycle code must run `citadel.gateway.configuration.validate_deployment_inputs`
on resolved parameter values **in memory before deployment**. It rejects
mutable images, missing entrypoints, shared credentials/context keys, unsafe
policy-substitution identifiers, unsupported regions and wrong certificate
material. `validate_gateway_certificate` checks the real PKCS12 private key,
self-signature, current validity, exact 90-day interval and matching public
allowlist. It never generates or writes a certificate/key.
The validator uses `cryptography` already present in the pinned Azure SDK
dependency closure; it does not install or change the stack.

Do not save secure inputs in tracked parameter files or shell command lines.
No template emits credentials, connection strings or private keys, including
nested module outputs. Only nonsecret resource/identity IDs, URLs, image
digests and pending-state markers are output.

## Resource and authority inventory

- Platform: Consumption-profile managed environment; Basic ACR (admin disabled);
  one BasicV2 APIM unit/system identity; regional OpenAI account with local auth
  disabled; `gpt-4.1-mini/2025-04-14`, `Standard`, `NoAutoUpgrade`;
  isolated gateway-certificate vault; Log Analytics and workspace App Insights.
- Five distinct Container Apps and user-assigned managed identities, each owned
  by its team group: Reference Data, Evidence Assessor, Release Reviewer,
  Candidate Planner, Briefing Author. Each is 0.5 vCPU/1 GiB,
  `minReplicas=maxReplicas=1`; Single revision mode and TCP probes.
  Rolling revisions may briefly add replicas. TCP readiness is not business
  readiness or evidence of accepted credentials.
- One RBAC vault and private StorageV2/Standard_LRS account per team. No shared
  storage keys, blob public access, optional soft-delete/versioning or archive.
- Vaults: RBAC, seven-day soft-delete, no purge protection. Conflicting policy
  blocks deployment; permanent purge needs separate approval/rights.
  New-vault requests omit `enablePurgeProtection`: Azure rejects an explicit
  `false`. The lifecycle reads all four actual vaults and verifies effective
  RBAC, soft-delete, seven-day retention and disabled purge protection before
  the portal gate and during deployed inventory verification.
- Workloads receive only secret-scoped readers for their allocated context
  secret and (agents only) own subscription secret. No agent reads another
  agent's key or the platform gateway certificate.
- Each workload has ACR Pull at the created registry and Monitoring Metrics
  Publisher at the App Insights component. They have no workspace query,
  model, deployment or role-management grant.
- APIM alone receives Cognitive Services OpenAI User at the model account and
  read access to the exact platform certificate secret; it also has telemetry
  ingestion permission. Ordinary managed identities are **not Entra Agent IDs**.

Container Apps diagnostics use `logAnalyticsDestinationType: Dedicated` and the
actual `ContainerAppConsoleLogs`/`ContainerAppSystemLogs` tables, not legacy `_CL`
tables. Console JSON is in `Log`. Every required table retains explicit 30-day
Analytics settings; no unused `AzureDiagnostics` table is fabricated.

Application Insights can create an untagged Failure Anomalies alert. The approved
read-only `Microsoft.AlertsManagement/smartDetectorAlertRules@2021-04-01` inventory
extension includes it only after its actual scope is exactly one deployment-tagged
Insights component in the same owned group and its detector is
`FailureAnomaliesDetector`. Scope is rechecked even after the alert enters inventory;
foreign or ambiguous links block repair and teardown. No alert is created by this
extension.

### Container-scoped Blob roles

| Container | Runtime permissions |
| --- | --- |
| Reference `reference` | Reference Data Reader only |
| Evidence `drafts` | Assessor Contributor, Reviewer Reader |
| Evidence `findings` | Reviewer Contributor only |
| Evidence `assessor-operations` | Assessor Contributor only |
| Evidence `reviewer-operations` | Reviewer Contributor only |
| Planning `candidate-lists`, `planner-operations` | Planner Contributor only |
| Planning `briefs`, `author-operations` | Author Contributor only |

No grants are on a prefix, storage account, team group or subscription.
Contributor still permits deletes/overwrites: immutable versions, conditional
updates, release uniqueness, ownership and fencing are application duties.
Issue 16 agrees that draft/release commit ledgers may live beside their
artifacts in `drafts`/`findings`; generic operation containers remain separate.
There is no shared cross-team accounting container or shared identity.

## Public gateway interfaces

Each workload's APIM prefix is `/<workload-name>`. Origin paths omit that prefix.

| Origin path | Method and distinct capability |
| --- | --- |
| `/a2a` | POST A2A 1.0 JSON-RPC `SendMessage` (invoke) or `GetTask` (status); no other RPC methods/batches |
| `/.well-known/agent-card.json` | GET discovery on permitted invocation edges |
| `/operations/{operationId}` | GET status on permitted invocation edges; owner check remains in operation service |
| `/findings/{findingId}/versions/{version}` | GET exact released version, Reviewer backend only; Planner/Author only |
| `/mcp` | Reference Data only: POST/GET/DELETE Streamable HTTP session transport |
| `/openai/v1/chat/completions` | APIM-only model API; four agents only, never operator/Reference Data |

Invocation edges: operator→Planner; Planner→Assessor/Author/Reference Data;
Assessor→Reviewer/Reference Data; Reviewer→Reference Data. Findings reads
**do not** grant Reviewer invocation or status/discovery access to Planner or
Author. Unknown credentials, APIs, routes and methods deny by default.
MCP POST allows initialize/initialized notification/ping/tools-list and the
three read-only tools `search_airports`, `lookup_airport`, `list_runways`.
Query strings are rejected (including subscription-key-in-query). Clients must
use `Ocp-Apim-Subscription-Key` headers. Discovery and returned follow-up URLs
must use gateway addresses; runtime must never publish its origin.

Model policy requires the exact deployment, `max_completion_tokens` in 1–2,000, no
alternative max-token field and nonstreaming completion. It applies 12/minute,
120k estimated TPM, global model concurrency one and a 60-second header timeout.
These gateway counters are approximate/additional controls, **not** authoritative
per-run accounting or a financial limit. Runtime enforces all exact intersecting
limits in `infra/limits.json`, including 16,000 input tokens and delegated
budgets. A2A exchanges have 180-second header timeouts; runtime must enforce
total exchange/run deadlines and safe-read 30-second deadlines itself.
The pinned Framework Chat Completions adapter translates its public
`options={"max_tokens": 2000}` into wire `max_completion_tokens`; a real
adapter/request-boundary test covers this distinction.

## Reusable origin trust middleware

Wrap the **entire** actual ASGI application with:

```python
from citadel.gateway import GatewayTrust, TrustConfiguration

application = GatewayTrust(
    actual_application,
    TrustConfiguration.from_json(
        target=allocated_target,
        certificates=public_certificate_allowlist_json,
        signing_keys=allocated_context_secret_json,
    ),
)
```

The deployed app receives `CITADEL_TARGET`, `CITADEL_GATEWAY_CERTIFICATES` and
secretRef `CITADEL_CONTEXT_KEYS`. Production Azure clients must use only the
assigned `AZURE_CLIENT_ID` with explicit `ManagedIdentityCredential`, never
`DefaultAzureCredential`/operator fallback.

ACA requires a TLS client certificate. Middleware additionally authorizes the
actual forwarded SHA256 against the configured current-validity allowlist and
rejects ambiguous/duplicate XFCC. Certificate **presence is insufficient**.
It also requires APIM's HMAC-SHA256 context signature. This prevents arbitrary
forged caller/certificate headers from being accepted even before the live
ingress header-overwrite gate is proven. Each backend holds only its own
context-validation secret, not another backend's secret or gateway private key.
This secret is a symmetric backend-specific trust credential, not Entra caller
authentication; compromise of a backend already compromises that backend.

Canonical UTF-8 signature input, joined with LF and no trailing newline:

```
v1
key-id
unix-seconds
request-id
validated-caller
target
HTTP-METHOD
origin-path
lowercase-SHA256-of-exact-body-bytes
```

APIM overwrites `X-Citadel-{Caller,Target,Key-Id,Timestamp,Request-Id,Signature}`,
removes incoming certificate/auth/subscription headers, rewrites the exact
origin path, signs, and presents the platform client certificate. Signature is
base64; freshness window is 30 seconds. Body limit is 1 MiB.
All API backends verify TLS chain and hostname.
Business logic consumes only `scope["citadel.caller"]`,
`scope["citadel.action"]`, `scope["citadel.request_id"]`, never caller fields in
the body or unvalidated headers. Status/findings ownership still belongs to
the durable service; a valid gateway request is not an ownership grant.
Signature freshness is not a durable anti-replay ledger; operation/input
binding and no-duplicate-side-effect rules remain mandatory.

### Rotation and revocation hooks

1. Generate new real 90-day certificate off-source; validate import/public
   metadata. Deploy old+new public allowlist before replacing the platform
   versionless certificate secret. Trigger/verify APIM Key Vault refresh;
   automatic refresh timing is not immediate revocation proof.
2. Verify allowed gateway traffic using the new certificate, remove the old
   fingerprint from all origins, verify old/unrelated/missing-certificate
   denials, and revoke/delete old secret versions under operator control.
3. Rotate each subscription's unused key, update the workload's allocated
   team-vault secret, verify allowed routes, replace the formerly active key,
   then prove its rejection. Suspend that exact subscription for immediate
   caller revocation. Both primary and secondary remain valid until replaced.
4. Context signing keys rotate per target: overlap validation keys, switch
   `activeId`/APIM named value, verify permitted traffic, then remove the old
   key from the target secret. Restart/revise apps or wait for and **verify**
   ACA secret refresh; do not assume environment variables hot-reload.
5. Never print key/PFX values or include them in acceptance evidence.

## Diagnostics and inventory gates

Workspace and explicit Analytics tables use 30-day retention and total
retention, without archive; daily workspace quota is unlimited (`-1`).
APIM diagnostics sample 100%, include errors, log zero body bytes and no
headers. App Insights requires AAD ingestion; runtime sends `always_on` spans.
No exporter is fabricated here: downstream runtime must actually implement
unsampled, correlated, sanitized telemetry and verify ingestion behavior.
Required diagnostic categories and effective table names/retention are live
gates. Some tables must first materialize through ingestion before their
retention update can succeed; reconcile rather than omit them.

**Approved API Center representation:** the human accepted environment-based
workload inventory plus the genuine released-findings REST capability
([canonical clarification](https://github.com/JoranBergfeld/citadel-example/issues/7#issuecomment-6176175396)).
`infra/modules/inventory.bicep` uses only stable `2024-03-01` resources:

- Five **testing environment** records represent the actual four agent apps
  and Reference Data MCP app, with server type `Azure compute service`.
- Seven required, flat string metadata properties per environment identify
  the real workload ARM ID (`workload`), `protocol`, `protocol-version`, `team`,
  `gateway-address`, `identity-kind`, and actual `identity-resource-id`.
  A2A remains A2A `1.0.0` using JSON-RPC 2.0; MCP remains MCP `2025-11-25`
  using Streamable HTTP. Identities are ordinary user-assigned managed
  identities, explicitly **not Entra Agent IDs**.
- This is **workload/environment inventory, not native A2A/MCP API
  registration or import validation**. No JSON-RPC transport is labeled REST.
- Separately, one genuine `kind: rest` API records released-findings reads.
  Its gateway deployment references API Center-scoped environment ID
  `/workspaces/default/environments/release-reviewer`, the actual host.
  The advertised base URL is APIM's `/release-reviewer`; the documented
  capability is GET `/findings/{findingId}/versions/{version}`. It confers
  neither Reviewer invocation nor release/private-draft access. No imported
  definition or verified operational `state` is fabricated.

Inventory is configured only with real runtime applications and gateway routes.
Foundation-only output states `not_configured`; an empty workspace never
constitutes an inventory pass. All environment, schema, REST API and deployment
IDs are retained in `inventory.capabilities`.

The Free plan's published limits permit 20 environments and 10 metadata
properties per entity; this representation uses five and seven respectively.
The exact stable API's metadata/provider acceptance, actual Free plan and
effective inventory completeness remain operator-owned **live gates**.
There is no invented `sku: Free` field, paid-plan substitution, API upgrade,
native-import claim or local claim that the provider accepted these records.

Live deployment exposed a stable-provider update incompatibility: initial service
creation succeeded, but repeating the same service PUT failed with a required
null SKU, even though SKU is absent from the pinned published schema. The operator
therefore creates API Center only when absent from fresh protected inventory.
For reuse it verifies the exact expected service ID, deployment tag, region and
successful provisioning through the same `2024-03-01` GET. A mismatch blocks
before ARM. The derived `createApiCenter` parameter skips only the service PUT;
workspace and inventory children still reconcile. No undocumented SKU field is
sent, and the human plan-observation gate remains required.

## Local versus live validation

Use the exact verified Bicep executable (`--version` must be **0.48.1**):

```sh
BICEP_EXECUTABLE=/absolute/path/to/verified/bicep-linux-x64
"$BICEP_EXECUTABLE" build infra/main.bicep --stdout
export BICEP_EXECUTABLE
.venv/bin/python -m unittest discover -s tests/infra -v
.venv/bin/python -m unittest discover -s tests/gateway -v
```

Tests inspect compiled ARM/schema properties, XML structure and real ASGI
allow/deny behavior. They **do not execute Azure's C# policy engine** or verify
effective inherited roles. Compilation cannot establish SKU availability,
policy/provider acceptance, APIM certificate/signature behavior, header
overwrite, stream/session routing, Free inventory, model quota/retirement,
permission propagation, image pulls, unsampled ingestion or live enforcement.

Source-supported interfaces:
[ACA client certificates](https://learn.microsoft.com/en-us/azure/container-apps/client-certificate-authorization),
[APIM policy expressions](https://learn.microsoft.com/en-us/azure/api-management/api-management-policy-expressions),
[APIM AAD telemetry](https://learn.microsoft.com/en-us/azure/api-management/api-management-howto-app-insights),
[API Center API schema](https://learn.microsoft.com/en-us/azure/templates/microsoft.apicenter/2024-03-01/services/workspaces/apis),
[environment schema](https://learn.microsoft.com/en-us/azure/templates/microsoft.apicenter/2024-03-01/services/workspaces/environments),
[metadata](https://learn.microsoft.com/en-us/azure/api-center/metadata).

No automated teardown/expiry or spending cap is introduced. Export required
evidence before manual inventory-scoped deletion. Report active resources,
failed deletions, seven-day recoverable vault state and Log Analytics recovery/
purge lifecycle separately; deleting a group is not proof of immediate erasure.
