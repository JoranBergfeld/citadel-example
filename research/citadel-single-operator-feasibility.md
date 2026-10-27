# Citadel feasibility: one operator, resource-scoped permissions

Research input for [issue #2](https://github.com/JoranBergfeld/citadel-example/issues/2). **Not an architecture decision, deployment, or tested implementation.**

- Checked: **2026-10-14**; commercial Azure and Microsoft 365 documentation.
- Blueprint: <https://aka.ms/foundry-citadel>, resolved to Azure-Samples/foundry-citadel-platform.
- Upstream pinned to **`89d3d70b13aada1972d2e280e00e5aa49a85ad97`**, committed **2026-10-12T12:14:16Z**. [Pinned overview][B0]; [commit][B1]. Companion layer documents below use the same revision.
- Constraints: one existing human operator, one tenant/subscription; three organizational teams mapped to resource groups; two teams each own at least two agents, third publishes a data MCP server. No new human users, elevated Entra privileges, external real-world actions, or provisioning during research. Disposable synthetic resources/data. No budget cap agreed.
- Vocabulary follows the repository glossary: team, operator, cross-team collaboration. Resource groups model ownership, not people.
- **Fact** means documented in the cited primary source. **Assessment** means an inference under these constraints. **Recommendation** means downstream planning advice, not a selected design. **Unknown** means not established by public documentation or not checked in the actual subscription.

## 1. Answer and limits

**Assessment:** A real-cloud, single-operator sample can demonstrate L1 gateway enforcement, L2 multi-agent operations, and resource-level identity/access/security controls. It cannot honestly promise the full L3 Agent 365 tenant command center or all L4 Defender/Purview/Conditional Access functions with only resource-scoped permissions. Cover all four layers by explicitly marking exercised, conditional, and unavailable capabilities; do not label a custom inventory or Azure RBAC as Agent 365. [B0][S1][S2][S3][S4][S5]

There are two important qualifications:

1. **“No Entra administration” does not mean “no identities in Entra.”** Azure managed identities are service principals provisioned through Azure resource operations. Foundry also documents automatic Entra Agent ID provisioning through its product integration. This is distinct from asking the human to create custom agent blueprints through Graph or the Entra portal, which requires tenant roles and consent. Product integrations can be restricted by existing tenant administrators; subscription ownership alone does not override those restrictions. [S6][S7][S8][S9]
2. **Agent 365 and Entra Agent ID are not globally preview-only anymore.** Agent 365 has been generally available in the commercial segment since **May 1, 2026**. Entra Agent ID's current release page also says generally available. Individual features remain preview, including the Entra creation wizard and older A2A 0.3 tool integrations. Licensing and tenant roles remain independent blockers even for GA capabilities. [S4][S10][S11][S12]

**Unknown:** Actual operator permissions, tenant product-integration policies, qualifying licenses, model quota, preview enrollment, regional capacity, and cloud costs were not inspected. No “will deploy successfully” claim is made.

## 2. Four-layer capability matrix

| Citadel layer | Resource-permission demonstration | Conditional or unavailable under this permission model | Evidence / truthful boundary |
| --- | --- | --- | --- |
| **L1 Governance Hub** — APIM + API Center | APIM can govern model APIs, external MCP tools, and JSON-RPC A2A APIs; apply authentication, explicit consumer allowlists, rate/token limits, diagnostics. API Center can inventory/discover the third team's MCP endpoint and ownership metadata. | APIM tier and transport support matter. Foundry's integrated gateway requires **v2** APIM; a standalone Developer gateway is not an equivalent integrated-gateway setup. Entra OAuth for a custom API needs a real audience and suitable app configuration, not merely “enable MI.” | [B2][S1][S2][S13][S14][S15][S16]. API Center is design-time governance, not runtime authorization. |
| **L2 Agent Operations** — Foundry / Agent Service / BYO | Prompt agents, managed hosted-code agents, or BYO on Container Apps/AKS are documented paths. MCP tools, A2A collaboration, model guardrails, traces and evaluations can be demonstrated with synthetic inputs. At least four genuinely identifiable agents can run without four human users. | Individual runtime/API versions, models, regions, networking and telemetry features have different maturity. Foundry new and classic APIs are not interchangeable. External/workflow-agent Foundry tracing remains preview. | [B3][S3][S6][S17][S18][S19][S20]. Actual per-agent authority must be verified, not inferred from a display name. |
| **L3 Agent Management** — Agent 365 + Entra Agent ID | Resource-level inventory, owner/team mapping, lifecycle, MI/RBAC assignments, and automatically provisioned Foundry Agent IDs can provide **partial** identity/accountability evidence. | Full Agent 365 governance needs Microsoft 365 licensing and tenant administration; custom Entra agent blueprints need Agent ID Developer/Administrator and authorized Graph clients. Managed identities are **not** Entra Agent ID objects. BYO registration in Foundry Control Plane is **not** Agent 365 enrollment. | [B4][S4][S5][S7][S8][S9][S10][S21]. State the L3 fidelity gap explicitly. |
| **L4 Security Foundation** — Entra + Defender + Purview | MI authentication to supported Azure resources, narrow data-plane roles, secret handling, network restrictions, Azure resource diagnostics, and resource-group Azure Policy guardrail governance are feasible when the operator has corresponding Azure permissions. | Defender for AI subscription-plan activation is not an RG-only operation. Agent Conditional Access needs a tenant CA administrator and licenses. Purview enforcement needs specific integrations/licenses/roles; storage tags or homemade filters are not Purview DLP. | [B5][S22][S23][S24][S25][S26][S27]. Mark unexercised Defender/Purview/CA capabilities unavailable or conditional, never simulated as active enterprise controls. |

### Ownership versus authorization

**Facts:** Azure RBAC grants a principal actions/data-actions at a scope. Foundry scopes include resource, project, and agent; current agent-scope assignments are evaluated only for agent endpoint access. Blob data roles can be assigned at container scope. Management-plane Contributor/Owner is not automatically a data-plane inference/blob permission. [S3][S22][S28]

**Assessment:** Three RGs provide inventory, lifecycle, and scope organization. They do not inherently prevent cross-RG calls, isolate network traffic, segregate human duties, or authorize MCP tools. A shared runtime identity can erase agent-level differences; a shared MCP backend identity can access everything granted to that server unless the MCP/gateway enforces caller authorization.

**Recommendations:** Model team ownership on the resources actually deployed in each RG; do not assume projects under one Foundry account can be placed into independently owned RGs. Specify an explicit caller → endpoint/tool → dataset grant matrix. Restrict inherited subscription grants and broad project roles for runtime identities. The single operator remains a privileged operator of all modeled teams, so prove **runtime** separation, not human separation of duties. [S3][S6][S22][S28]

## 3. Permission prerequisites: Azure resources are not tenant administration

These are capability-specific prerequisites, not a request to grant broad roles. Existing delegated rights may satisfy them; missing rights are a blocker, not permission to elevate.

| Operation | Resource/subscription prerequisite | Tenant prerequisite / caution |
| --- | --- | --- |
| Create the three RGs | `Microsoft.Resources/subscriptions/resourceGroups/write` at subscription scope; if the operator has only existing-RG rights, use already-created authorized RGs. Creating resources within them needs relevant provider writes, commonly RG Contributor. | No new human accounts needed. RG rights cannot create new RGs outside their scope. [S28][S49] |
| Register required Azure providers | Provider `/register/action` at subscription scope, covered by subscription Contributor/Owner; already registered providers remove this step. Confirm only selected providers, e.g. CognitiveServices, App, ApiManagement, ApiCenter, Storage, ManagedIdentity, Insights/OperationalInsights, ContainerRegistry and Network if used. | Resource-provider registration can add provider apps to Entra through Azure's managed experience; this is not human app-registration consent. Do not assume RG Contributor suffices for subscription registration. [S29] |
| Create/manage MI-backed compute | Write permission on the compute resource for system-assigned MI. For standalone UAMI creation, Managed Identity Contributor at the appropriate RG; attaching a UAMI requires its `assign/action`, e.g. Managed Identity Operator, plus write rights on the target resource. | Azure provisions the service principal; no human Agent ID role is required merely to use Azure MI. Identity creation does not grant downstream data access. [S7][S30][S31] |
| Assign or revoke Azure RBAC | `Microsoft.Authorization/roleAssignments/write` / `delete` at the target scope or ancestor, e.g. Owner, User Access Administrator, or Role Based Access Control Administrator, subject to assignment conditions. Contributor alone does **not** grant general role-assignment authority. | These are **Azure** roles, not Entra directory administrator roles. Recommendation: use the CLI's documented known-object-ID syntax, `--assignee-object-id ... --assignee-principal-type ServicePrincipal`, rather than relying on directory name lookup. [S28][S49] |
| Create Foundry account / models / projects | Account: `Microsoft.CognitiveServices/accounts/write` at RG scope. Models: `Microsoft.CognitiveServices/accounts/deployments/write` at account scope. Resource/project management and data-plane agent creation require their respective permissions. Foundry User (formerly Azure AI User) covers development/data-plane access, not resource creation. Project MI needs Foundry User on the account for project-mediated model access. | Existing tenant policies may block product-managed Agent ID creation. No evidence that an arbitrary custom blueprint can be created using Azure Contributor. [S3][S6][S9][S18] |
| Create MCP/A2A project connections | Foundry Project Manager on the relevant project; Foundry User to create/test agents. Obtain target-resource data roles for the identity actually used by that connection. | For custom OAuth, an app registration and appropriate consent are separate requirements. Entra Agent ID auth, project MI auth, API-key auth and delegated OAuth are distinct choices. [S12][S20][S32] |
| Invoke a Foundry agent endpoint | Foundry Agent Consumer on the target project, or narrowly at agent scope where supported; Foundry User is broader. Assign to the runtime caller, not only the operator. | New Foundry agent identities may be automatic; do not use the operator's broad token as runtime proof. Incoming A2A needs to be enabled separately. [S3][S12] |
| Use account-level OpenAI inference directly | Cognitive Services OpenAI User on the actual OpenAI resource for MI/Entra inference; do not confuse direct account APIs with Foundry project APIs. | Foundry documentation advises Foundry roles for project work; direct OpenAI access is a different endpoint/permission case. [S18][S33] |
| Manage APIM APIs/policies | Create instance: Contributor/Owner on target RG. Manage instance entities: API Management Service Contributor on the instance. Integrated Foundry gateway additionally needs Foundry Account Owner/Owner and same tenant/subscription, v2 APIM. | Policy editors can act as APIM's MI and potentially exfiltrate its token; they are trusted administrators, not ordinary agent callers. [S13][S34][S35] |
| Build/pull hosted-agent image | Operator/build principal: Container Registry Repository Writer (or AcrPush for a non-ABAC registry). Foundry project MI: Container Registry Repository Reader (or appropriate AcrPull), at registry/repository scope supported by its mode. | Agent runtime identity and project infrastructure identity are different. Do not assign every runtime the image-builder identity. [S18] |
| Read synthetic data | Storage Blob Data Reader at chosen container/account scope; use Data Contributor only for an explicit seeding/writing principal. MCP server MI and agent MI grants differ according to whose token the data service receives. | No Microsoft Graph permission is needed for Azure Blob RBAC access. Entra portal Reader alone is not blob data access. [S22] |
| Query traces / configure diagnostics | Tracing docs require access to linked Application Insights and Log Analytics reader. Hosted-agent permission docs specify project MI Log Analytics Data Reader for evaluation telemetry. Diagnostic-setting writes and access to destination workspace are needed to configure export. | Logs do not require purchasing Agent 365. Tenant sign-in/audit portals may remain inaccessible. [S18][S19][S36][S37] |
| Create RG guardrail policies | Owner or Resource Policy Contributor at RG/subscription scope, per Foundry compliance guide. | Azure Resource Policy Contributor is not a tenant Conditional Access administrator. [S26] |
| Enable Defender for AI | Subscription-plan activation; official overview says subscription Owner or specific equivalent permissions, onboarding says Owner/Contributor, and Foundry guide says subscription Security Admin/Owner. **Documentation does not give one consistent minimum role.** | Confirm effective subscription plan-write rights before including activation. No RG-only activation path was established in these sources. Do not enable a subscription-wide paid plan in a shared subscription merely because the sample uses one RG. [S23][S24][S26] |
| Manage Agent 365 tenant registry/governance | Azure resource roles do not confer access. | AI Administrator or Global Administrator for install/modify/approve/manage; AI Reader/Global Reader and other listed reader roles for appropriate views. Qualifying M365/Agent 365 licensing is separate. Under “no elevated Entra privileges,” these admin actions are unavailable. [S4][S5][S10] |
| Create a custom Entra Agent ID blueprint | Azure RBAC is insufficient. | Agent ID Developer or Agent ID Administrator; client delegated permissions include `AgentIdentityBlueprint.Create`, `AgentIdentityBlueprintPrincipal.Create`, and permissions for credential/auth-property changes. Application/Cloud Application Administrator can consent Graph delegated permissions; Privileged Role Administrator is the least privileged role documented for Graph **application** permission consent. Blueprint ownership can allow later identity creation without an Agent ID role, but does not bootstrap missing blueprint creation or client consent. [S8][S9] |
| Agent Conditional Access | Not an Azure RG operation. | At least Conditional Access Administrator. Agent 365 plus Entra P1/M365 E3, or M365 E7; agent risk-based CA requires P2/E5 in the paired-license path. Azure MI is not automatically covered by Agent ID-specific policies. [S25][S27] |
| Purview integrations | New Foundry integration configuration requires Foundry Account Owner; this does not by itself provide Purview policy/audit administration or licensing. | Specific Purview roles/licensed integration required. Legacy Defender-mediated Purview integration excludes Foundry agent context and requires user-context tokens for data security policies; new Foundry configuration is replacing it. Do not generalize either route to arbitrary MI-only MCP traffic. [S24][S26][S38] |

**Documentation caveat:** Current Foundry RBAC and hosted-agent permission pages differ in their descriptions of Foundry Owner's constrained role-assignment powers. Use the actual built-in role definition/effective actions at the deployment date, and independent explicit `roleAssignments/write` authority where needed; do not depend on a role-name guess. Both pages agree ARM Owner/Contributor does not automatically supply Foundry data-plane permissions. [S3][S18]

## 4. Runtime and collaboration options, not a selected architecture

| Candidate | Documented strengths | Permission / integration / maturity risk to carry into the spec |
| --- | --- | --- |
| **Foundry prompt agents** | Managed instructions/model/tools, no container orchestration to maintain. MCP and A2A integration; prompt-agent tracing GA. [S17][S19][S20][S12] | Pin **new versus classic** API/SDK. New agent object model creates a unique Agent ID/blueprint at creation; older unpublished agents share project identity. MCP project-MI authentication still intentionally shares identity. Inspect actual `instance_identity` / connection principal. [S6][S32][S39] |
| **Foundry hosted agents** | Custom framework/code in managed containers, per-session VM-isolated sandboxes, Responses/Invocations protocols, infrastructure project MI distinct from runtime Agent ID. CPU/memory consumption pricing; Python/C# protocol support. [S17][S18][S40] | ACR, project connections and resource roles required. Official current concepts no longer justify a blanket “hosted agents are preview” claim; this research did not independently establish a global hosted-runtime GA announcement/SLA. A2A 1.0 and managed-agent tracing are explicitly GA; individual preview endpoint/API paths remain. Check chosen region/protocol/version rather than infer maturity for all features. [S12][S19][S39][S40] |
| **BYO on Azure Container Apps** | Own orchestration/framework, HTTP/MCP/A2A endpoints and OpenTelemetry; system/UAMI credentials for Azure dependencies; consumption scale-to-zero is possible. No custom Entra Agent ID blueprint necessary for ordinary workload MI. [S7][S21][S31][S41] | Builder owns validation, tool authorization, loop/retry bounds and telemetry. App ingress authentication is not supplied merely by adding MI. Foundry external-agent tracing is preview; standard Application Insights/OTel is a separate path. Registering a custom agent in Foundry Control Plane requires integrated AI Gateway and reachable endpoint. [S19][S21] |
| **BYO on AKS** | Explicitly in the upstream L2 runtime set; accommodates custom agents/protocols. [B0][B3] | Not separately deep-validated here. More cluster/network/identity/upgrade responsibilities and fixed compute cost than a small consumption deployment. Treat AKS as a possible runtime, not a researched ready-to-deploy baseline; investigate its workload identity and RBAC if chosen. |
| **Copilot Studio / M365 agents** | Upstream supports SaaS agent types and Agent 365 integration. [B0][B4] | Power Platform/M365 licenses, environments, admin controls and publishing consent; no reason to assume available from one Azure subscription alone. Not necessary to meet the three-team/four-agent requirement. [S4][S5][S10] |

### New identity model versus stale shared-identity assumptions

**Facts:** Foundry's identity concepts and MCP authentication pages still describe shared unpublished project identities and unique identities after publishing. Both the migration guide and hosted-agent permission reference describe newer agent objects with dedicated identities. The migration guide explicitly says new agents receive unique identity and stable endpoint immediately; old agents with null identity remain legacy. Its migration example uses `2025-11-15-preview` and `Foundry-Features: AgentEndpoints=V1Preview`. [S6][S18][S32][S39]

**Recommendation:** Pin the object model and inspect runtime principal IDs before claiming “two agents, two security principals.” Do not create Teams/M365 publishing as a workaround for agent identity when the new model can provide it without that channel. If only the legacy shared/project-MI path is available, either accept explicitly team-level authority or choose separate isolation scopes; this is a downstream decision, not made here.

### MCP publishing and governance

**Facts:**

- APIM can expose an existing remote MCP server or convert managed REST operations into MCP tools. Existing remote servers must conform to MCP `2025-06-18` or later; Streamable HTTP or SSE are supported. Native support is listed for Developer/Basic/Standard/Premium and their v2 equivalents, **not Consumption**, and not APIM workspaces. [S2][S14]
- External-MCP how-to says tools **and resources** are supported, while the overview still says tools only and no resources/prompts. **Use tools as the demonstrated compatibility floor; resources remain a documented conflict, prompts unsupported.** [S2][S14]
- APIM policies generally apply to all tools in that MCP server. Select exposed tools deliberately; per-tool authorization is not established merely by attaching a policy to the endpoint. Avoid `context.Response.Body` and global response-body logging: buffering can break MCP streaming. [S14]
- Foundry supports public/private MCP endpoints; private MCP needs networking, including its documented dedicated MCP subnet/internal Container Apps route. Project connections support API keys, agent identity, project MI, and individual OAuth passthrough. Connection API keys are accessible to project members; they are shared secrets, not per-human isolation. [S20][S32]
- Foundry Toolbox provides a reusable managed MCP endpoint and central tool authentication/versioning. Long-running MCP tasks are preview. Tool approval gates express execution consent, not downstream authorization. [S20][S17]
- API Center registers remote MCP endpoint metadata for discovery. It does not host the third team's business data or enforce tool access. [S15][S16]

**Assessment:** The third team can publish a real read-only data MCP server backed by synthetic Azure data and expose it via a governed endpoint. A compliant MCP protocol library supplies transport; it does not supply the caller-to-dataset authorization rule. If the MCP server accesses storage as its own MI, storage sees **the server**, not the originating agent.

**Credential choices left open:** APIM API-scoped/product-scoped subscription keys are a documented resource-only inbound option and can be separate per modeled caller without creating human users. They prove credential-scoped gateway access, not Agent ID or secretless end-to-end identity. Token-based inbound auth needs issuer/tenant/audience/caller checks and a correctly registered audience. For native Azure backends, APIM can obtain outbound tokens with its MI and narrow Azure data roles. That authenticates the **gateway**, not the caller, to that backend. A custom MCP audience/app registration and any required consent are additional preconditions; no authority for creating them is assumed. Never repurpose an ARM/Graph token as a generic custom API credential or accept unverified `agent-id` headers as identity. [S13][S32][S35]

### Agent-to-agent transport

**Facts:** Current Foundry A2A `a2a` tool is **GA**, protocol **1.0**. Older `a2a_preview` is preview, protocol **0.3**. For Foundry targets, enable incoming A2A and give caller Foundry Agent Consumer (or higher) on the target; target audience is `https://ai.azure.com`. Foundry target limitations include text-only and no streaming responses. APIM A2A import supports JSON-RPC, transforms the agent card to gateway host/preferred JSON-RPC/subscription requirements, and does not deserialize outgoing response bodies. [S12][S13]

**Fact:** Classic Connected Agents / `agent.as_tool` is **not available in new Foundry Agent Service**; replacements documented are A2A and workflows. Do not reuse the upstream's generic “Connected Agents” wording as a new-API implementation requirement. [B3][S12]

**Recommendation:** Distinguish (a) a runtime orchestrator calling multiple agents using their native endpoint APIs, (b) a genuine A2A protocol exchange, and (c) MCP calling a tool. The sample may choose among them, but must label the transport actually exercised. For cross-team access, target-endpoint authorization and backend bypass prevention matter irrespective of protocol. Do not claim “all calls governed” solely because agent cards or MCP URLs were registered.

## 5. Honest L3/L4 coverage and licensing

**Facts:** Agent 365 is per-user licensed; at least one qualifying licensed user enables it. The current service description lists a standalone subscription for eligible M365 subscriptions and inclusion in **M365 E7**. E5 is described by the overview as a “works best” prerequisite, not evidence of a universal mandatory E5 requirement. The service-description feature table combines “included with M365” and “requires Agent 365” columns in ways that should not be used as a definitive contract for this tenant. Verify purchased entitlements/Product Terms. No public evidence supports calculating cost as four agent licenses. [S4][S10]

**Facts:** Entra Agent ID is available to Entra customers; Agent 365 enables Microsoft 365 service/workflow use and licensing. Agent ID GA does not eliminate role/consent prerequisites. Conditional Access licensing requires Agent 365 + P1/E3 or E7; risk-based CA additionally needs P2/E5 in the paired path. User-account/mailbox-style agents require further objects/permissions and are not a prerequisite for the Azure-only sample. [S8][S9][S11][S25][S27][S42]

**Facts:** Defender for AI threat protection is GA for supported Azure OpenAI/Model Inference text tokens in commercial Azure, not image/audio or all cloud/BYO agent activity. Trial: 30 days, capped at 75 billion scanned tokens, charges begin when either limit is reached. Its paid plan does not include the paid Purview data-security feature. [S23][S24][S43]

**Facts:** Purview's Agent 365 documentation lists audit, classification, labels, DLP, risk, eDiscovery and retention, but not encryption without labels. Newly created Agent 365 content does **not** automatically inherit source sensitivity labels. Its supported Agent 365 interactions are not proof that arbitrary Blob/MCP payloads are protected. Legacy Defender-mediated Foundry Purview integration explicitly excludes agent data/context and needs user-context for data-security policies; a newer Foundry route is being rolled out/documented instead. [S24][S26][S38]

**Recommendation:** L3 evidence can include owned agent inventory, real resource/runtime identities and lifecycle; call this partial resource-level accountability. L4 evidence can include real Azure authorization denials, native model guardrails and optional RG Azure Policy compliance. Mark Agent 365 registry workflows, custom Agent ID bootstrap, tenant CA and unsupported/unlicensed Purview/Defender paths **not exercised**. If full-fidelity L3/L4 is an acceptance requirement, the constraints are incompatible until the human explicitly changes them; do not silently expand permissions.

## 6. Observability and denied-access proof to require downstream

This is a proposed evidence contract, **not executed tests**.

**Facts:** Prompt/hosted Foundry tracing is GA; workflow/external-agent tracing is preview. Traces use OTel and Application Insights. APIM has gateway logs, MCP/A2A telemetry and custom traces/correlation headers. Blob resource diagnostics can capture `RequesterObjectId`, `RequesterAppId`, `RequesterAudience`, `AuthenticationType`, `StatusCode`, `StatusText`, `ClientRequestId` and `CorrelationId` in `StorageBlobLogs`. Azure Activity Log is not the sole source for data-plane denial evidence. [S19][S2][S13][S36][S37]

**Recommendations for the future spec:**

1. Capture deployment manifest: resource IDs/RGs, four agent identifiers, actual runtime principal object IDs, MCP publisher identity, endpoint/tool/data grants, model/API/SDK versions, and enabled/disabled layer capabilities.
2. Exercise one allowed cross-team collaboration using the chosen transport, with the third team's synthetic read-only MCP data. Record participating agent/tool spans, gateway route, trace/correlation ID and final result. Repeat once to expose state/identity drift.
3. At gateway boundary: valid allowed caller → success; missing/invalid credential → documented authentication failure; valid but disallowed caller → authorization denial; forged caller metadata → no additional access. Record gateway result and absence of backend invocation, not just an LLM's statement “I cannot.”
4. At data boundary: from the actual unauthorized workload principal, directly attempt a synthetic container read with Entra auth → expected service-level authorization denial. An authorized principal should read a different permitted container. Record principal/audience, service error and storage logs. If all storage requests use a shared MCP MI, explicitly state that backend storage logs alone do not prove per-agent isolation.
5. If the MCP publisher MI is allowed read-only data, attempt an isolated synthetic write/delete → denied; verify the fixture remains unchanged. Do not use real-world external actions, real financial/workflow systems, or tenant-wide destructive tests.
6. At agent boundary: allowed versus unapproved agent endpoint call; validate target-side caller role and A2A/tool trace if chosen. If gateway MI replaces caller credentials, correlate the original caller with backend identity and state this delegated-trust limitation.
7. Prove anti-bypass: direct origin model/MCP/agent URL must be denied/unreachable for an unapproved runtime. A public, broadly authorized origin invalidates “govern every call,” even when the normal path uses APIM. Integrated Foundry gateway verification specifically checks gateway request metrics/logs; new projects inherit enablement while existing projects must be added. [S34]
8. Test request/token limit with bounded synthetic input. Integrated gateway guide documents **429** for TPM limit and **403** for total token quota. These are governance denials, not interchangeable with RBAC denial. Record which policy produced the result. [S34]
9. Test a harmless synthetic injection/data-egress fixture only inside the sample. Distinguish model/content guardrail refusal, tool policy denial, cloud RBAC denial and Defender alert; no one signal proves all four.
10. Keep deterministic tool/permission tests separate from stochastic model quality evaluation. Bound turns, tokens, recursion and retries, especially A→B→A cycles. Include timeout/cleanup behavior in the chosen collaboration contract.
11. Export evidence before teardown; redact tokens, keys, authorization headers and payload secrets. Synthetic inputs do not justify logging credentials. Capture positive and negative results with same principal/test window after RBAC propagation; distinguish auth failures, firewall failures, resource-not-found, and authorization failures.

Example query shape from the documented StorageBlobLogs schema, to adapt to fixture IDs rather than execute during planning:

```kusto
StorageBlobLogs
| where TimeGenerated > ago(1h)
| where RequesterObjectId in ("<allowed-principal>", "<denied-principal>")
| project TimeGenerated, OperationName, RequesterObjectId, RequesterAudience,
          AuthenticationType, StatusCode, StatusText, ClientRequestId, CorrelationId
```

## 7. Availability and preview ledger

| Capability | Research-date documented state | Planning effect |
| --- | --- | --- |
| Agent 365 commercial availability | GA May 1, 2026. [S4] | Still license- and tenant-admin-gated; do not mark the whole product preview. |
| Entra Agent ID | GA on current release page; portal creation wizard still preview. [S11][S8] | Separate product GA from feature/UI/API maturity and human privileges. |
| Foundry prompt/hosted tracing | GA; external/workflow tracing preview. [S19] | BYO Azure Monitor telemetry is feasible without promising GA Foundry external-agent UX. |
| Foundry A2A | 1.0 GA; 0.3 preview; Foundry targets text-only/no streaming. [S12] | Pin client/server protocol and SDK. |
| Connected Agents | Classic API only, unavailable in new service. [S12] | New spec must choose a supported replacement rather than copy blueprint prose. |
| New Foundry agent endpoint model | Documented available; migration example still preview API/feature header. [S39] | Inspect object/API support; no blanket all-GA claim. |
| Foundry hosted regions | Current list includes East US 2, Sweden Central, West Europe, UK South and many others. [S40] | Region list alone does not establish model capacity, all-tool support, or GA/SLA. |
| Foundry cloud red teaming | Current regions: East US 2, France Central, Sweden Central, Switzerland West, North Central US. [S44] | Separate from hosting region; no universal red-team availability inferred. |
| Foundry MCP | Public/private paths documented; long-running Toolbox MCP tasks preview; .NET SDK preview stated on tool page. [S20] | Prefer bounded read-only tools; pin language packages/features. |
| APIM MCP/A2A | Dedicated how-tos list classic/v2 tiers except Consumption; MCP workspaces unsupported. [S2][S13][S14] | Standalone Developer versus Foundry integrated v2 are different choices. |
| APIM unified model API | Preview explicitly stated in capability overview. [S1] | Not required to govern a single selected model. |
| Defender for AI | GA, commercial text-model coverage. [S23] | No blanket BYO tool/agent/session coverage; subscription activation/cost gate. |
| Purview integrations | Integration-specific scope/licensing; legacy path being deprecated. [S24][S26][S38] | Carry explicit unsupported coverage/user-context gaps instead of a universal DLP claim. |

**Unknown:** Final intersection of model deployment region/type/quota, Agent Service feature version, gateway tier/networking, MCP transport and any evaluations/red-teaming features. No region is selected by this research. Region/preview/license checks must be repeated at implementation time.

## 8. Cost drivers, not a budget decision

**No agreed cap. No resources or paid plans were enabled. No absolute monthly total is defensible until the human chooses runtime, region, SKUs, model, expected turns and retained telemetry.**

| Driver | What creates spend / useful sizing input | Primary evidence |
| --- | --- | --- |
| Model inference | Input/output tokens per participating agent/turn; growing context; retries, collaboration fan-out, embeddings and model-based evaluations. Native prompt/workflow agent execution has no extra compute charge on the pricing page, but model tokens/tools/IQ connections still cost. | [S45][S33] |
| Hosted-agent runtime | Per active-session CPU/memory; session concurrency and idle timeout, not merely four agent definitions. Documented idle timeout 2–60 minutes, default 15; oversized sandbox multiplies concurrent-session cost. | [S40][S45] |
| BYO Container Apps | Consumption vCPU-seconds/GiB-seconds/requests, minimum replicas and idle charges; dedicated profile capacity differs. Free grants are subscription-wide, not a free grant per team/agent. | [S41] |
| APIM | Service tier/units and duration; private networking tier requirement can dominate a short demo. Integrated Foundry new-gateway flow creates Basic v2; its free-tier/eligibility note is not proof this subscription owes zero. Standalone Developer supports native MCP but does not meet the integrated v2 requirement. | [S34][S46] |
| API Center | Free versus Standard plan; feature limits. Free lacks Microsoft support. Do not confuse an API catalog plan with APIM traffic/hosting cost. | [S16] |
| ACR/data/secrets/network | Registry/image storage/builds; synthetic blob capacity and operations; secret-store transactions; private endpoints/DNS/NAT/egress if selected. These are separate resources, not included in a framework license. | [S18][S22][S40] |
| Search/grounding/tools | Azure AI Search capacity, vector storage, paid code interpreter/search/connectors/Fabric/M365 services if selected. None is intrinsically required just to publish a synthetic data MCP tool. | [S17][S45] |
| Observability | Log ingestion GB, retention, diagnostics, optional advanced metrics/alerts; per-hop payload logging can amplify cost and exposure. | [S19][S37][S47] |
| Agent 365 / Entra / Purview | Per-user Agent 365/qualifying M365 entitlement; paired Entra licensing and Purview integration-specific charges. Not “four agents × four seats” by default. | [S4][S10][S25][S38] |
| Defender for AI | Scanned text token volume; trial expiration or cap triggers charges; not automatically included with the inference price or Purview license. | [S23][S43] |

**Recommendation:** Downstream estimate should separate fixed SKU-hours, consumption and monthly SaaS entitlements. Record expected run count, max turns/tokens, session concurrency/idle, log volume/retention, disposable lifetime and cleanup owner. Azure budgets notify but **do not stop consumption**, and costs typically lag 8–24 hours with daily budget evaluation. Request a cap/expiry decision before any deployment, without inventing an agreed amount. Explicit runtime limits/teardown are operational controls, not a financial hard-cap guarantee. [S48]

**Recommendation:** Cleanup must enumerate independent UAMIs, role assignments, Agent ID/blueprint lifecycle, APIM subscriptions, published endpoints, images, data and telemetry. RG deletion is not proof that every tenant object or retained log was removed; verify provider-managed identity lifecycle and preserve selected evidence before destruction. [S7][S31][S6][S39]

## 9. Inputs required for an implementation-ready downstream spec

1. **Layer fidelity decision:** Is resource-level partial L3/L4 with explicit gaps acceptable? If not, record incompatibility with no elevated Entra privileges; do not quietly add a tenant admin.
2. **Effective permission inventory:** Authorized RG creation/provisioning scope; provider registration; explicit scoped role-assignment authority; Foundry development/connection roles; existing Defender enablement and subscription scope; available M365/Entra/Purview entitlements. Operator-only access must be separated from workload rights.
3. **Runtime/API decision:** Prompt, hosted, BYO, or mixed; new versus classic Foundry object model; per-agent or per-team runtime authority; four concrete agent responsibilities. Do not count four prompts sharing one authority as proof of four isolated agents.
4. **Collaboration contract:** Native calls versus A2A/workflows; timeout/turn/retry budget; caller/target permissions; exact permitted cross-team exchange and a denied exchange.
5. **MCP contract:** Synthetic read-only datasets, tool schemas, allowed-caller matrix, gateway subscription/token choice, token audiences and credentials; backend identity/anti-bypass enforcement. If a custom OAuth audience is needed, establish whether existing app ownership/tenant policy permits it without elevation.
6. **Resource ownership/topology decision:** Three actual team RGs; where shared platform resources live; which resource/project/agent/network scopes genuinely enforce boundaries. No extra human personas are required.
7. **Region/SKU/maturity decision:** Intersect runtime/model/tool availability and quota; integrated v2 gateway versus standalone APIM; private networking requirements; acceptable preview dependencies and unsupported features.
8. **Evidence and disposal plan:** Required allowed/denied tests, identities/log destinations/correlation, safe fixtures, lifecycle/revocation checks, cleanup verification and retention.
9. **Cost decision:** Region/model/SKU, run/lifetime/telemetry assumptions, budget cap if any, alerting and teardown owner. No amount selected by this ticket.

Remaining factual uncertainty is recorded above. The next planning work may narrow these alternatives; this research does not authorize creating agents, allocating resources, purchasing licenses, or changing tenant policy.

## Primary-source register

All sources accessed 2026-10-14. Microsoft Learn links are live documents; `ms.date`/`updated_at` and doc source commits were inspected on key pages. Blueprint links are immutable. Particularly decision-sensitive snapshots: Foundry RBAC updated 2026-09-22 (`aa8dac9af5c360ba3d338f4fe7ad04e794d98ea5`); new agent-model migration updated 2026-09-25 (`2188d69cdd9f9aeb42f4515667e5933fc21259e7`); Agent 365 service description updated 2026-10-01 (`2a40db841a771b2839d0c2304ec0b8c781c8882d`); Entra CA updated 2026-10-07 (`e0e0ef0e6ecb4ceaed065f6afdb05d037d2f60b5`). Public docs and upstream architectural prose were compared; the blueprint's internal Agent 365 field FAQ was not available and is not treated as licensing authority.

[B0]: https://github.com/Azure-Samples/foundry-citadel-platform/blob/89d3d70b13aada1972d2e280e00e5aa49a85ad97/README.md "Pinned Citadel overview and four layers"
[B1]: https://github.com/Azure-Samples/foundry-citadel-platform/commit/89d3d70b13aada1972d2e280e00e5aa49a85ad97 "Upstream revision"
[B2]: https://github.com/Azure-Samples/foundry-citadel-platform/blob/89d3d70b13aada1972d2e280e00e5aa49a85ad97/layer-1-governance-hub.md "Pinned L1"
[B3]: https://github.com/Azure-Samples/foundry-citadel-platform/blob/89d3d70b13aada1972d2e280e00e5aa49a85ad97/layer-2-agent-operations.md "Pinned L2"
[B4]: https://github.com/Azure-Samples/foundry-citadel-platform/blob/89d3d70b13aada1972d2e280e00e5aa49a85ad97/layer-3-agent-management.md "Pinned L3"
[B5]: https://github.com/Azure-Samples/foundry-citadel-platform/blob/89d3d70b13aada1972d2e280e00e5aa49a85ad97/layer-4-security-foundation.md "Pinned L4"
[S1]: https://learn.microsoft.com/en-us/azure/api-management/genai-gateway-capabilities "AI gateway capabilities and unified-model preview"
[S2]: https://learn.microsoft.com/en-us/azure/api-management/mcp-server-overview "MCP gateway overview, tiers and limitations"
[S3]: https://learn.microsoft.com/en-us/azure/foundry/concepts/rbac-foundry "Foundry roles, planes, scopes and rename"
[S4]: https://learn.microsoft.com/en-us/microsoft-agent-365/overview "Agent 365 GA date and licensing overview"
[S5]: https://learn.microsoft.com/en-us/microsoft-365/admin/manage/agent-roles-perms "Agent management tenant roles"
[S6]: https://learn.microsoft.com/en-us/azure/foundry/agents/concepts/agent-identity "Foundry-managed Agent ID, project/runtime identity"
[S7]: https://learn.microsoft.com/en-us/azure/container-apps/managed-identity "Container Apps managed identities and lifecycle"
[S8]: https://learn.microsoft.com/en-us/entra/agent-id/create-blueprint "Blueprint roles, Graph permissions, consent and wizard preview"
[S9]: https://learn.microsoft.com/en-us/entra/agent-id/agent-id-creation-channels "Product-managed creation versus custom creation"
[S10]: https://learn.microsoft.com/en-us/office365/servicedescriptions/microsoft-agent-365/microsoft-agent-365 "Current Agent 365 plans and capability entitlements"
[S11]: https://learn.microsoft.com/en-us/entra/agent-id/whats-new-agent-id "Agent ID GA and feature-level previews"
[S12]: https://learn.microsoft.com/en-us/azure/foundry/agents/how-to/tools/agent-to-agent "A2A 1.0 GA, 0.3 preview, permissions, limits, Connected Agents replacement"
[S13]: https://learn.microsoft.com/en-us/azure/api-management/agent-to-agent-api "APIM A2A JSON-RPC, agent-card rewriting and limits"
[S14]: https://learn.microsoft.com/en-us/azure/api-management/expose-existing-mcp-server "External MCP version, transport, scope and streaming caveats"
[S15]: https://learn.microsoft.com/en-us/azure/api-center/register-discover-mcp-server "MCP registration and discovery"
[S16]: https://learn.microsoft.com/en-us/azure/api-center/overview "Design-time governance and Free/Standard plans"
[S17]: https://learn.microsoft.com/en-us/azure/foundry/agents/overview "Agent runtime types and Toolbox capabilities"
[S18]: https://learn.microsoft.com/en-us/azure/foundry/agents/concepts/hosted-agent-permissions "Hosted-agent resource and identity permission reference"
[S19]: https://learn.microsoft.com/en-us/azure/foundry/observability/concepts/trace-agent-concept "Tracing GA/preview distinction and log access"
[S20]: https://learn.microsoft.com/en-us/azure/foundry/agents/how-to/tools/model-context-protocol "MCP setup, approvals, private networking, Toolbox and previews"
[S21]: https://learn.microsoft.com/en-us/azure/foundry/control-plane/register-custom-agent "Foundry external-agent registration prerequisites and gateway path"
[S22]: https://learn.microsoft.com/en-us/azure/storage/blobs/assign-azure-role-data-access "Blob data roles and container scopes"
[S23]: https://learn.microsoft.com/en-us/azure/defender-for-cloud/ai-threat-protection "Defender GA, coverage, roles and trial"
[S24]: https://learn.microsoft.com/en-us/azure/defender-for-cloud/ai-onboarding "Subscription-plan activation, Purview restrictions and new route"
[S25]: https://learn.microsoft.com/en-us/entra/identity/conditional-access/agent-id "Agent CA licensing, subjects and audiences"
[S26]: https://learn.microsoft.com/en-us/azure/foundry/control-plane/how-to-manage-compliance-security "RG policy rights, Defender and newer Purview configuration"
[S27]: https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-autonomous-agents "CA Administrator and risk-based licensing prerequisites"
[S28]: https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-cli "Role-assignment prerequisites and avoiding Graph lookup"
[S29]: https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/resource-providers-and-types "Provider registration action and Entra provider apps"
[S30]: https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/identity "Managed Identity Contributor/Operator role actions"
[S31]: https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/manage-user-assigned-managed-identities-azure-portal "UAMI resource creation, lifecycle and rights"
[S32]: https://learn.microsoft.com/en-us/azure/foundry/agents/how-to/mcp-authentication "MCP credential alternatives, shared keys, custom OAuth audience restrictions"
[S33]: https://learn.microsoft.com/en-us/azure/ai-services/openai/how-to/role-based-access-control "Direct OpenAI inference versus management roles"
[S34]: https://learn.microsoft.com/en-us/azure/foundry/configuration/enable-ai-api-management-gateway-portal "Integrated gateway v2 prerequisites, networking, verification and limits"
[S35]: https://learn.microsoft.com/en-us/azure/api-management/authentication-managed-identity-policy "Outbound MI tokens, audiences and policy-editor authority"
[S36]: https://learn.microsoft.com/en-us/azure/storage/blobs/monitor-blob-storage-reference "Blob monitoring and diagnostic categories"
[S37]: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/storagebloblogs "Actual Log Analytics principal/status/correlation schema"
[S38]: https://learn.microsoft.com/en-us/purview/ai-agent-365 "Purview supported Agent 365 interactions and label-inheritance limits"
[S39]: https://learn.microsoft.com/en-us/azure/foundry/agents/how-to/migrate-agent-applications "New agent identity/endpoint model and transition"
[S40]: https://learn.microsoft.com/en-us/azure/foundry/agents/concepts/hosted-agents "Hosted runtime, identities, session billing, networking and regions"
[S41]: https://azure.microsoft.com/en-us/pricing/details/container-apps/ "Container Apps consumption/dedicated pricing drivers and shared grants"
[S42]: https://learn.microsoft.com/en-us/entra/agent-id/what-is-microsoft-entra-agent-id "Agent ID availability and relationship to Agent 365"
[S43]: https://azure.microsoft.com/en-us/pricing/details/defender-for-cloud/ "Defender token-based pricing and trial limits"
[S44]: https://learn.microsoft.com/en-us/azure/foundry/concepts/ai-red-teaming-agent "Cloud red-team regional availability"
[S45]: https://azure.microsoft.com/en-us/pricing/details/foundry-agent-service/ "Native agent, hosted runtime, model and tool pricing"
[S46]: https://azure.microsoft.com/en-us/pricing/details/api-management/ "APIM service tier pricing"
[S47]: https://azure.microsoft.com/en-us/pricing/details/monitor/ "Telemetry ingestion and retention pricing"
[S48]: https://learn.microsoft.com/en-us/azure/cost-management-billing/costs/tutorial-acm-create-budgets "Budgets are alerts, not consumption stops"
[S49]: https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/privileged "Azure Owner, Contributor, RBAC Administrator and User Access Administrator definitions"
