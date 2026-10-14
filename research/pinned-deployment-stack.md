# Pinned deployment stack: documentary compatibility

Research for [Wayfinder child #12](https://github.com/JoranBergfeld/citadel-example/issues/12), 2026-10-14. Planning only: no Azure sign-in, subscription inspection, deployment, secret retrieval, package installation, or integration test occurred.

## Result and publication status

**A coherent, source-backed candidate exists, not a verified deployment bundle.** Use the Microsoft Agent Framework release's own Python lock as the starting point, not independently selected latest packages. West Europe documents regional Standard `gpt-4.1-mini` version `2025-04-14`; APIM Basic v2 supports the needed public-origin gateway pattern, token policies, certificates and HTTP streaming. Five Container Apps, Azure storage, Key Vault and API Center remain as agreed. Details below distinguish upstream dependency evidence, proposed configuration and untested composition.

**Publication base resolved by explicit follow-up authorization.** Local `main` remains unborn, but the repository is not empty: its remote default is `research/citadel-open-datasets` at `d662e86d84fd1d518a37df0865d4b1c4b966de80`. The coordinator authorized fetching that exact existing branch and creating `research/pinned-deployment-stack` from that commit in a separate session-files worktree. The existing `research/citadel-open-datasets.md` is preserved; only this research artifact belongs in the new commit. User files and unborn main remain untouched. Publication is research-branch-only, without a PR or merge; the parent owns issue closure and map updates.

The established remote convention is `research/*.md`, evidenced by the [previous immutable gateway study](https://github.com/JoranBergfeld/citadel-example/blob/bf9a0a68984b58c9d5f76e0906e0536f5391317c/research/gateway-only-container-apps.md). Intended published path: `research/pinned-deployment-stack.md`.

## Authoritative boundaries

- [#6 runtime resolution](https://github.com/JoranBergfeld/citadel-example/issues/6#issuecomment-6166769167): four separate Microsoft Agent Framework agents and one real read-only MCP server, separate workload identities; APIM on all agent/tool/model network paths; public HTTPS origins acceptable with gateway certificate authorization; only APIM has model inference authority.
- [#10 evidence resolution](https://github.com/JoranBergfeld/citadel-example/issues/10#issuecomment-6169237188): immutable evidence versions, exact draft hashes, bounded tools, deterministic release authority, separately authorized findings/status reads and ambiguous-timeout reconciliation. The four-complete-candidate fixture precondition remains unverified.
- [#11 certificate resolution](https://github.com/JoranBergfeld/citadel-example/issues/11#issuecomment-6165831454): ingress certificate presence is not certificate authorization; the documented composition still requires negative-case testing.
- Human-selected Bicep + azd, local-first deployment, optional CI, disposable teardown, exact source/configuration/container pins; no spending ceiling. An EU region alternate requires explicit human approval. These constraints are inputs, not choices made by this research.

## 1. Package, source and container matrix

### Follow-up: current agreed limits and request-lifecycle incompatibility

The coordinator subsequently supplied these **agreed limits**, which supersede the earlier numerical recommendations in section 7:

| Scope | Agreed cap |
| --- | --- |
| Overall logical run | 15 minutes / 900 seconds |
| Agent executions | 42 total: Planner + 20 Assessor/Reviewer pairs + Briefing Author |
| Model attempts | 128/run and 8/agent execution |
| Model tokens | 16k input + 2k output/call; 1 million combined input/output tokens/run |
| Model timeout | 60 seconds/call |
| Safe read timeout | 30 seconds/attempt |
| A2A request timeout | 180 seconds/request |
| Safe tool/status attempts | 512/run, including at most two retries per safe logical read |

Keep the supplied `16k`/`2k` notation until configuration explicitly chooses decimal versus binary units; do not silently treat the earlier 16,384/2,048 proposal as agreed.

**Verified lifecycle matrix:**

| Boundary | Primary evidence | Consequence |
| --- | --- | --- |
| ACA HTTP ingress | [Ingress overview](https://learn.microsoft.com/en-us/azure/container-apps/ingress-overview): “Request time out is 240 seconds.” | A 900-second synchronous Planner request is unsupported by this documented limit. |
| APIM forwarding | [forward-request](https://learn.microsoft.com/en-us/azure/api-management/forward-request-policy): `timeout` waits for **response headers**; values above 240 seconds may not be honored because idle connections can be dropped. | It is not a total application-operation timer. `timeout=900` is not a solution. |
| Agreed A2A request cap | 180 seconds, supplied by coordinator | Applies to the initial Planner request too unless explicitly exempted; it is already stricter than ACA's 240 seconds. |
| A2A 1.0 blocking request | [SendMessageConfiguration](https://a2a-protocol.org/v1.0.0/specification/): `returnImmediately=false` or unset waits for a terminal or interrupted task state. | Cannot return a still-working task merely to evade the timeout while retaining default blocking semantics. Do not fabricate `INPUT_REQUIRED` to yield. |
| A2A 1.0 nonblocking request | Same specification: `returnImmediately=true` returns after creating a task; caller subsequently polls Get Task, subscribes, or uses push. | Protocol-supported request/operation separation, but continuing processing after the response is a lifecycle choice. It does not establish compliance with #6's “no background delegation,” durability, or restart fencing. |
| Streaming | [APIM SSE guidance](https://learn.microsoft.com/en-us/azure/api-management/how-to-server-sent-events) requires unbuffered delivery and idle keepalive. A2A says `returnImmediately` does not affect streaming operations. | Heartbeats address idle behavior, not proof of a 900-second ACA request or compliance with the agreed 180-second request maximum. |

**Faithful strict-request/reply interpretation:** keep the 900-second logical deadline as an outer ceiling, not a promise that a request may occupy 900 seconds. For each request, use an absolute deadline no later than `min(run deadline, parent request deadline, request start + 180 seconds)`. Reserve response/cleanup time inside that limit (for example five seconds); individual model/read timeouts are `min(60 or 30 seconds, remaining work time)`. Nested Assessor and Reviewer calls do not restart the ancestor's clock. Enforce total request time in application code/client cancellation, not only APIM's header timer or an HTTP client's per-read inactivity timeout.

Under that strict interpretation, the root Planner's processing must finish, fail or be fenced from further commits before its request budget expires; it cannot use the rest of the 15 minutes for continuing agent work after returning without a separately approved lifecycle. The outer run deadline can still bound status reconciliation/CLI handling after an ambiguous failure. Status reads report durable state; they must not implicitly resume the Planner or consume a new agent execution.

On timeout/disconnect, do not assume the remote operation was canceled or that a missing status record means it never ran. Preserve #10's indeterminate/reconciliation contract; only established `failed_no_commit` with late execution fenced permits explicit retry. The platform timeout itself is not evidence of rollback.

**Known unresolved incompatibility:** a Planner operation that actually needs 15 minutes, a universal 180-second A2A request cap, and strictly request-bound execution cannot all hold simultaneously in one root invocation. Standard nonblocking A2A can separate request and task lifetimes without requiring a broker, but the human/parent must explicitly permit the post-response execution mechanism and reconcile it with #6 before adoption. No such permission is inferred here. No source-backed, already-approved continuation mechanism was established.

The count/token/time limits are intersecting ceilings, not simultaneous entitlements. Eight model attempts for each of 42 executions would be 336, so the 128 global cap wins. If `k` means decimal, 128 calls at 18,000 tokens total would be 2.304 million tokens, so the 1-million run cap can stop the run much earlier. Twenty sequential candidate invocations at their individual maximum likewise cannot be promised inside 900 seconds, much less one 180-second root request.

The earlier documentary read-count envelope is still useful: 121 Reference Data reads + 23 findings reads = 144 logical reads; three attempts each use 432 of the 512 safe tool/status attempts, leaving at most 80 attempts for additional counted status/discovery/reconciliation traffic. Count attempts, not just successes; hidden SDK retries must not bypass any guard. Actual model input sizes, service latency and fixture viability remain untested.

### Strongest available documentary baseline

The immutable [Microsoft Agent Framework `python-1.21.0` lock](https://github.com/microsoft/agent-framework/blob/91ab44faa4824a30247d00c341f3498ba46b1ca3/python/uv.lock) contains the following versions together. Its workspace Python constraint is `>=3.11,<3.15`. The release was published 2026-10-08. This is **upstream lock co-occurrence**, stronger than intersecting dependency ranges but weaker than running this application's dependencies or gateway flow. The workspace uses editable Framework packages, includes unrelated integrations/dev dependencies, and is not a minimal deployable application lock.

| Layer | Candidate exact version | Evidence and qualification |
| --- | --- | --- |
| Python | CPython `3.12.15`, Linux amd64 | Within upstream lock range. Official image evidence below; not executed here. |
| Framework core | `agent-framework-core==1.21.0` | Upstream lock and [published metadata](https://pypi.org/pypi/agent-framework-core/1.21.0/json); Python >=3.10. |
| Framework OpenAI adapter | `agent-framework-openai==1.16.0` | Lock and [metadata](https://pypi.org/pypi/agent-framework-openai/1.16.0/json): core >=1.20,<2; OpenAI >=2.25,<4. |
| Framework A2A adapter | `agent-framework-a2a==1.0.0b261002` | Lock and [metadata](https://pypi.org/pypi/agent-framework-a2a/1.0.0b261002/json): core >=1.19,<2; A2A SDK >=1,<2. **Beta** adapter; human acceptance is still needed for this candidate. |
| Official A2A | `a2a-sdk[fastapi]==1.2.1` | Lock package version; [release source](https://github.com/a2aproject/a2a-python/tree/041c17bbe8d5ced7a8f6c48761152ce01ffbfc14) and [metadata](https://pypi.org/pypi/a2a-sdk/1.2.1/json). FastAPI extra explicitly supports server integration; application must select/lock that extra. |
| Official MCP | `mcp==1.30.0` | Lock and [source](https://github.com/modelcontextprotocol/python-sdk/tree/8c2fa6eabacde869d75568e33b9d466b58c2f512). Core's `all` extra requires MCP >=1.24,<2. Do not choose published latest MCP 2.3.0: it violates that declared range. Avoid installing the enormous Framework `all` extra merely to obtain MCP. |
| OpenAI client | `openai==3.23.0` | Lock and [metadata](https://pypi.org/pypi/openai/3.23.0/json), not independently selected latest 3.31.0. |
| HTTP application | `fastapi==0.141.1`, `starlette==1.7.0`, `uvicorn==0.54.0` | Co-occurring upstream lock; [FastAPI metadata](https://pypi.org/pypi/fastapi/0.141.1/json). ASGI lifecycle/mount behavior remains an application test, not something the metadata proves. |
| Shared dependencies | `pydantic==2.13.5`, `anyio==4.15.1`, `sse-starlette==3.5.0` | Upstream lock; Pydantic satisfies MCP >=2.11,<3 and A2A >=2.11.3. Lock all remaining transitives, not only this table. |
| Distinct HTTP clients | `httpx==0.28.1`, `httpx2==2.13.1` | Both occur in upstream lock. A2A/MCP use HTTPX; OpenAI 3.23 uses HTTPX2. They are distinct packages: do not inject a client from one library into the other merely because their names resemble each other. |
| Azure managed identity | `azure-identity==1.26.0`, `azure-core==1.41.0` | Both upstream-locked; [identity metadata](https://pypi.org/pypi/azure-identity/1.26.0/json). Production uses explicit assigned `ManagedIdentityCredential`, not operator fallback. |
| Azure Blob | `azure-storage-blob==12.31.0` | Upstream lock and [metadata](https://pypi.org/pypi/azure-storage-blob/12.31.0/json), azure-core >=1.37. |
| Async Azure transport | `aiohttp==3.14.3` | Upstream lock. Include explicitly if asynchronous Azure SDK clients are chosen; async transport does not follow merely from importing the SDK. |
| Key Vault secrets | `azure-keyvault-secrets==4.11.3` | **Addition outside that upstream lock**, [metadata](https://pypi.org/pypi/azure-keyvault-secrets/4.11.3/json): azure-core >=1.31, isodate >=0.6.1, typing-extensions >=4.6. Its ranges fit the candidate; combined resolution/imports remain untested. Agents retrieve assigned subscription secrets, not certificates' private keys. |

No separate `azure-ai-openai` or Foundry-hosted Agent Service SDK is required for this proposed direct Azure OpenAI inference topology. Use the official OpenAI adapter/client with an explicit APIM base URL. The [versioned Framework adapter source](https://github.com/microsoft/agent-framework/blob/91ab44faa4824a30247d00c341f3498ba46b1ca3/python/packages/openai/agent_framework_openai/_chat_client.py) uses the official OpenAI clients. Passing the per-agent subscription credential and preventing endpoint fallback must be tested; use of a Framework Azure helper must not silently restore a direct model URL or developer credential chain.

**Beta adapter: supported versus assumed.** The [exact-release A2A README](https://github.com/microsoft/agent-framework/blob/91ab44faa4824a30247d00c341f3498ba46b1ca3/python/packages/a2a/README.md) documents both `A2AAgent` (remote client wrapper) and `A2AExecutor` (hosting bridge), with an official `A2AStarletteApplication` and `DefaultRequestHandler` example. Therefore client and hosting bridges are documented, not invented. The example's `InMemoryTaskStore` is not sufficient evidence for durable #10 operations or restart/reconciliation behavior. The README explicitly says hosting adds no authentication/authorization and task/session IDs are not credentials. Its client drops response-cookie persistence by default; an explicitly supplied `httpx.AsyncClient` is caller-owned and can retain cookies, so isolate it by security context. A2A SDK 1.2.1 separately documents protocol 1.0 JSON-RPC support. What remains assumed/unverified is their complete mounted FastAPI application with APIM keys, certificate middleware, task ownership, durable state, deadlines, gateway cards and negative cases. Upstream lock co-occurrence is not an integration test or stability guarantee for the beta adapter.

Published wheel SHA-256 values, read from each version-specific PyPI JSON endpoint, all non-yanked at retrieval:

| Distribution | Wheel SHA-256 |
| --- | --- |
| `agent_framework_core-1.21.0-py3-none-any.whl` | `ef333ff8348375b7d0757e690b1bd2ac3a1da67afc5cfacf6ce8db7da93bc423` |
| `agent_framework_openai-1.16.0-py3-none-any.whl` | `93790e61f8ee0104db56d2998bd03924c844600046b16efc26ed5df7fe1bee7f` |
| `agent_framework_a2a-1.0.0b261002-py3-none-any.whl` | `f91d2c6da8dd4645876dd893b8bf0296ccceb2c0ff9d474604b56b1034d6ebeb` |
| `azure_keyvault_secrets-4.11.3-py3-none-any.whl` | `c77cc80f33d07e1b8cbbda5e7b6b8a1da1471ca917796f9895603a0c2b5f9c2f` |

The upstream lock supplies registry artifact hashes for its other entries. These four values are not a complete dependency lock or a claim that wheels were downloaded/executed.

### Container and toolchain pins

The [Docker Official Images Python manifest](https://github.com/docker-library/official-images/blob/0d4d083562035d03141ef0acd006ef5a2df438b4/library/python) lists `3.12.15-slim-bookworm`, directory `3.12/slim-bookworm`, build-source Git commit `2a3b794c223ab067d122719541cdd54a068732a5`.

The public Docker registry manifest response for `library/python:3.12.15-slim-bookworm` gave:

- OCI index: `sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258` (response-body SHA-256 independently matched).
- Linux amd64 child manifest: `sha256:2ed6491b93cd49272ee6de2b5a38440c3448360322c089fc23e370722d74179d`.
- Candidate build base: `docker.io/library/python:3.12.15-slim-bookworm@sha256:2ed6491b93cd49272ee6de2b5a38440c3448360322c089fc23e370722d74179d`, with platform explicitly Linux amd64.

Registry evidence endpoint: `https://registry-1.docker.io/v2/library/python/manifests/3.12.15-slim-bookworm` (public pull-token exchange required). No image was pulled or built. A tag alone is not immutable. Final application/fixture image digests cannot exist until those images are built; do not invent them.

Observed official release candidates: [azd 1.35.1](https://github.com/Azure/azure-dev/releases/tag/azure-dev-cli_1.35.1), [Bicep 0.48.1](https://github.com/Azure/bicep/releases/tag/v0.48.1), [Azure CLI 2.91.0](https://github.com/Azure/azure-cli/releases/tag/azure-cli-2.91.0). These are individually verified releases, **not a tested toolchain combination**. Provisioning must record binary/download hashes, Bicep executable actually selected by azd, any CLI extension versions and the dependency-lock tool version. No tooling was installed.

## 2. Protocol, API and region contract

| Boundary | Candidate pin/configuration | Documentary support / limitation |
| --- | --- | --- |
| Agent collaboration | A2A specification `1.0.0`, JSON-RPC 2.0 binding; SDK 1.2.1; bounded request/reply | The [SDK compatibility table](https://github.com/a2aproject/a2a-python/blob/041c17bbe8d5ced7a8f6c48761152ce01ffbfc14/README.md#-compatibility) explicitly supports 1.0 JSON-RPC clients and servers. [Versioned spec](https://a2a-protocol.org/v1.0.0/specification/) is authoritative. Do not confuse SDK 1.2.1 with protocol 1.2.1, or silently negotiate 0.3 compatibility mode. |
| Reference tools | MCP `2025-11-25`, Streamable HTTP | Versioned [SDK types](https://github.com/modelcontextprotocol/python-sdk/blob/8c2fa6eabacde869d75568e33b9d466b58c2f512/src/mcp/types.py) name this protocol. [Transport spec](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) requires POST handling, JSON/SSE response support and protocol negotiation. It is not the obsolete separate HTTP+SSE transport. |
| Model interface | Azure OpenAI GA `/openai/v1/chat/completions`; explicit APIM frontend equivalent; no preview headers | The [v1 API documentation](https://learn.microsoft.com/en-us/azure/foundry/openai/api-version-lifecycle) supports the ordinary OpenAI client and removes required dated `api-version`. Pin the v1 path and accepted request shape; hosted v1 behavior is not frozen by a client pin. Model parameter is the fixed deployment name. |
| Model | `gpt-4.1-mini`, model version `2025-04-14`, deployment SKU `Standard`, resource location `westeurope` | [Model capability table](https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-sold-directly-by-azure) documents Chat Completions, tools/function calling and structured outputs. [Availability table](https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-sold-directly-by-azure-region-availability), **Standard/Regional**, marks West Europe supported. |
| Residency | Regional Standard, not Global Standard and not silently Data Zone Standard | The availability page distinguishes regional processing from EU-zone and worldwide processing. A resource located in West Europe with a Global SKU is not equivalent to West Europe inference. Sweden Central also lists this regional model, but is only an evidence-backed alternate requiring explicit human approval. |
| Model upgrade | `versionUpgradeOption: NoAutoUpgrade`; record exact model version | Supported by the [deployment ARM schema](https://learn.microsoft.com/en-us/azure/templates/microsoft.cognitiveservices/2024-10-01/accounts/deployments). Does not defeat retirement. The retrieved [retirement page](https://learn.microsoft.com/en-us/azure/foundry/openai/concepts/model-retirements) has a `gpt-4.1-mini` row under **Fine-tuned models**, with training/deployment retirement dates: those dates must not be presented as this base model's guaranteed availability. A definitive base-model retirement date was not established; recheck the applicable lifecycle before deployment. |
| Model authority | `disableLocalAuth: true`; only APIM MI has runtime model role | [Account schema](https://learn.microsoft.com/en-us/azure/templates/microsoft.cognitiveservices/2024-10-01/accounts), [APIM managed-identity policy](https://learn.microsoft.com/en-us/azure/api-management/authentication-managed-identity-policy), and [OpenAI role definition](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/ai-machine-learning#cognitive-services-openai-user). APIM replaces frontend auth with its own backend bearer token. |

For APIM's model backend, the [backend documentation](https://learn.microsoft.com/en-us/azure/api-management/backends#configure-managed-identity-for-authorization-credentials) explicitly gives audience/resource `https://cognitiveservices.azure.com`. Use that APIM-documented configuration; the generic v1 SDK page also shows `https://ai.azure.com/.default` for direct token-provider examples. These examples are not an instruction to give agents direct model identities or to append `/.default` to an APIM policy resource. The selected v1 route/audience/role combination still needs an actual authorized request and negative direct-origin tests.

### ASGI and HTTP handling

Mount the real A2A and MCP ASGI handlers; framework execution alone does not make an HTTP route protocol-compliant. Lifespans, `initialize`, tool discovery/calls, task identifiers and exact gateway discovery URLs must be tested. Choose synchronous/non-streamed model and A2A responses initially where supported by the bounded workflow; MCP clients still must accept either JSON or SSE according to the negotiated transport.

For MCP, preserve `Accept`, `Content-Type`, `MCP-Protocol-Version`, and `MCP-Session-Id` when used; authorize every request, not just initialization. Explicitly choose/test session mode: a stateless, JSON-response server is a candidate for these read-only tools, but it still performs MCP initialization and must follow transport semantics. GET may return 405 if no server-to-client SSE stream is offered. If sessions/resumption are enabled, preserve `Last-Event-ID` and handle session termination; no cross-caller session reuse. Validate Origin when supplied. These requirements follow the [transport specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports), not a claim about this unbuilt server.

Use ordinary APIM HTTP APIs/pass-through operations for the pinned JSON-RPC/MCP routes if needed. **Do not claim native APIM import validates A2A 1.0 or custom subscription authentication.** The [native external MCP feature](https://learn.microsoft.com/en-us/azure/api-management/expose-existing-mcp-server) documents MCP >=2025-06-18 and Streamable HTTP, but its authorization limitations reference MCP authorization standards. The agreed subscription-key plus backend-certificate composition is not proof of standardized OAuth interoperability. Preserve the agreed private-client boundary rather than silently adding an Entra app registration. If native MCP onboarding cannot express it, HTTP pass-through plus API Center inventory is the proposed path, with end-to-end proof outstanding.

## 3. Azure configuration matrix

| Resource | Candidate configuration | Source / qualification |
| --- | --- | --- |
| API Management | One `BasicV2` unit, West Europe; default public TLS hostname, separate subscription credentials per agent and operator | [v2 overview](https://learn.microsoft.com/en-us/azure/api-management/v2-service-tiers-overview), [region table](https://learn.microsoft.com/en-us/azure/api-management/api-management-region-availability). Basic v2 is suitable for dev/test and sufficient for public origins. Standard v2 is an optional networking upgrade, not a requirement here. No Premium v2 availability is claimed in West Europe. |
| APIM token controls | Model-operation scoped `llm-token-limit`, counter keyed to validated subscription/caller mapping; explicit rate/quota values belong to #7 | [Policy reference](https://learn.microsoft.com/en-us/azure/api-management/llm-token-limit-policy) supports Basic v2 and OpenAI Chat Completions/Responses. 429 rate / 403 quota responses; counting can be approximate. Token limits are workflow safety controls, not an invented financial budget. |
| APIM HTTP transport | No response caching/body buffering on protocol streams; `forward-request buffer-response="false"`; no prompt, response-body or credential logging | [SSE guidance](https://learn.microsoft.com/en-us/azure/api-management/how-to-server-sent-events). Consumption is unsuitable for these long-running connections and omitted from the token-policy tier list. SSE idle traffic must occur within four minutes; this does not waive ACA's request timeout. |
| APIM backend certificates | Named APIM certificate object backed by Key Vault; authorize HTTPS backend with it; keep backend server-name/chain verification enabled | [Backend configuration](https://learn.microsoft.com/en-us/azure/api-management/backends), [certificate integration](https://learn.microsoft.com/en-us/azure/api-management/api-management-howto-mutual-certificates). Client authentication is distinct from validation of ACA's server certificate. No need to disable server verification for a self-signed client credential. |
| Container Apps | Five separate applications/identities; Consumption workload profile; external HTTPS ingress, `allowInsecure: false`, `clientCertificateMode: require`; no extra exposed app port | [ACA certificate guide](https://learn.microsoft.com/en-us/azure/container-apps/client-certificate-authorization), [ingress reference](https://learn.microsoft.com/en-us/azure/container-apps/ingress-overview). Numeric resources/replicas below are pricing assumptions, not a measured sizing result. |
| Backend authorization | Verify exact permitted gateway certificate/validity and trusted caller mapping before A2A, MCP or findings/status logic | ACA overwrites incoming `X-Forwarded-Client-Cert`, whose `Hash` is SHA-256. Certificate presence alone is insufficient. Reject malformed/ambiguous certificate metadata, unrelated/expired certificates and missing caller context. These are implementation obligations from #11, not a platform allowlist feature. |
| Storage | Team-owned GPv2 Hot LRS Blob storage; explicit container-scoped data roles; immutable version naming/hash and conditional writes | [Blob role scoping](https://learn.microsoft.com/en-us/azure/storage/blobs/assign-azure-role-data-access); #10 supplies application immutability/reconciliation semantics. LRS does not itself enforce draft or release immutability. No SAS/account-key runtime fallback. |
| Key Vault | Standard, RBAC authorization; allocated workload secrets; gateway certificate material isolated from agent-readable scopes | [Certificate model](https://learn.microsoft.com/en-us/azure/key-vault/certificates/about-certificates), [RBAC roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/security). No HSM needed for exportable gateway TLS client key. |
| Inventory | API Center Free plan candidate for small inventory | [Overview](https://learn.microsoft.com/en-us/azure/api-center/overview). Inventory is design-time governance, not runtime authorization. Validate limits/region before provisioning; Basic v2 does not qualify for the no-extra-cost Standard-plan benefit listed for Standard/Premium APIM. |
| Registry and telemetry | One Basic ACR; workspace-based application telemetry/Log Analytics; correlation metadata only | Pricing assumption; preserve #6/#8 observable routes. No additional broker, search index, Foundry-hosted agent service, private endpoint or dedicated environment profile assumed. |

Stable resource API candidates directly checked for relevant properties:

- `Microsoft.App/containerApps@2025-01-01` — `clientCertificateMode`.
- `Microsoft.ApiManagement/service@2024-05-01` — `BasicV2`; `service/certificates@2024-05-01` — Key Vault `secretIdentifier`.
- `Microsoft.CognitiveServices/accounts@2024-10-01` — `disableLocalAuth`; `accounts/deployments@2024-10-01` — model version and `NoAutoUpgrade`.
- `Microsoft.KeyVault/vaults@2023-07-01` — `enableRbacAuthorization`.

Sources: [ACA schema](https://learn.microsoft.com/en-us/azure/templates/microsoft.app/2025-01-01/containerapps), [APIM schema](https://learn.microsoft.com/en-us/azure/templates/microsoft.apimanagement/2024-05-01/service), [certificate schema](https://learn.microsoft.com/en-us/azure/templates/microsoft.apimanagement/2024-05-01/service/certificates), [model account](https://learn.microsoft.com/en-us/azure/templates/microsoft.cognitiveservices/2024-10-01/accounts), [model deployment](https://learn.microsoft.com/en-us/azure/templates/microsoft.cognitiveservices/2024-10-01/accounts/deployments), [vault](https://learn.microsoft.com/en-us/azure/templates/microsoft.keyvault/2023-07-01/vaults).

This is not an ARM/Bicep schema for every resource: storage, ACR, environments, identities, role assignments, inventory and diagnostic resources must also have explicit API versions in the eventual specification. No Bicep compilation or resource-provider validation was performed.

## 4. Credentials, certificates and teardown

1. **Private key location.** Key Vault certificates create a certificate, key and secret with the same name. APIM needs an exportable PFX/private key; public certificate metadata or a non-exportable HSM key is insufficient. Select an exportable software key and client-auth usage; only APIM and the authorized lifecycle operator may retrieve its private material. Agents receive only public validation material. [Certificate composition/exportability](https://learn.microsoft.com/en-us/azure/key-vault/certificates/about-certificates).
2. **APIM integration.** Use its managed identity and Key Vault permissions for the certificate's backing secret. ARM uses the `secretIdentifier`, not an assumption that a certificate URI returns a PFX. For automatic refresh, the Key Vault identifier is versionless. This is a deliberate exception to immutable content pins: record exact certificate versions/thumbprints in rotation evidence without hard-pinning APIM to an old version. [APIM integration](https://learn.microsoft.com/en-us/azure/api-management/api-management-howto-mutual-certificates), [ARM certificate schema](https://learn.microsoft.com/en-us/azure/templates/microsoft.apimanagement/2024-05-01/service/certificates).
3. **Rotation is not instantaneous.** APIM documents refresh within four hours; manual refresh is possible. Proposed safe sequence: distribute old+new public allowlist, publish new PFX version, refresh/observe new APIM certificate on every backend, then remove old allowlist entry and revoke/disable old material. Allow overlap beyond refresh uncertainty; test expiry and rollback. Disabling a Key Vault secret alone does not demonstrate immediate revocation of APIM's cached certificate. [APIM lifecycle](https://learn.microsoft.com/en-us/azure/api-management/api-management-howto-mutual-certificates).
4. **Renewal choices.** Self-signed certificates are supported for this disposable sample, but require explicit pin/validity checking and renewal planning. Selected partner CAs support automatic renewal; non-partner issuers do not obtain that capability simply by being imported. Do not promise a purchased CA or its price. [Key Vault certificates](https://learn.microsoft.com/en-us/azure/key-vault/certificates/about-certificates).
5. **Firewall caveat.** If Key Vault's firewall is enabled for APIM integration, the docs require APIM's system-assigned identity and the trusted-services exception. Do not enable a firewall configuration that strands the five workloads' secret reads. Network topology is a separate config choice, not solved by RBAC. [Integration prerequisites](https://learn.microsoft.com/en-us/azure/api-management/api-management-howto-mutual-certificates#requirements-for-key-vault-firewall).
6. **Subscription credentials.** Separate per-agent/operator credentials; store only in allocated secret scopes; replace credential-bearing headers before forwarding and redact diagnostic output. Rotate with explicit caller cutover and subsequent old-key invalidation. Treat subscription ownership as possession-based attribution, not Entra end-user identity. This is the authoritative #6 boundary.
7. **Disposable cleanup.** `azd down` deletes project resources; `--purge` requests permanent deletion of soft-deleted resources and is not permission escalation. Inventory actual resources afterward, including managed groups, active revisions, registry, storage, model deployment, logs and APIM. Removing model traffic or scaling apps to zero does not stop APIM/ACR standing charges. [azd reference](https://learn.microsoft.com/en-us/azure/developer/azure-developer-cli/reference#azd-down).
8. **Key Vault tombstones.** Soft-delete retention is 7–90 days, selected at creation and subsequently immutable; enabled soft-delete cannot be disabled. Purge protection, when enabled, prevents early purge even for a privileged operator. Unique disposable names avoid blocked name reuse. Purge authority is separate; retention and purge choice belong in #7 and must respect subscription policy. Recovery does not restore RBAC assignments automatically. [Soft-delete guide](https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview).

## 5. Minimum authority and live preflight

Separate **minimum operations** from convenient built-in role bundles; broad Contributor is not the mathematically minimal custom role.

| Principal | Needed authority and narrow scope |
| --- | --- |
| Deployment operator | Resource writes/deletes and `Microsoft.Resources/deployments/*` at the disposable resource-group scope; Contributor is a practical bundle, not data access or role-assignment permission. Creating the resource group or subscription-scoped azd deployment additionally needs subscription-scope deployment/group-create operations. An existing admin-created group can avoid granting broad subscription Contributor. |
| Role-assignment step | `Microsoft.Authorization/roleAssignments/write` and cleanup delete at each target scope; scoped Role Based Access Control Administrator is a possible bundle, preferably constrained to the required roles/principals. Contributor alone cannot do this. Do not assume Owner or tenant Global Administrator. |
| Provider registration | Required providers must be registered; registering requires subscription `/register/action`, not merely RG Contributor. An administrator can pre-register Microsoft.App, ApiManagement, CognitiveServices, KeyVault, Storage, ContainerRegistry, ManagedIdentity, OperationalInsights, Insights and ApiCenter as actually used. |
| Image publisher | ACR push on the selected registry/repository according to its permission mode. ACA pull identities need only image-pull authority, not registry admin credentials. Exact AcrPush/AcrPull versus repository-ABAC choice must match registry configuration. |
| Data loader | Temporary Blob Data Contributor on the reference-data container for the pinned load; runtime Reference Data gets Blob Data Reader only. Revoke bootstrap write privilege when appropriate. |
| APIM MI | Cognitive Services OpenAI User on the one model account; only runtime principal with model inference authority. Key Vault Secrets User on the isolated backing-secret scope for certificate fetch; if certificate API reads are required, Certificate User is a broader documented alternative, never assign it to agents. No runtime storage role required for APIM. |
| Each agent MI | Key Vault Secrets User only on its own credential secret/scope. No access to other agent credentials or gateway private keys. Backend certificate validation uses public configuration, not secret reads. |
| Evidence Assessor | Blob read/write private drafts/status state only; no approved-findings write. Release Reviewer: draft reader, approved-findings writer and its own status state. |
| Candidate Planner / Briefing Author | Write own Exercise Planning output/state scope; read released findings through their separately authorized endpoint, no direct Evidence Review Blob data role. |
| Certificate/secret lifecycle operator | Certificate create/import/update and allocated secret write rights (e.g. Certificates Officer / Secrets Officer scoped appropriately), separate from read-only runtime roles. Vault-wide assignments expose all corresponding objects; isolated vaults may be simpler than fragile object-level layouts. |
| Teardown operator | Resource-group/resource deletion; role-assignment cleanup; separate purge authority only if purging is selected and allowed. Deleting objects and purging a deleted vault have different required operations/scopes. Do not grant runtime purge permissions. |

Sources: [Contributor/RBAC Administrator definitions](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/privileged), [resource-provider registration](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/resource-providers-and-types), [storage role scoping](https://learn.microsoft.com/en-us/azure/storage/blobs/assign-azure-role-data-access), [Key Vault role data actions](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/security), [OpenAI User](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/ai-machine-learning#cognitive-services-openai-user), [APIM certificate access](https://learn.microsoft.com/en-us/azure/api-management/api-management-howto-mutual-certificates), [purge constraints](https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview). The per-workload storage mapping is the #6/#10 contract, not a newly discovered Azure role.

Object-scoped role assignments, managed-identity attachment/pull configuration, bootstrap role delegation, admin-consent requirements for **optional future CI**, Azure Policy restrictions and inherited rights have not been inspected. Managed identities do not require turning this design into a custom application-registration exercise. A human with broad operator rights remains privileged across modeled teams; policy editors can exercise APIM's MI, a caveat explicitly documented by the [managed-identity policy reference](https://learn.microsoft.com/en-us/azure/api-management/authentication-managed-identity-policy).

Before any authorized deployment, the operator must verify:

- Subscription eligibility, regional provider/SKU capacity, local policy and exact role permissions.
- Model quota for **this model + regional Standard + West Europe**, available TPM and corresponding RPM, not just a supported-region check. [Quota documentation](https://learn.microsoft.com/en-us/azure/foundry/openai/how-to/quota) scopes allocations by subscription, region, model and deployment type.
- APIM capacity, ACA cores and certificate/secret access/propagation. No quota or tenant capability is asserted here.
- Numeric agent steps, tool calls, timeouts, token/output ceilings and TPM configuration selected in #7. ACA documents a 240-second HTTP request timeout; chained workflow deadlines and status reconciliation must fit the actual request design. Do not use a long APIM timeout to imply unlimited ACA duration.

## 6. Indicative 24-hour charges

**Public retail USD, West Europe, consumption price rows retrieved 2026-10-14; not a quote, bill, budget limit or account estimate.** No discounts, taxes, credits or unused subscription-wide free grants assumed. Azure's Retail Prices API is public and was queried without Azure account credentials. Price values below are regional rows, not copied global OpenAI prices.

Reproducible public source queries:

- [APIM](https://prices.azure.com/api/retail/prices?$filter=armRegionName%20eq%20%27westeurope%27%20and%20serviceName%20eq%20%27API%20Management%27%20and%20priceType%20eq%20%27Consumption%27)
- [Container Apps](https://prices.azure.com/api/retail/prices?$filter=armRegionName%20eq%20%27westeurope%27%20and%20serviceName%20eq%20%27Azure%20Container%20Apps%27%20and%20priceType%20eq%20%27Consumption%27)
- [ACR](https://prices.azure.com/api/retail/prices?$filter=armRegionName%20eq%20%27westeurope%27%20and%20serviceName%20eq%20%27Container%20Registry%27%20and%20priceType%20eq%20%27Consumption%27)
- [Model meters](https://prices.azure.com/api/retail/prices?$filter=armRegionName%20eq%20%27westeurope%27%20and%20contains%28meterName%2C%20%274.1%27%29%20and%20priceType%20eq%20%27Consumption%27)
- [Key Vault](https://prices.azure.com/api/retail/prices?$filter=armRegionName%20eq%20%27westeurope%27%20and%20serviceName%20eq%20%27Key%20Vault%27%20and%20priceType%20eq%20%27Consumption%27)
- [Log Analytics](https://prices.azure.com/api/retail/prices?$filter=armRegionName%20eq%20%27westeurope%27%20and%20serviceName%20eq%20%27Log%20Analytics%27%20and%20priceType%20eq%20%27Consumption%27)
- [Hot LRS storage](https://prices.azure.com/api/retail/prices?$filter=armRegionName%20eq%20%27westeurope%27%20and%20serviceName%20eq%20%27Storage%27%20and%20skuName%20eq%20%27Hot%20LRS%27%20and%20priceType%20eq%20%27Consumption%27)

| Meter/assumption | Observed rate | 24-hour illustration |
| --- | --- | --- |
| APIM Basic v2 Unit, one unit | $0.20548/hour | **$4.93152**, even with no traffic. Effective price date 2024-03-01. |
| APIM Standard v2 Unit, alternative not baseline | $0.9589/hour | $23.01360, before other services. Do not use the cheaper secondary-unit row for the first unit. |
| ACR Basic Registry Unit | $0.1666/day | **$0.1666**. Image storage beyond allowance/build tasks can add charges. |
| ACA active CPU | $0.000034/vCPU-second | Five replicas, each 0.5 vCPU, all active for 24 hours: $7.344. |
| ACA active memory | $0.000004/GiB-second | Same five replicas, each 1 GiB: $1.728. Active compute total **$9.072**. |
| ACA idle CPU + memory | $0.000004/vCPU-second and $0.000004/GiB-second | All five min-replicas continuously eligible for idle billing: **$2.592**. This is conditional, not guaranteed idle classification. |
| ACA requests | $0.56/million | 100,000 billable requests: $0.056, before free grants. |
| Regional gpt-4.1-mini input | `gpt 4.1 mini Inp regnl Tokens`, $0.000528/1K | 1,000,000 uncached input tokens: $0.528. |
| Regional model output | `gpt 4.1 mini Outp regnl Tokens`, $0.002112/1K | 100,000 output tokens: $0.2112. Combined **$0.7392**; regional price effective 2025-11-01. |
| Regional cached model input | $0.000132/1K | Not assumed; no invented cache hit rate. |
| Key Vault Standard Operations | $0.03/10K | 10,000 operations: $0.03. |
| Key Vault Certificate Renewal Request | $3/request | Only if applicable; not blanket $3 per certificate or per day. External CA issuance may cost extra. |
| Log Analytics paid Analytics Logs ingestion | $2.99/GB, after free tier | One paid GB: $2.99. Retention beyond allowance: $0.13/GB-month. |
| GPv2 Hot LRS | $0.0196/GB-month first tier; reads $0.0043/10K; writes $0.054/10K | 1 GB retained for 1/30 month plus 10K reads and 10K writes: about $0.05895. |
| API Center Free | Free-plan inventory | $0 if its limits suffice; validate rather than assuming Standard is free with Basic v2. |

Illustrations, not predicted workloads:

- **Standing APIM + ACR floor:** about **$5.10/24h**, before any compute, usage, storage or telemetry.
- **Light day:** all five replicas active one hour then scaled to zero for 23 hours, plus the listed model/1-GB-log/10K-vault/storage/100K-request usage: about **$9.35**.
- **All five replicas active for 24 hours**, same usage allowances: about **$18.04**.
- **Warm idle day:** five eligible idle replicas for 24 hours plus APIM/ACR, with no assumed inference/log volume: about **$7.69**, plus actual usage.
- Substituting one Standard v2 unit adds about **$18.08/day**. No reason to buy it solely for this public-origin topology.

Arithmetic assumes 0.5 vCPU/1 GiB is sufficient per workload; memory/latency were not measured. Resource sizing, replicas and traffic can change these totals materially. Model consumption is across **all** agents, including repeated prompts/tool cycles; bounded candidate counts are not token counts. No number above caps spending.

[ACA billing](https://learn.microsoft.com/en-us/azure/container-apps/billing) documents subscription-month free grants of 180,000 vCPU-seconds, 360,000 GiB-seconds and 2M requests, zero compute when scaled to zero, and idle eligibility conditions. Existing subscription usage may already consume those grants. Extra active revisions count; private endpoints/planned maintenance can add dedicated management fees even with Consumption.

APIM call overage, registry builds/excess storage, certificate renewal, extra logs/retention, storage versions, network egress, private networking, retries and resources left during slow/failed teardown are excluded from illustrations, **not free**. APIM Basic v2's public rate feed includes a $0.03/10K paid calls tier; validate the billing-period included-call allowance rather than interpreting its zero-price row as unlimited calls. Delayed billing visibility and soft-delete retention require a post-teardown inventory/cost review.

**Pricing confidence:** high for the quoted public meter values and shown arithmetic; medium for mapping the intended resource mix; low for the actual bill until workload, discounts, allowances, retention and teardown duration are known.

## 7. Earlier proposed numeric runtime limits: superseded by agreed-limits follow-up

**Historical proposals only:** the agreed-limits follow-up in section 1 supersedes the numbers below, including 50 minutes, 64 model calls and 1.2 million tokens. Retained to distinguish the research proposal from later human choices. These were recommendations for #7, not measured latency, implementation, or a financial spending ceiling. Stop after three complete released candidates or after the fixed first-20 pool is exhausted. The maximum-count analysis deliberately allows all 20 candidates to reach both Assessor and Reviewer, including releasable insufficient findings.

### Hard counts and payloads

| Limit | Recommendation |
| --- | --- |
| Concurrent runs | One per deployment initially; no overlapping CLI run. |
| Candidate concurrency / nested depth | One candidate at a time; maximum cross-agent depth Planner → Assessor → Reviewer. No recursive delegation. |
| Candidate assessments | 20 maximum, once each. |
| Agent invocations | 20 Assessor + 20 Reviewer + 1 Briefing = 41 internal A2A invocations; 42 including the operator's Planner invocation. No automatic invocation retry. |
| Reference MCP logical reads | 1 search + 20 × 2 Planner evidence reads + 20 × 2 Assessor rechecks + 20 × 2 Reviewer rechecks = **121** maximum. Cache only exact snapshot/profile/fixture keys within the authorized caller context. |
| Released-finding logical reads | Up to 20 Planner reads, including insufficient findings retained for outcome explanation, plus at most 3 Briefing reads = **23**. |
| Safe-read retries | At most two retries after the first attempt, backoff 0.25 then 0.5 seconds; shared absolute deadlines. Thus at most **363 MCP tool attempts + 69 findings-read attempts**. Not a permission to retry authorization/validation/not-found failures. |
| MCP discovery overhead | One initialize + tools/list per authorized Reference Data caller (Planner, Assessor, Reviewer): six logical discovery exchanges per run; retain those clients for that run, no discovery loop. Separate from 121 tool reads. |
| Model calls | Planner 2; Assessor 2 per candidate; Reviewer 1 per candidate; Briefing 2: **64 maximum**. Tool invocations/results consume the agent's existing call/step budget, not fresh unbounded loops. |
| Function execution | Only the allowlisted route/tool graph; Reviewer release authority remains deterministic code, not a model tool capable of granting itself approval. |
| Payloads | 256 KiB per application evidence/A2A response; explicit result-limit failure if exceeded. Never truncate evidence into apparent completeness. Existing 20-search / 50-runway bounds remain authoritative. |

The optional extra Assessor model call is reserved for consuming tool results or one bounded correction; it does not trigger another Reviewer release attempt. If the implementation needs more rounds, fail visibly or reopen the limits rather than silently increasing them.

| Role | Calls | Input tokens per call | Output tokens per call | Maximum total tokens |
| --- | --- | --- | --- | --- |
| Planner | 2 | 8,192 | 1,024 | 18,432 |
| Assessor | 40 total | 16,384 | 2,048 | 737,280 |
| Reviewer | 20 total | 16,384 | 1,024 | 348,160 |
| Briefing | 2 | 16,384 | 2,048 | 36,864 |
| **Run sum** | **64** | **1,032,192 aggregate input** | **108,544 aggregate output** | **1,140,736** |

Recommend a **1,200,000-token logical-run guard** plus the per-call limits, accounting for all roles. This is an execution-safety budget, not a requested dollar ceiling. Count system instructions, tool schemas/history and outputs; do not silently omit required evidence to fit. At the quoted regional prices, the nominal per-role maxima correspond to about **$0.7742 model charges**, excluding additional failed/billable attempts and inaccurate estimates. APIM token estimates alone are not an exact billing guard.

A starting throughput target is **120,000 aggregate TPM** and an application pacing ceiling of **12 model requests/minute**, with no parallel model calls initially. Use caller counters plus an aggregate gateway counter; suggested per-caller TPM: Planner 20,000, Assessor 80,000, Reviewer 40,000, Briefing 40,000, all subordinate to the aggregate 120,000 ceiling. These maxima need not sum to the aggregate ceiling: not all callers can consume their individual maximum simultaneously. Reserve caller and aggregate allowance before a model call; throttle locally rather than busy-retry. **Actual Azure TPM/RPM quota must be checked**, including the model-specific capacity ratio; the [quota table](https://learn.microsoft.com/en-us/azure/foundry/openai/how-to/quota) does not explicitly identify GPT-4.1-mini's ratio, so its generic “older chat models” row is not proof.

### Time limits and the ingress decision that cannot be hidden

| Scope | Proposed upper bound |
| --- | --- |
| Individual model request | 20 seconds; SDK automatic retries off. Ambiguous inference failures are counted, not silently replayed. |
| Individual safe MCP/findings attempt | 2 seconds, limited by remaining caller/run deadline. Retries above apply only to safe transient reads. |
| Reviewer invocation | 40 seconds, within the Assessor deadline; includes rechecks, one model call and deterministic commit. |
| Assessor invocation | 100 seconds, **including** its nested Reviewer; not 100 + 40 seconds. |
| Whole candidate iteration | 120 seconds, including Assessor response, Planner's finding read and state recording. |
| Planner search/preparation | 360 seconds logical allocation for bounded source reads, up to two Planner model calls and state preparation. |
| Briefing invocation | 90 seconds; only when three complete released candidates exist. |
| Full 20-candidate logical run | **3,000 seconds / 50 minutes**: 360 + 20 × 120 + 90 + 150 seconds margin. Child timeouts always shrink to remaining parent/run time. No guarantee of success during throttling/outage. |
| Status/reconciliation reads | At most 300 across the run; task-mode operator polls no more often than every 15 seconds (at most 200 in 50 minutes), leaving 100 owner-scoped reconciliation reads. No automatic re-invocation to “check” status. |

**This 50-minute envelope cannot be one synchronous Planner HTTP request through ACA.** ACA documents a **240-second request timeout**. A longer APIM timeout does not remove it. The fully agreed request/reply topology therefore has a genuine operational choice:

1. **Preserve a single synchronous root request:** recommend a **210-second application deadline**, APIM timeout **220 seconds**, operator HTTP timeout **230 seconds**. The 20-candidate count remains a ceiling, **not a promise that all 20 will complete**. Stop as failed/partial at the deadline; never report pool exhaustion unless every pool member actually completed. This mode may often find three candidates quickly, but that has not been measured or proven by the fixture data.
2. **If completing a slow all-20 run is required:** seek explicit human agreement for standard A2A task-return/status-polling behavior or another explicit resumable request design. A [protocol task and Get Task](https://a2a-protocol.org/v1.0.0/specification/) can avoid holding one HTTP request for the entire logical run. Recommend each kickoff/status response complete within 10 seconds, with the logical 50-minute limits above, durable state and restart fencing. This is **not yet an approved architecture adjustment**: #6's “no background delegation” and bounded request/reply wording must be reconciled by the human/parent before interpreting it as permission for a task-running mechanism. This research neither implements that mechanism nor assumes the in-memory SDK example meets it.

No credible documentary source establishes that 20 sequential model-backed Assessor/Reviewer pairs fit inside 210 seconds. Selecting aggressively tiny timeouts just to make the arithmetic fit would fabricate feasibility. The source-backed recommendation is to expose this choice, preserve explicit partial-result semantics, and measure the actual bound before promising the all-20 acceptance path.

## 8. Handoff: what this research does and does not resolve

Documentarily supported:

- Release-lock-coherent Framework/A2A/MCP/OpenAI/ASGI/Azure core candidate, with a separately flagged Key Vault SDK addition.
- Genuine pinned A2A 1.0 JSON-RPC and MCP 2025-11-25 Streamable HTTP support in official SDKs.
- Tool-capable fixed Azure model/version with documented **regional** West Europe availability, not an assertion of live quota.
- Basic v2 capabilities, relevant stable ARM properties, certificate lifecycle constraints, scoped-authority requirements and public 24-hour cost illustrations.

Required proof before calling the bundle deployable:

1. Resolve a minimal application lock with hashes on the exact Python/container platform, including the Key Vault addition and selected extras. Install/import, run ASGI lifecycle and local protocol tests. Upstream lock co-occurrence is not this proof.
2. Bicep compile/lint and azd/toolchain validation; exact remaining resource APIs, source commit, profile/fixture/config hashes and built application image digests.
3. Authorized operator-only live checks for quota, permissions, policy, regional SKU capacity and role propagation.
4. End-to-end A2A, MCP initialization/list/call, model tools, gateway URL/header behavior and correlation through APIM. Validate nonstreaming and any streaming path actually enabled.
5. Deny missing/wrong/expired gateway certificates, forged XFCC/caller headers, unauthorized subscriptions/routes, direct model origins and cross-team storage/secret access. Test rotation and failure/timeout/reconciliation without duplicate releases.
6. Execute #10's pinned data/fixture viability gate and #8 acceptance evidence. Do not infer evidence correctness from a successful deployment.

Human/coordinator decisions still needed: acceptance of the beta A2A adapter candidate; final deployment/model/token/resource limits and the synchronous-root versus explicitly approved task/polling choice in #7; lifecycle/purge choices; optional CI identity if later chosen; explicit permission before any EU alternate. Publication uses the separately authorized existing remote base. No implementation, financial budget ceiling, issue closure or map resolution is supplied by this study.
