# Feasibility Check: Gateway-Only Access (APIM-Fronted ACA Agents/MCP, No New App Registration)

Scope: narrow feasibility hinge for [#11](https://github.com/JoranBergfeld/citadel-example/issues/11), informing the runtime decision in [#6](https://github.com/JoranBergfeld/citadel-example/issues/6). Verified against current primary Microsoft Learn docs and the A2A/MCP specs (fetched directly in this session where noted). Not an architecture recommendation; the human decides alternatives.

**Summary / verdict:** The building blocks for a "gateway-only" pattern exist in current docs, but the enforcement boundary is **not entirely platform-level**. APIM can present a client certificate to a backend (documented). Azure Container Apps (ACA) ingress can be set to `clientCertificateMode: require`, which makes the ingress *require* a client cert to complete the request and forwards it to the app — but ACA's own docs state the **application itself is responsible for extracting and validating** the certificate from the `X-Forwarded-Client-Cert` (XFCC) header; there is no documented "platform validates cert identity against an allow-list" mode. ACA docs do explicitly state the XFCC header "is overwritten if sent by the client" — a documented anti-header-injection guarantee — but this is distinct from, and weaker than, platform-enforced *authorization* (only one specific pinned certificate permitted). A2A (JSON-RPC over HTTP/HTTPS + SSE) and MCP Streamable HTTP (HTTP POST/GET + optional SSE) have no transport requirement incompatible with TLS terminating at APIM and re-originating at ACA's ingress. Disabling local auth (API keys) on Cognitive Services/Foundry resources in favor of RBAC-only, managed-identity access is a real, documented, current capability. **Net: the pattern is buildable with documented Azure features, but "gateway-only, no direct-origin bypass" requires application-code enforcement of the client-certificate/XFCC check at each ACA backend (and/or network-layer restriction), not a pure declarative platform guarantee.**

---

## 1. APIM → ACA outbound mutual-TLS / client-certificate presentation

**Verdict: Yes, documented.**

- Source: https://learn.microsoft.com/en-us/azure/api-management/backends
  - APIM backend entities support securing gateway-to-backend access via mutual TLS using client certificates or CA certificates, configured via the Backend entity's authorization credentials.
  - APIM also supports system-/user-assigned managed identity as backend authorization credentials for Azure-resource backends (a separate, non-mTLS mechanism).
- Caveat: client-certificate / CA-certificate-detail configuration on the Backend entity is documented as a **v2-tier-only** feature.

## 2. ACA ingress `clientCertificateMode` — what it actually does

**Verdict: Partially — ingress requires presence of a cert at the handshake when `require` is set; validation/authorization is app-level.**

- Source: https://learn.microsoft.com/en-us/azure/container-apps/client-certificate-authorization (fetched directly, ms.date 2025-06-30)
  - `clientCertificateMode` values: `require` ("The client certificate is required for all requests to the container app"), `accept` (optional, still forwarded if present), `ignore` (default; dropped).
  - "Ingress passes the client certificate to the container app if `require` or `accept` are set."
  - The article's only "how to use" guidance for the `Hash`/`Cert`/`Chain` fields of XFCC is for the **app** to identify/validate the certificate — no platform-side allow-list/authorization step is described.
- Source: https://learn.microsoft.com/en-us/azure/container-apps/mtls
  - "In Azure Container Apps, all incoming requests pass through Envoy before being routed to the target container app... Each of these certificates is placed into the `X-Forwarded-Client-Cert` header, which is then sent to the application." Building an mTLS app requires the app to "Extract X.509 Certificates from requests" — framed explicitly as an application-development task.
- Caveat: No ACA feature found that declaratively restricts access to a specific certificate thumbprint/CN/issuer at the ingress/control-plane level (unlike APIM's own inbound `validate-client-certificate` policy, which is platform/policy-level but secures APIM's *inbound* side, not ACA's).

## 3. X-Forwarded-Client-Cert (XFCC) header: sanitization / spoof resistance

**Verdict: Partially documented — ACA states the header is overwritten if client-supplied, but does not document the underlying mechanism in more depth.**

- Source: https://learn.microsoft.com/en-us/azure/container-apps/ingress-overview, HTTP headers table (fetched directly):
  - `X-Forwarded-Client-Cert`: "The client certificate if `clientCertificateMode` is set... Semicolon separated list of Hash, Cert, and Chain... **This value is overwritten if sent by the client.**"
  - Same table: `X-Forwarded-Proto` is likewise "overwritten if sent by the client." By contrast, `X-Forwarded-For` is explicitly **not** fully protected: "Only the rightmost IP is provided by Azure Container Apps. Any other values must be validated by the user to prevent IP spoofing." This asymmetry shows ACA docs distinguish headers they guarantee from ones the app must still defend.
- Notes/caveats:
  - This is a direct ACA citation (not inferred from generic Envoy documentation) — ACA's own docs state the overwrite behavior for XFCC specifically, which is a real, documented spoof-resistance property for header injection by the direct caller.
  - Docs do **not** describe deeper implementation mechanics (e.g., exactly how/where the substitution happens) the way Envoy's own project docs describe XFCC handling; no ACA page found cross-referencing Envoy's XFCC docs. Treat the deeper mechanics as undocumented by Microsoft.
  - No ACA doc found claiming the XFCC header itself is cryptographically signed or otherwise tamper-evident beyond the ingress-overwrite guarantee.

## 4. App-level vs platform-level enforcement of "gateway-only"

**Verdict: Enforcement requires application code (or network isolation); not purely platform-declarative.**

- Per §2/§3: ACA ingress can require that *some* client certificate is presented (`clientCertificateMode: require`) and guarantees the XFCC header reaching the app reflects the real TLS-negotiated cert rather than a client-supplied header. However, docs explicitly place certificate *extraction and validation* on the application (`mtls` and `client-certificate-authorization` pages), and no platform-level "accept only thumbprint X" control is documented for ACA ingress.
- Complementary, separately documented controls exist at the platform level: IP restrictions (`ingress-overview` → "IP restrictions"), and internal-only ingress / internal-only environments (`ingress-overview` → "External and internal ingress", "Restrict an app to virtual network access only"). These narrow exposure but are distinct mechanisms from certificate-based identity authorization, not a substitute for it per docs.
- Conclusion: a true "gateway-only, no direct-origin bypass" guarantee for this architecture rests on (a) `clientCertificateMode: require` rejecting cert-less connections at the ingress (platform-level, confirmed), **and** (b) the backend app verifying the specific certificate identity (thumbprint/CN) from XFCC matches the expected APIM certificate (application-level, per docs) — optionally hardened further by internal-only ingress/IP restrictions (platform-level, but orthogonal).

## 5. External HTTP/TLS termination realities

**Verdict: Yes — TLS terminates at ACA's ingress, and a cert-less direct caller is rejected before reaching app code when `clientCertificateMode: require` is set; a caller presenting *any* certificate is still forwarded to the app.**

- Source: https://learn.microsoft.com/en-us/azure/container-apps/ingress-overview (fetched directly): "HTTPS endpoints that always use TLS 1.2 or 1.3... terminated at the ingress point."
- Source: https://learn.microsoft.com/en-us/azure/container-apps/client-certificate-authorization: `require` mode — "The client certificate is required for all requests to the container app," implying rejection at/before the handshake completes for a caller presenting no certificate at all, since Envoy-based ingress is the TLS terminator.
- Caveat: docs confirm rejection of a *cert-less* connection when `require` is set, but do not document rejection, at the ingress layer, of a connection presenting *any* valid-but-wrong certificate — such a request is still forwarded to the app (with the real presented cert in XFCC) for the app to reject. This reinforces §4: final identity authorization is app-level.
- Separately, `ingress-overview` documents that an app's public reachability also depends on **App ingress visibility** (`external`/`internal`) combined with the **environment accessibility level** (public vs `--internal-only`); an internal environment has "no public endpoint at all," which is a genuine platform-level way to remove public direct-origin reachability entirely (distinct from, and compatible with, client-certificate checks).

## 6. A2A JSON-RPC and MCP Streamable HTTP transport compatibility with APIM→ACA proxying

**Verdict: Yes — both protocols are specified over standard HTTP(S) request/response (+ optional SSE), with no raw-TCP, WebSocket-only, or "client TLS session must reach origin unbroken" requirement that would be broken by TLS terminating at APIM and re-establishing to ACA.**

- MCP Streamable HTTP — https://modelcontextprotocol.io/specification/2025-06-18/basic/transports (fetched):
  - "This transport uses HTTP POST and GET requests. Server can optionally make use of Server-Sent Events (SSE) to stream multiple server messages."
  - "The server MUST provide a single HTTP endpoint path... that supports both POST and GET methods."
  - Session continuity uses an application-layer `Mcp-Session-Id` HTTP header; resumability uses SSE `Last-Event-ID` — both ordinary HTTP header mechanisms compatible with an intermediary proxy hop.
  - Spec security guidance: servers "SHOULD implement proper authentication" and "MUST validate the Origin header" — application-level MCP-server responsibilities regardless of gateway topology, not blockers to proxying through APIM.
- A2A — https://a2a-protocol.org/latest/specification/ (fetched):
  - Guiding principle: "Simple: Reuse existing, well-understood standards (HTTP, JSON-RPC 2.0, Server-Sent Events)."
  - Protocol bindings (JSON-RPC methods, gRPC, HTTP/REST endpoints) are all defined over standard HTTP(S), not a bespoke transport; streaming operations use SSE-style long-lived HTTP response bodies.
- Caveat (unverified/inferred, not directly re-confirmed against primary text this session): third-party summaries describe an A2A normative expectation that production Agent Card/interface URLs use HTTPS. This is plausible and consistent with the fetched spec text but was **not independently re-verified against the exact normative section** in this session; flagged as inferred rather than confirmed documented fact.
- Neither spec mandates a transport (raw TCP, WebSocket-only) or end-to-end client-TLS-session preservation that is incompatible with APIM terminating the client connection and re-originating a new TLS (optionally mTLS) connection to the ACA backend.

## 7. Disabling local auth + managed-identity-only RBAC for model inference

**Verdict: Yes — real, current, documented capability.**

- Source: https://learn.microsoft.com/en-us/azure/ai-services/disable-local-auth (fetched directly, updated 2026-09-09):
  - "You can disable local authentication using the Azure policy **Azure AI Services resources should have key access disabled (disable local authentication)**... If you're creating an account using Bicep/ARM template, you can set the property `disableLocalAuth` to `true`."
  - Also settable via `Set-AzCognitiveServicesAccount ... -DisableLocalAuth $true`.
- Source: https://learn.microsoft.com/en-us/azure/foundry-classic/openai/how-to/managed-identity:
  - Documents assigning an RBAC role (e.g., **Cognitive Services OpenAI User**) to a resource's managed identity and authenticating via `DefaultAzureCredential`/bearer tokens instead of an API key; explicitly supports container apps' managed identities for this flow.
- Net: scoping inference-call RBAC to exactly one managed identity (e.g., only APIM's) plus `disableLocalAuth: true` on the target resource is a documented mechanism to require that only explicitly role-assigned principal(s) can call the model endpoint — enforced by Entra ID/RBAC at the resource's control plane, independent of ACA/APIM network topology. No new Entra app registration or elevated directory permission is needed for this (standard RBAC role assignment on a resource the operator already controls).

---

## Caveats and open gaps

- **No ACA platform feature found** that authorizes inbound requests by specific client-certificate identity (thumbprint/CN/issuer) at the ingress/control-plane level; all ACA docs found assign that verification to application code via the XFCC header.
- **XFCC spoof-resistance** is documented only as "overwritten if sent by client" — no ACA doc found describing the underlying mechanism in more depth or cross-referencing Envoy's own XFCC documentation; treat deeper mechanics as undocumented by Microsoft.
- **A2A's HTTPS-in-production normative requirement** — only consistent with, not directly re-confirmed against, the exact primary spec text fetched in this session; flagged as unverified/inferred.
- This report verifies individually documented Azure/protocol features; it does not verify a tested, end-to-end reference configuration combining APIM client-cert backends with ACA `clientCertificateMode: require` and app-level pinning. No Microsoft doc was found describing a turnkey "gateway-only" ACA preset — this is a composition of independently documented mechanisms (ACA `clientCertificateMode`, APIM backend client certs, ACA ingress visibility/environment accessibility/IP restrictions, Entra `disableLocalAuth` + RBAC), not one named capability.
- Runtime identity used for inference RBAC assignment is whatever managed identity the runtime decision selects (e.g., APIM's own system-assigned identity); this is not necessarily a Foundry Agent ID, consistent with the constraint that Foundry Agent IDs remain conditional on the runtime choice.

## Sources

- https://learn.microsoft.com/en-us/azure/api-management/backends
- https://learn.microsoft.com/en-us/azure/container-apps/ingress-overview
- https://learn.microsoft.com/en-us/azure/container-apps/mtls
- https://learn.microsoft.com/en-us/azure/container-apps/client-certificate-authorization
- https://learn.microsoft.com/en-us/azure/ai-services/disable-local-auth
- https://learn.microsoft.com/en-us/azure/foundry-classic/openai/how-to/managed-identity
- https://modelcontextprotocol.io/specification/2025-06-18/basic/transports
- https://a2a-protocol.org/latest/specification/
