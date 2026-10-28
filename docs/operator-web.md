# Protected Operator application and retained runs

The hosted Operator application is not a scenario playback. It opens
on Comparison, Replacement and Exhaustion descriptions with expected outcomes and
linked Reference Data, Evidence Review and Exercise Planning perspectives. Choose
one scenario and use **Run scenario** to start the actual deterministic workflow.
The current run becomes the primary view; Earlier runs reopens retained Planner
observations. CLI submissions enter the same durable Planner index and share
global admission with browser submissions. **Check and recover** is available for
retained UI/CLI runs.
**Retry this run** is a separate, explicitly confirmed action offered only from a
fresh observation of authoritative no-commit work; the owning service rechecks it.
There is no simulated production mode or automatic submission after login.

## Explicit Check and recover

Open a retained run, then select **Check and recover**. This authenticated,
same-origin CSRF-protected action resolves the original owner and immutable inputs
inside Candidate Planner. It never accepts browser ownership, receipts or paths.
Planner follows only the recorded child grants to their owning services; ordinary
workload status/invocation ownership is unchanged.

Each bounded request uses the deployment's separate **2,048 recovery-proof reads**
for outgoing proof/control exchanges, index/operation/audit reads and private
commit proof reads, including failures. All physical reads require confirmed
unique spent markers. Admission and downstream work share one **30-second**
deadline, with no automatic retries, refunds, refill or workflow-ticket spending.

Run-bound intent, request identity, proof and outcome are retained in the owning
operation ledger. Duplicate requests and lost responses reconcile that action;
they never replay agents, models or unfinished workflow logic. Reopen/refresh to
inspect the latest persisted outcome. An unconfirmed response remains **unknown**,
not proof that nothing happened. Re-login never resubmits an interrupted action.
Control actions invalidate mutable observations, including pre-control refreshes.
Only a persisted safe recovery outcome updates the retained execution summary and
resolves a hosted ambiguous-dispatch blocker. Missing/unknown proof never clears it.

A live owner stays blocked until a later explicit check. Definite no-commit may
release only the exact owned admission generation. Partial work requires the
original deadline plus the existing 16-second storage-lease margin, fenced owners,
resolved or bound quiescent child/private effects, no outstanding model effect,
and two unchanged owner snapshots. Its admission may then be released, but its
execution remains **incomplete**, artifacts and accounting remain unchanged, and
it is **not retryable**. Starting another run is separate. There is no Cancel,
Reset, force unlock or artifact deletion.

Missing ownership/bindings, absent child commits, unresolved models, changing
snapshots, unavailable proof and exhausted allowance do not authorize release.
Infrastructure repair, credential administration and intrusive diagnostics remain
CLI/manual operations, not recovery fallbacks. Each owner retains at most 1,024
control intents in its bounded ledger; reaching that bound refuses new controls.

Hosted recovery entrypoint
`operator.recovery.RecoveryClient.check(run_id, request_id)` calls Planner
`POST /operator/runs/{run_id}/recover/{request_id}`.
`runtime.recovery.Recovery.check_run` resolves `RunIndex` bindings and stores
`operator_controls` beside operations. Child proof uses
`GatewayPeers.recover_child` and `POST /operator/recovery/{operation_id}/{request_id}`.
These remain reconciliation interfaces, not execution/retry admissions.

## Separately confirmed Retry this run

After **Check and recover** proves `failed_no_commit`, reopen/refresh the retained
or current run. If the owner projection reports eligible no-commit state, use
**Retry this run**, check the confirmation box and choose **Confirm retry this run**.
With JavaScript enabled, a separate confirmation dialog also guards submission;
cancelling or a second submit does not send the form. Server confirmation is
required independently of JavaScript. No action is replayed after login, refresh,
history navigation or backend restart.

`RecoveryClient.retry(run_id, request_id, confirmed=True)` uses a separately
authorized `POST /candidate-planner/operator/runs/{run_id}/retry/{request_id}`
with only `{"confirmed": true}`. Only the authenticated `operator-web` caller may
use it, through APIM and signed/certificate-protected origin authorization.
The browser supplies no fixture, owner, receipt, deadline, budget or storage path.

Planner resolves its retained immutable input binding and rechecks authoritative
no-commit state, matching original root budget, unexpired original deadline,
no outstanding model/child or committed/ambiguous external effect, and global
single-run admission. Previously visited candidates/delegated grants are refused,
not resumed. Quiescent partial work is never retryable. An unresolved hosted
dispatch also remains a blocker even if the global lease slot appears empty.

Admission requires the remaining original allowance to fund the next root agent
and model step (one agent, one model, 18,000 conservative tokens, one accounting
read and an unused per-execution model attempt). One actual original workflow
ledger read additionally proves/spends a remaining physical workflow ticket.
This is **not a promise that enough allowance/time remains to finish the run**:
every later model, child, candidate and read still checks/charges the existing
bounded accounting. No pool is created/refilled, prior attempt counters/charges
are retained, and the original deadline never moves. Proof/index/audit/protocol
reads use the same separate finite recovery-proof allowance and 30-second bound.

The owning ledger retains a run/input-bound retry intent **before admission**.
Existing `Operations.retry`/claim and generation-specific global leases fence
prior owners; an old generation cannot commit or release the new admission.
The safe outcome is durably stored before any execution is scheduled or response
reported. `retry_admitted` means admission was recorded, **not guaranteed
dispatch/completion**. A process can stop between persistence and dispatch; its
intent is deliberately not a restart queue. Duplicate/lost/ambiguous requests
return the recorded outcome or unknown and never blindly schedule work. A lost
outcome/admission leaves conservative retained state for an explicit later check;
there is no automatic retry, unlock or resumption of partial workflow logic.
The proposed admission generation is retained before lease acquisition, so a
fresh explicit check can release that exact lease after proven no-commit even
when the acquisition response was lost before the operation changed generation.
It cannot release another run's lease or a newer owned execution.

Reopen **Observe this run** for the existing bounded observation/active-run refresh.
Control responses invalidate all composed mutable observations, including older
in-flight refreshes. Historical control outcomes are not current execution or
admission status. A separate new run remains a separate action.

Offline checks:

```sh
python -m unittest discover -s tests/unit -p 'test_operator_recovery*.py' -v
python -m unittest discover -s tests/unit -p 'test_operator_retry*.py' -v
python -m unittest tests.infra.test_operator_retry tests.infra.test_policies -v
node --test tests/client/*.test.mjs
```

These fixtures establish controlled handler, ownership, accounting and recovery
behavior and checked-in APIM contracts only. Deployed Azure/APIM enforcement,
real model behavior and live-demo recovery/retry
have not been verified by these tests.

## Running and observing scenarios

The browser sends only a scenario and opaque request identity to its authenticated
backend. The backend's isolated `operator-web` caller invokes
`POST /candidate-planner/operator/scenarios`; only this explicit control authority
maps to the Planner's existing root ownership. It grants no generic A2A invocation
or CLI-key access. Planner resolves fixed bindings: comparison → `base-source`,
replacement → `missing-width-replacement`, exhaustion → `no-alternative`.
Browser-provided fixture, owner, run ID and storage paths are rejected.

Planner derives one run identity per submission request and conditionally persists
immutable inputs plus dispatch intent **before calling the existing runtime**.
Only the confirmed intent writer may dispatch once. Duplicates, lost responses,
concurrent requests and backend restart reconcile that retained intent; an
ambiguous write never authorizes dispatch. An intent with no known outcome stays
unknown, even when no workflow was actually started. There is deliberately no
background resubmission or automatic repair. Persisted intent/outcome races can
remain unknown and require explicit recovery inspection, not another click.
An unresolved intent or ambiguous dispatch also blocks fresh UI and CLI starts
through the shared index, even before a workflow slot was confirmed. Missing
proof is not permission to clear it.
The existing durable global slot blocks concurrent CLI/UI execution; a blocker or
conflicting state is shown without a reset or ownership bypass.

The selected current run shows only exact saved Planner products: selected and
skipped candidates, evidence gaps, labelled overlay provenance, an actual embedded
saved brief and its exact approved-finding references. Replacement candidates are
identified after the initial three candidates. Exhaustion explains the finite
pool with no brief. Technical/incomplete execution, release rejection and
insufficient evidence stay distinct. Missing prose/artifacts are not regenerated;
original source data is unchanged and fictional-use caveats remain visible.
Detailed team inspection and exact citation navigation compose through the
separate team-view slices; this summary does not grant draft access.

Only a selected **current** run whose observed execution is pending/running
refreshes every 15 seconds while its page is visible. History/completed views are
manual. The dependency-free client stops on hidden pages, terminal/unknown
execution, exhausted observation allowance or authentication denial. It has no
submission, retry or recovery loop. Active stale observations remain labelled
last-known, not live activity. No simulated stages or percentages exist.
Manual/automatic requests share one in-flight backend read across tabs; automatic
requests reuse the latest attempt for 15 seconds, including failed attempts.
Authentication and explicit user submission remain separate from observation.

### Cross-team flow and node inspection

The current-run screen leads with an interactive, team-grouped architecture and
short owner-action descriptions. Its arrows are **authored possible routes**, not
a played-back timeline. The diagram includes all four agents, Reference Data,
private drafts, approved findings, planning records, the UI/backend/APIM entry,
gateway-mediated calls, scoped storage and the model route.

Select an agent/data node to inspect its existing team-owned projection with the
same selected run. Architecture/support nodes open explanatory detail without a
service request. Exact brief citations still open the saved approved-finding
version; private draft links remain Operator-only Evidence Review inspection.
Planning receives no draft preview. Missing/partial history, provenance and
source-versus-overlay distinctions are unchanged.

Only an owning service's **actual in-flight call** can substantiate a highlighted
agent or route. Services attach a small allowlisted, run-bound activity projection
to their existing summary/draft/release/brief responses. It reports an awaiting
reference, child, finding or model call, not downstream execution or model output.
It is ephemeral, bounded to 32 concurrent local task entries, and absent after the
call ends, cancellation or process restart. A persisted running label, lease,
expected sequence or saved artifact is never used to invent activity.

Each snapshot expires within **15 seconds** (and before its original execution
deadline). The browser removes pulses and changes descriptions to unknown/last
observed on expiry or failed/stale observation, even if a refresh is still pending.
Independent owner observations may disagree in age; they are not an atomic
cross-team snapshot. Calls between observations may be missed; unknown does not
mean idle. Only the reporting origin agent and its evidenced route light up, never
a destination agent inferred from that route.

The existing single 15-second visible selected-active-run refresh also updates
the flow. Existing authorized cache keys and in-flight work are shared with team
inspection and across tabs. There are no per-node pollers. The one client expiry
timer only makes presentation stale; it does not fetch or dispatch anything.
Additional outgoing owner projections and their underlying storage/supporting
reads consume the same finite deployment observation allowance, within the same
30-second composition deadline and without automatic retries. Activity itself
requires no new persistence, gateway capability, model call or storage read.

**Pause animation** and system **reduced motion** leave a static diagram without
stopping observation or changing execution, recovery or retry controls. With no
JavaScript there is no animation. The pinned throwaway prototype supplied only
interaction reference: its synthetic playback code/data is not a production mode
and is not evidence that agents or deployed Azure routes ran. Offline handler and
Node tests do not establish live service, Azure/APIM enforcement or model quality.

## Private setup and replacement

After `init`, before preflight/deploy, use a private interactive terminal:

```sh
python -m citadel.operator configure-web-login --state-dir "$CITADEL_STATE_DIR"
```

Username, passphrase and confirmation are hidden prompts, never command arguments.
Use a unique passphrase of **15–128 characters**; spaces and Unicode are accepted
without composition rules or truncation. No public credentials/defaults exist.
The existing pinned `cryptography==50.0.2` Argon2id implementation produces a
32-byte hash with an independent random 16-byte salt, 64 MiB memory, three
iterations and parallelism one. Plaintext is never written.

The CLI stores only username/hash in private `operator-web-auth.json` (0600)
inside the owned state directory (0700), then passes them through the existing
private ARM parameter facility. Two allocated platform-vault secrets hold these
values. The app references exact secret versions. Never paste credentials/hashes
into Git, shell arguments, tracker comments, browser storage, images or logs.
Missing/invalid authentication configuration blocks provisioning/startup.

For replacement, the same command first verifies inventory/ownership, stops the
existing app through the Container Apps Stop API, and waits for confirmed
`runningStatus=Stopped` before prompting or changing configuration. It invalidates
the previous private configuration. Invalid/interrupted replacement leaves the
app stopped and requires successful reconfiguration; there is no old-configuration
fallback. Successful setup also leaves it stopped. Explicitly resume the normal
paid-confirmed deployment after reviewing the existing deployment gates.

Runtime deployment/repair also stops the existing Operator app before foundation
secret changes or application replacement. After successful runtime provisioning,
it explicitly starts the app. **Expect downtime and loss of all browser sessions.**
Single revision mode alone is *not* stop-before-start: Azure normally rolls
revisions. Do not bypass this lifecycle with direct ARM/portal updates, revision
restarts, alternate worker commands, scaling, or manually activated revisions.
See the [Stop API contract](https://learn.microsoft.com/en-us/rest/api/resource-manager/containerapps/container-apps/stop?view=rest-resource-manager-containerapps-2025-01-01).
Failed/ambiguous stop never permits replacement; reconcile explicitly.

## Deployment, ownership and teardown

- One additional **platform-owned Operator Container App**, not a sixth team
  workload/API Center capability or another agent identity. It shares the existing
  managed environment and locked image, serving assets/backend on its HTTPS origin.
- Its own managed identity has ACR Pull, secret-scoped readers for its two
  login secrets and isolated `subscription-operator-web`, and write-only admission
  to the platform accounting container. No team Blob roles, agent/context/CLI subscription secrets, model
  permission, Azure-management authority, CLI state mount or generic proxy.
  The distinct `operator-web` APIM caller can GET the Planner's narrow retained
  list/page/summary paths and the Assessor/Reviewer's run-bound Evidence Review
  projections and Reference Data assessed-run paths described below, and POST
  its narrow scenario-submission and explicit run-bound recovery/retry actions.
  It cannot use generic agent invocation, ordinary owner status, models or
  arbitrary URLs. It never copies the CLI Operator key.
- Exactly one container/process (`python -m citadel.operator.web`, one Uvicorn
  worker, no reload) and `minReplicas=maxReplicas=1`. The deployment verifier rejects
  extra environment authority, mounts, worker commands and scaling.
- `operatorInventory` records the app, separate identity, three secrets, scoped role
  assignments, immutable image and HTTPS origin. It joins the existing recursive
  private lifecycle inventory and deliberately manual, ownership-checked teardown.
  Manual teardown removes the exact accounting assignments before their custom
  role and platform group; it never broadens deletion to foreign roles.
  It also inventories accounting-only StorageV2 state, descriptors and marker roles.
  No new authentication database/service is provisioned. The additional
  warm 0.5-vCPU/1-GiB app, secrets and retained resources are billable; no automatic
  cleanup or spending cap is introduced.

Obtain the origin from private deployment outputs, not a credential-bearing URL.
Existing [deployment and manual teardown safeguards](operator.md) remain required.
Direct standalone Bicep deployment is not the supported update path.

## Shared login contract

All usernames share five failed attempts per five minutes, then a five-minute
nonextending cooldown; at most ten verifications per rolling minute and one
concurrent Argon2id verification. Requests/input sizes and body-reading time are
bounded. Unknown usernames perform the same verification as known usernames.
Errors are generic; forwarded IP headers are not used as identity. Temporary
login denial by an attacker is an accepted limitation of this shared cooldown.

One random 256-bit opaque session is active at a time; successful login replaces
the old session and CSRF context. Only the token hash is retained server-side.
The host-only `__Host-citadel-session` cookie is Secure, HttpOnly,
SameSite=Strict, Path=/, with no persistent lifetime. Expiry is exactly eight hours
after login, never extended by use. Every protected view checks it. Login POST
requires the configured HTTPS Origin; logout additionally requires the
session-bound CSRF value. GET never submits work or logs out. Responses are
`no-store`, with a restrictive same-origin script/connect CSP. The external
refresh module stores no credentials or authority in browser storage.

Logout revokes the session and clears its cookie. Restart discards all sessions
and throttle counters. **Restart-proof throttling and individual attribution are
not promised.** Tabs share the cookie, and another successful login displaces the
previous session. Authentication never cancels/replays runs; only an explicit
CSRF/origin-protected Run scenario POST can submit. Do not expose the container
port outside HTTPS ingress.
Only fixed authentication outcomes are logged, never usernames, passwords,
hashes, cookies or CSRF tokens.

## Reopening retained runs

Use **Earlier runs**, then select a run. Pages contain at most 20 summaries;
team links preserve selection. Initial loading observes once; subsequent reads
use the shared server cache. **Refresh observation** is explicit, origin/CSRF
protected and coalesced across tabs, with one request in flight per selection.
History/completed views never poll. Opening history invokes no submission,
model work or recovery.

Planner persists the index before admission, including partial/ambiguous CLI
submissions, and updates it during execution, never during observation.
The example index holds at most **256 runs**; reaching capacity blocks new
submissions rather than evicting unresolved history. It is not a scan of all
storage and does not backfill pre-index runs. Original owner/input bindings are
server-resolved. Missing source/profile/overlay/product bindings remain partial,
not inferred from a current bundle. Private draft content, receipts and paths
never leave the service through this allowlisted summary surface.

Each projection shows its last-successful observation time, not an artifact
modification time or an atomic cross-team snapshot. Refresh failure preserves
previous data with a **stale** warning. Denied, confirmed empty/missing, partial
history, unavailable source, exhausted allowance and unknown execution differ.
A saved running label is not fresh activity; no pulses are fabricated.

The connected deployment shares **16,384 observation** and **2,048 recovery-proof**
physical reads across runs/tabs/logins/restarts. Recovery is a separate explicit
control, never an observation side effect.
Protocol GETs and every actual supporting/team storage GET are separately prepaid
by confirmed conditional markers, including failed attempts. Descriptor checks
use leases, not recursive meter GETs. SDK/read retries are disabled; the whole
observation, including admission/downstream work, has a **30-second** deadline.
No refund, daily reset, refill, workflow-ticket use or privileged fallback exists.
Losing the in-memory cache restores no allowance or authority.

Bootstrap creates/leases the two accounting-only descriptors explicitly and
initializes `planner-operations/retained-runs-v1.json`. Missing recorded state
blocks repair; never delete markers, descriptors or index to obtain more reads.
Reference Data and the four agents receive marker-write-only roles on the
accounting container for subsequent projections, not reference-dataset writes.
Later team slices must use the same physical admission path for their own reads.

## Evidence Review: private drafts and exact releases

Select a retained run, then **Evidence Review**. The authenticated view
`/teams/evidence/runs/{run_id}` reads actual saved owner-service records,
including CLI-created runs. It shows exact draft versions, saved assessment
prose, completeness/gaps, provenance, original caveats and release outcomes.
Release Reviewer remains the approving agent: there is no human release gate.
Rejected release, unknown/incomplete reviewer execution and approved finding
are separate. Approval permits sharing, not completeness or airport safety;
an approved finding may report insufficient evidence.

Drafts remain **private Operator inspection**, not planning-workload authority.
The owner services allowlist fields before returning HTTP responses. Private
notes, prompts/model exchanges, reasoning, credentials, receipts and private
paths are never returned. New drafts save an explicit `assessment_prose`;
legacy drafts containing only private notes show unavailable prose, never
reinterpret those notes as an explanation.

Releases link their original exact draft and approved-finding versions.
An exact finding opens at
`/teams/evidence/runs/{run_id}/findings/{artifact_id}/versions/{version}`.
The view is an allowlisted projection with the original artifact reference/hash,
not rewritten artifact bytes. Exact private-draft links use the same pattern
with `drafts` in place of `findings`. Multi-record pages contain at most 20
entries with explicit next-page navigation. Correction versions are not
silently substituted. Original private draft hashes can legitimately differ
from the hash of the filtered projection.

Owner endpoints, reached only by the backend through APIM:

| Owner | Operator-only GET |
| --- | --- |
| Evidence Assessor | `/operator/runs/{run_id}/drafts` and `/drafts/page/{cursor}` |
| Evidence Assessor | `/operator/runs/{run_id}/drafts/{artifact_id}/versions/{version}` |
| Release Reviewer | `/operator/runs/{run_id}/releases` and `/releases/page/{cursor}` |
| Release Reviewer | `/operator/runs/{run_id}/findings/{artifact_id}/versions/{version}` |

Page suffixes are relative to `/operator/runs/{run_id}`. These endpoints
accept opaque identities only, never browser owner/source/path/receipt claims.
The owner verifies committed exact artifact and release linkages. New reviewer
admissions retain their exact draft binding; older rejected/incomplete reviews
without that binding stay partial. Missing records or storage remain explicitly
missing/partial/unavailable. Inspection neither regenerates products nor
submits/reviews work. A saved finding remains inspectable even if reviewer
execution did not finish; it does not manufacture run success or a brief.

Evidence projections use the same server-shared cache, in-flight coalescing,
deployment observation pool, separately charged protocol and physical storage
reads, zero retries and 30-second ceiling. Each owner panel has its own
last-success time and stale warning; they are not an atomic snapshot. Manual
Evidence Review refresh is origin/CSRF protected and preserves run selection.
Ordinary workload draft/findings authorization and workflow pools are unchanged.

## Inspecting assessed Reference Data

Select a retained run, then **Reference Data**. Expand an assessed airport to see
airport/country/region/runway raw values, parsed values and quality reasons;
original-source values and labelled synthetic-overlay values are separate.
Comparison-profile rules, exact source/profile/fixture hashes, source provenance
and only the assessed candidates' overlay differences are expandable. Completeness
is neither release approval nor accuracy, safety or operational suitability.
The source dataset is never edited. There is no candidate search, export or
arbitrary-path input.

The browser sends only the opaque run ID. The backend's isolated APIM credential
GETs `/reference-data/operator/reference/runs/{runId}`; the Reference Data owner
resolves candidate membership and exact provenance from Planner's retained index.
Planner saves this context after each returned assessment/release handoff, before
brief writing, so later failures preserve assessed candidates. Failed or ambiguous
handoffs do not invent candidate membership. Pre-slice history without saved
assessed bindings stays partial; no candidate-pool scan or historical backfill.
Until the last assessment binding is saved, the projection is explicitly partial,
even when some exact candidates are inspectable. A projection-recording failure
does not fail or replay execution; it leaves incomplete observation context.

Reference Data has an inventoried **read-only, ABAC path-restricted** grant for
`planner-operations/retained-runs-v1.json` only, with Blob listing explicitly denied.
It cannot read Planner's operation ledger or write Planner state. Its existing
reference-dataset role stays read-only, and its accounting role writes markers
only. This adds no UI team-data role or agent-draft authority. The additional
assignment appears in `operatorInventory.referenceContextAssignments` for manual
ownership-checked teardown.

The source is available only when the loaded, independently verified immutable
bundle matches **all** saved source/profile/fixture bindings. Missing historical
material is labelled unavailable/partial, never silently replaced with current
data. Loaded exact immutable source is an in-memory cache: it incurs no fictional
storage GET. Every actual supporting-index GET and backend protocol GET is
separately prepaid, including failures. The same 30-second deadline covers both
tiers, with no automatic retries or workflow-pool spending. All tabs share the
Reference Data projection cache keyed by deployment/run/projection/exact bindings.
Manual, origin/CSRF-protected refresh preserves selection and last-success data
with stale/exhausted/denied warnings. Source inspection never executes models,
creates artifacts or recovers runs.

## Exercise Planning: decisions and actual saved briefs

Select **Exercise Planning** for any retained run, including CLI-created runs:
`/teams/planning/runs/{run_id}`. Expand each saved candidate's evidence summary
for completeness, missing-field reasons, release outcome, selection/skipping
reason, original caveats and exact approved-finding reference. A replacement is
labelled separately from the original three candidates. Labelled overlays and
original source/profile/fixture versions and hashes are preserved.

The backend uses only these Operator-only APIM GET capabilities:

| Owner | Owner-relative path |
| --- | --- |
| Candidate Planner | `/operator/runs/{run_id}/decisions` |
| Briefing Author | `/operator/runs/{run_id}/brief` |

Planner resolves its immutable original submission and exact committed product.
During execution it saves public decision summaries alongside assessed membership
before requesting a brief, so Author failure does not hide completed assessments.
A complete saved Planner product remains independently inspectable if that
supporting context is incomplete. Older partial history without saved decisions
shows unknown decisions, never current-reference reassessment or index backfill.

Only Author's hash-bound saved product supplies the brief and **its exact saved
citations**. Planner commentary, a copied Planner brief, current findings and
private assessment drafts are never substitutes. Missing or ambiguous Author
history shows no brief. Citation links use the existing exact-version
[Evidence Review interface](#evidence-review-private-drafts-and-exact-releases);
deleted versions remain missing even if a newer release exists. The separately
labelled **Operator-only Evidence Review** link grants no draft authority to
Planning workloads.

Owner services allowlist public fields before HTTP serialization; no private
draft previews/prose, notes, prompts, hidden reasoning, credentials, workflow
receipts or private paths appear in Planning projections. Responses contain at
most 20 candidates and three brief citations, with a 256-KiB serialized limit.
The backend bounds streaming responses before caching. Owner reads and protocol
GETs spend the shared deployment observation pool, never workflow tickets.
Admission and downstream work share the 30-second ceiling with zero retries.
Each panel retains its own last-success time and stale warning.
The current-run execution header, visible-active refresh and explicit **Check and
recover** control remain available. Planning detail suppresses the generic
Planner brief copy: only the independently observed Author product is displayed.

Insufficient evidence is not an airport-safety judgment. Successful bounded-pool
exhaustion explains why no brief was requested; technical interruption remains
incomplete with unknown effects. Inspection never generates missing history,
submits work, refills allowances or establishes deployed enforcement.

## Local checks and claim limits

From the repository root in the installed pinned project environment, run the
full development/merge gate or the focused landing-page checks while iterating:

```sh
python -m unittest discover -s tests/unit -v
python -m unittest discover -s tests/unit -p 'test_operator_web*.py' -v
python -m unittest discover -s tests/unit -p 'test_observation.py' -v
python -m unittest discover -s tests/unit -p 'test_submission.py' -v
python -m unittest discover -s tests/unit -p 'test_browser_scenarios.py' -v
python -m unittest discover -s tests/unit -p 'test_scenario_summary.py' -v
node --test tests/client/*.test.mjs
python -m unittest discover -s tests/unit -p 'test_evidence_observation.py' -v
python -m unittest discover -s tests/unit -p 'test_reference_observation.py' -v
python -m unittest discover -s tests/unit -p 'test_planning_observation.py' -v
```

The full command is required before merging. See [testing.md](testing.md) for
discovery and the optional diagnostic suites. Legacy catalogue completion,
cloud passes, fresh-deployment proof and human narrative signoff are not
development/merge obligations; real deployment/readiness and manual teardown
safeguards above still apply when operating the app.

These are real local HTTP handlers/server-rendered presentation, fake-time
session/throttling checks, controlled cryptographic-concurrency checks, private
CLI/configuration checks and controlled management/deployment-contract checks.
They require no Azure credentials, cloud services, paid models, Docker, browser
runner or external data. Fixtures/credentials are explicitly test-only. There is
also a small dependency-free Node built-in test runner (Node 20+), covering the
actual client refresh scheduler with controlled visibility, terminal states,
coalescing and fake timers. It does not require browser automation or npm
installation. The hosted workflow runs these client units alongside Python units.

The offline results and local template compilation do **not** prove deployed
Azure enforcement, real rolling-update behavior, model quality or demo success.
No live Azure validation is claimed by this slice.
