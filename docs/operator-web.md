# Protected Operator application and retained runs

The hosted Operator application is not a scenario playback. It opens
on Comparison, Replacement and Exhaustion descriptions with expected outcomes and
linked Reference Data, Evidence Review and Exercise Planning perspectives. **Run
scenario is disabled**. Earlier runs lists and reopens retained Planner observations.
No browser execution, recovery or model calls are implemented here. Continue using
the CLI for actual runs; its submissions enter the same durable Planner index.
There is no simulated production mode or automatic submission after login.

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
  The distinct `operator-web` APIM caller can only GET the Planner's narrow retained
  list/page/summary and Reference Data assessed-run paths. It cannot invoke agents, owner status, findings, models,
  arbitrary URLs or recovery. It never copies the CLI Operator key.
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
`no-store`, with a restrictive CSP; no frontend JavaScript/storage is used.

Logout revokes the session and clears its cookie. Restart discards all sessions
and throttle counters. **Restart-proof throttling and individual attribution are
not promised.** Tabs share the cookie, and another successful login displaces the
previous session. Authentication never cancels/replays runs; the shell has no
workflow dispatch path. Do not expose the container port outside HTTPS ingress.
Only fixed authentication outcomes are logged, never usernames, passwords,
hashes, cookies or CSRF tokens.

## Reopening retained runs

Use **Earlier runs**, then select a run. Pages contain at most 20 summaries;
team links preserve selection. Initial loading observes once; subsequent reads
use the shared server cache. **Refresh observation** is explicit, origin/CSRF
protected and coalesced across tabs, with one request in flight per selection.
History/completed views never poll. No JavaScript, client storage, submission,
model work or recovery is involved.

Planner persists the index before admission, including partial/ambiguous CLI
submissions, and updates it during execution, never during observation.
The example index holds at most **256 runs**; reaching capacity blocks new
submissions rather than evicting unresolved history. It is not a scan of all
storage and does not backfill pre-index runs. Original owner/input bindings are
server-resolved. Missing source/profile/overlay/product bindings remain partial,
not inferred from a current bundle. Private products, receipts and paths never
leave the service through this summary surface.

Each projection shows its last-successful observation time, not an artifact
modification time or an atomic cross-team snapshot. Refresh failure preserves
previous data with a **stale** warning. Denied, confirmed empty/missing, partial
history, unavailable source, exhausted allowance and unknown execution differ.
A saved running label is not fresh activity; no pulses are fabricated.

The connected deployment shares **16,384 observation** and **2,048 recovery-proof**
physical reads across runs/tabs/logins/restarts. Recovery is not exposed yet.
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

## Local checks and claim limits

From the repository root in the installed pinned project environment, run the
full development/merge gate or the focused landing-page checks while iterating:

```sh
python -m unittest discover -s tests/unit -v
python -m unittest discover -s tests/unit -p 'test_operator_web*.py' -v
python -m unittest discover -s tests/unit -p 'test_observation.py' -v
python -m unittest discover -s tests/unit -p 'test_reference_observation.py' -v
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
no browser-only logic requiring a separate client runner.

The offline results and local template compilation do **not** prove deployed
Azure enforcement, real rolling-update behavior, model quality or demo success.
No live Azure validation is claimed by this slice.
