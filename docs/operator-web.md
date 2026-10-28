# Protected Operator application and retained runs

The hosted Operator application is not a scenario playback. It opens
on Comparison, Replacement and Exhaustion descriptions with expected outcomes and
linked Reference Data, Evidence Review and Exercise Planning perspectives. Choose
one scenario and use **Run scenario** to start the actual deterministic workflow.
The current run becomes the primary view; Earlier runs reopens retained Planner
observations. CLI submissions enter the same durable Planner index and share
global admission with browser submissions.
There is no simulated production mode or automatic submission after login.

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
last-known, not live activity. No simulated stages, pulses or percentages exist.
Manual/automatic requests share one in-flight backend read across tabs; automatic
requests reuse the latest attempt for 15 seconds, including failed attempts.
Authentication and explicit user submission remain separate from observation.

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
  list/page/summary paths and POST its narrow scenario-submission action. It cannot
  use generic agent invocation, owner status, models or arbitrary URLs.
  It never copies the CLI Operator key.
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
