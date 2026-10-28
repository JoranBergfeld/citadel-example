# Protected Operator landing page

The hosted Operator application is a **shell**, not a scenario playback. It opens
on Comparison, Replacement and Exhaustion descriptions with expected outcomes and
linked Reference Data, Evidence Review and Exercise Planning perspectives. **Run
scenario is disabled**. No execution, observation, recovery, model calls, history
or team-data reads are implemented here. Continue using the CLI for actual runs.
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
- Its own managed identity has only ACR Pull and secret-scoped readers for its two
  login secrets. No team Blob roles, agent/context/CLI subscription secrets, model
  permission, Azure-management authority, CLI state mount or generic proxy.
  It has no APIM caller credential/actions yet; later observation/control slices
  must allocate distinct narrow authority rather than copy the CLI Operator key.
- Exactly one container/process (`python -m citadel.operator.web`, one Uvicorn
  worker, no reload) and `minReplicas=maxReplicas=1`. The deployment verifier rejects
  extra environment authority, mounts, worker commands and scaling.
- `operatorInventory` records the app, separate identity, two secrets, scoped role
  assignments, immutable image and HTTPS origin. It joins the existing recursive
  private lifecycle inventory and deliberately manual, ownership-checked teardown.
  No new authentication database/supporting service is provisioned. The additional
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

## Local checks and claim limits

In the installed project environment, run:

```sh
python -m unittest discover -s tests/unit -p 'test_operator_web*.py' -v
```

These are real local HTTP handlers/server-rendered presentation, fake-time
session/throttling checks, controlled cryptographic-concurrency checks, private
CLI/configuration checks and controlled management/deployment-contract checks.
They require no Azure credentials, cloud services, paid models, Docker, browser
runner or external data. Fixtures/credentials are explicitly test-only. There is
no browser-only logic requiring a separate client runner.

The offline results and local template compilation do **not** prove deployed
Azure enforcement, real rolling-update behavior, model quality or demo success.
No live Azure validation is claimed by this slice.
