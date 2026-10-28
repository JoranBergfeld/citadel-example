# Offline unit tests

From the repository root, in the installed project's pinned Python environment:

```sh
python -m unittest discover -s tests/unit -v
```

For focused feedback, replace `<area>` with a filename stem below:

```sh
python -m unittest discover -s tests/unit -p 'test_<area>.py' -v
```

For example:

```sh
python -m unittest discover -s tests/unit -p 'test_candidate_planner.py' -v
```

The explicit start directory matters: root `tests` discovery can report a
misleading zero-test success for the older nested suites. Unit test modules are
flat; `fixtures/` holds labelled, fictional reference rows and a canned model
response, not downloaded source data or actual inference.

These commands require only the already-installed project dependencies. No Azure
deployment, credentials, Docker, real model, network, retained dataset,
telemetry collection or production-duration waits are needed. Ambient cloud
configuration does not select live tests or transports.

## Boundaries and focused areas

| Area | Behavior exercised |
| --- | --- |
| `candidate_planner` | Public `Runtime.accept`/status/task result: complete selection, missing-width replacement, rejection/exhaustion without author dispatch, model outage without replay. |
| `evidence_assessor` | Actual private draft persistence and exact reviewer input, rejection propagation and failure before draft/release. |
| `release_reviewer` | Exact requested immutable version rather than latest draft, hash denial, independent recheck rejection and private-field exclusion from actual saved findings. |
| `briefing_author` | Actual saved narrative/citations/caveats, duplicate-reference denial and approved-but-incomplete evidence denial before inference. |
| `evidence` | Pure completeness, raw/parsed values, source/overlay provenance, bounded candidates and shareable-projection rules. |
| `operations`, `completion` | Conditional immutable approval, exact versions, privacy, ownership, lost-response reconciliation, atomic product/result publication and closed receipts. |
| `accounting`, `read_tickets` | Finite inherited budgets/deadlines, charged retries, physical reads, shared-store concurrency/reconstruction/exhaustion and ambiguous marker admission refusing dispatch. |
| `peer_reads` | Actual gateway-client exact-version/hash checks through controlled HTTP; a failed finding read spends its allowance and cannot dispatch again after exhaustion. |
| `recovery`, `operator_quiescence` | Fencing, no replay/refund, restricted explicit retry, immutable deadlines and quiescent partial work staying incomplete. |
| `gateway`, `startup` | Local ASGI authorization/signature/path denials and explicit workload configuration/capability validation. |

Agent tests create **one runtime per case**. `agent_fixtures.py` supplies controlled
peer-service responses, `MemoryLedger`, a fake clock and a real `GovernedModel`
with HTTPX2's `MockTransport`. Assertions concern the agent's decisions,
saved products and denied boundary calls, not just fixture responses. Peer
responses do not execute another agent; they do not prove child-protocol or
delegated-accounting wiring. The separate shared-rule and local handler tests
exercise those owning boundaries where selected.

Private-file reads in quiescence validation are controlled filesystem responses;
the real proof validator and CLI refusal run without opening Operator state.
`Accounting` accepts an optional injected `sleep`; `runs_quiescent` accepts an
optional `clock`. Production defaults remain ordinary asyncio sleep/wall time.

## Migration and claim limits

The isolated evidence, operation, gateway, completion, startup, recovery,
read-ticket and Operator proof checks were relocated by behavior. Optional
protocol/SDK diagnostics reuse the relocated signing/configuration/recovery
helpers; the unit gate imports no optional test suite or whole-flow harness.
Useful broader diagnostics remain intact and are not dependencies of these
commands.

Passing units establishes behavior under controlled inputs only. It proves
neither deployed Azure/APIM enforcement, real model quality, cloud
reproducibility, telemetry delivery nor actual demo success. Historical cloud
results are unchanged. Broader workflow/guide retirement and development/merge
job alignment belong to ticket #37, not this gate-establishment change.
