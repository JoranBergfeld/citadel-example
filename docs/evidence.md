# Reference evidence and local fixture gate

Implements the pure evidence/preparation boundary from [issue 14](https://github.com/JoranBergfeld/citadel-example/issues/14)
and its [canonical contract](https://github.com/JoranBergfeld/citadel-example/issues/10#issuecomment-6169237188).
No MCP transport, agents, approval authority, runtime storage, Azure provisioning, or paid operations are implemented here.
Use the interpreter selected in [stack.md](stack.md); the evidence package needs only the standard library.

## Local commands

Run from the repository root. Set `DATA` and `BUNDLE` to operator-owned directories **outside Git**.
Commands never select a newer source or accept a source URL:

```bash
export PYTHONPATH=src
python -m citadel.evidence acquire --source-dir "$DATA"
python -m citadel.evidence gate --source-dir "$DATA"
python -m citadel.evidence prepare --source-dir "$DATA" --output-dir "$BUNDLE"
python -m citadel.evidence verify --bundle-dir "$BUNDLE"
python -m citadel.evidence verify --bundle-dir "$BUNDLE" --fixture missing-width-replacement
python -m citadel.evidence verify --bundle-dir "$BUNDLE" --fixture no-alternative
```

`acquire` uses anonymous HTTPS with a 30-second timeout, fixed URLs, byte limits and SHA-256 checks.
It retains four exact CSV files, the pinned `LICENSE`, and an immutable `source-manifest.json`.
Existing matching files are reused without a network refresh; different bytes fail, never overwrite.
Only `acquire` performs network access. Locally retained files can be passed directly to `gate`.
A recorded source manifest, when present, is validated rather than silently replaced.

`gate` emits the complete first-20 report and exits 0 on at least four complete candidates, 2 if
the precondition is not met. Source/service/integrity errors exit 1 and are not missing evidence.
`prepare` evaluates the gate before publishing a bundle. A failing gate raises
`fixture_gate_failed`: stop dependent work and obtain approval to reopen selection. Never widen
the pool, repair source data, or invent completeness.

`verify` checks every manifest and artifact before returning deterministic evidence-only candidate
selection. `bounded_pool_exhausted` is a successful evidence outcome, not a service failure. It
does not generalize beyond this pool.

## Public Python boundary

```python
from citadel.evidence import EvidenceError, ReferenceData
from citadel.evidence.preparation import prepare_bundle
from citadel.evidence.source import acquire_source

data = ReferenceData.from_directory(source_directory)
data = ReferenceData.from_bundle(bundle_directory, fixture="base-source")
data.search_airports()  # defaults: NL/BE/DE, small/medium/large, limit 20
data.lookup_airport("EBAM")
data.list_runways("EBAM")
assessment = data.assess_airport("EBAM")
gate = data.fixture_gate()
fixtures = data.fixture_manifests()
replacement = data.with_overlay(fixtures["missing-width-replacement"])
selection = replacement.select_candidates()
```

`ReferenceData.from_rows(airports=..., runways=..., countries=..., regions=...)` accepts scoped
allowlisted raw string records for deterministic tests and callers with explicit in-memory data.
Its provenance says `supplied_rows` with a content hash and **no claimed snapshot**. Only verified
disk inputs receive pinned-source provenance. Optional `schema_version`, `profile_version`, and
`fixture_version` are strictly integer 1, not booleans, strings, or implicit latest.

Only these three methods are intended as Reference Data MCP tools:

| Method | Contract |
| --- | --- |
| `search_airports(**arguments)` | Only `countries`, `types`, `limit`; filters nonempty, unique, allowlisted; integer limit 1–20. Defaults apply only to omitted fields. Country-code/identifier sort, no pagination. Valid empty search succeeds. |
| `lookup_airport(ident)` | One exact case-sensitive identifier, 1–64 ASCII letters/digits/hyphens/underscores; returns allowlisted airport plus resolved country/region. |
| `list_runways(ident)` | Same identifier rule; numeric runway-ID ordering; more than 50 fails without truncation. Closed runways remain visible. |

Successful responses have `provenance`; tool errors expose it on `EvidenceError.provenance`.
`EvidenceError.code` distinguishes `invalid_input`, `not_found`, `unsupported_version`,
`result_limit`, `data_integrity`, `forbidden`, `temporary_unavailability`, and fixture setup's
`fixture_gate_failed`. Acquisition/loading failures before validation have null provenance, not
a false claim of verified data. Authorization is a separate transport/runtime responsibility.

Each field is `{raw, parsed, quality_reasons}`. Blank parsed values are null. Invalid dimensions
are not zero; unknown flags are not false. Dimensions remain positive finite feet. Only exact
source `0`/`1` flags are recognized. Coordinates respect inclusive latitude/longitude bounds.
Unknown surface markers are case-insensitive; all other nonblank surface text remains literal,
without a paved/unpaved classification. Non-allowlisted columns never enter prepared evidence.
Missing columns/structural keys and duplicate IDs/identifiers/codes are integrity errors, not gaps.
Runway joins cross-check both airport identifier and ID; country/region relationships must resolve.
The loader checks full-source duplicate keys and runway joins before geographic selection.

Completeness examines the entire airport comparison: identity/name/type, valid coordinates,
resolved dimensions, at least one recorded-open runway, no unknown closed flags, and length,
width, surface and lighting on **every** recorded-open runway. Closed-runway dimensions do not
invalidate completeness. Missing evidence succeeds with field-specific gaps and caveats.
`select_candidates()` assesses each ordered pool member at most once, stopping at three complete
candidates or explicit bounded-pool exhaustion. This pure helper neither obtains nor implies release.

## Versioned fixtures and immutable manifests

`fixture_manifests()` requires four initially complete candidates and unchanged base-source data.
The replacement overlay nulls width on the lowest-ID recorded-open runway of the first complete
pool member. The no-alternative overlay does the same for every initially complete pool member.
Initially insufficient members remain insufficient. Overlays identify every record, field and
original source value; an overlay field carries `raw: null`, `parsed: null`, original `source_raw`,
and `synthetic_missing_width`. Every tool/assessment retains the overlay identity and hash.
Applying an altered, differently bound, unknown-version or stacked overlay fails explicitly.

Bundles contain:

- `source-manifest.json`: fixed commit, file URLs/SHA-256/byte sizes, public-domain terms,
  pinned Unlicense evidence and attribution.
- `profile-manifest.json`: versioned allowlists, comparison rules, bounds and mandatory caveats.
- `reference-data.json`: only allowlisted NL/BE/DE records and referenced dimensions.
- `base-source-v1.json`, `missing-width-replacement-v1.json`, `no-alternative-v1.json`:
  source/profile-bound fixture manifests with explicit mutations.
- `gate-report.json`: exact original pool and both overlay selection outcomes.
- `bundle-manifest.json`: exact filenames and SHA-256 hashes, published last.

JSON hashes use sorted keys, compact separators, UTF-8, non-ASCII characters unescaped, and no
nonfinite JSON numbers. Bundle files use these exact bytes. Duplicate JSON keys are rejected.
The derived allowlisted rows have an independently pinned transformation-v1 hash, so changing
both data and its local manifest cannot fabricate pinned-source provenance.
Writers publish complete files without replacing existing ones; byte-identical reruns reuse them.
Any changed artifact conflicts. Incomplete bundles cannot pass verification. Retain failed output
for diagnosis; use a new operator-selected directory for repair rather than silently overwriting.

## Shareable projection

`data.shareable_projection(draft)` rechecks structured evidence against that exact data/profile/
fixture before projecting. Required fields:

```text
artifact_id, version, schema_version, run_id, operation_id, airport_ident,
evidence, classification, gap_reasons, caveats, provenance
```

`version` is a positive integer; schema is v1. `artifact_id`, run/operation IDs and airport
identifier use the 1–64 ASCII identifier syntax. Evidence/classification/gaps/caveats/provenance
must exactly match `assess_airport()`. Unknown structured claims fail. Optional `private_notes`,
`prompts`, `reviewer_deliberation`, `credentials`, and `storage_path` are excluded from projection.
Do not put credentials in drafts; these exclusions are defense-in-depth, not secret storage.

The projection contains evidence, completeness, all gaps/caveats, provenance, run/operation and
airport IDs, and an opaque exact draft ID/version/canonical SHA-256 reference. Private material
contributes only to that opaque hash. Mandatory caveats are fictional comparison, not operational
suitability, unverified source accuracy, and recorded length not being usable landing distance.
Complete and insufficient assessments can be projected; neither is approved by this helper.
Reviewer identity, immutable release/version concurrency, approval authority, prose review and
durable publication remain the operation/release module's responsibility.

## Verification

The development/merge gate is the flat offline unit suite in
[testing.md](testing.md), run in the installed pinned project environment:

```sh
python -m unittest discover -s tests/unit -v
python -m unittest discover -s tests/unit -p 'test_evidence.py' -v
```

The focused command is for iteration. The broader evidence suite and retained
external-data checks below are **opt-in diagnostics**, not an additional gate.
They do not require new downloads when the pinned snapshot is already retained;
`acquire` remains a separate explicit network action.

```bash
PYTHONPATH=src python -m unittest discover -s tests/evidence -v
CITADEL_EVIDENCE_DATA="$DATA" PYTHONPATH=src \
  python -m unittest discover -s tests/evidence -v
```

Without retained source, three genuine-snapshot tests are explicitly skipped; this does not prove
the dataset gate. With the exact source, all tests run without network access. Acquisition tests
mock only the HTTP boundary using actual retained bytes. Test scratch directories are unique,
inside `tests/evidence`, and cleaned after each test.

Verified snapshot `a5a1ab8c3d9d57568c4bf9a7d398a23a60623830`: 20 pool members, **16 complete**.
Base selection: `BE-0052`, `EBAM`, `EBAR`. Replacement: `EBAM`, `EBAR`, `EBAW`.
No-alternative: zero complete, twenty assessed, bounded pool exhausted. These are reference-data
completeness results, not airport safety or operational assessments.
