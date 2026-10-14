# Open datasets for three-team Citadel scenarios

Research for [issue #3](https://github.com/JoranBergfeld/citadel-example/issues/3). Evidence checked **2026-10-14**. This is decision input for an implementation-ready, real-cloud demo specification, **not a domain selection or implementation**. No infrastructure, agents, or MCP server were created.

## Answer: ranked shortlist

| Rank | Candidate | Best reason to consider it | Principal tradeoff |
| --- | --- | --- | --- |
| **1** | **OurAirports reference data** | Actual relational CSVs, explicit public-domain data terms, small downloads, and a verified commit-pinned snapshot. Best low-friction reproducibility. | Airport reference data is not live operational truth. Workflows need clearly synthetic assessment/release records; exclude comments and free-text fields. |
| **2** | **Eurostat electricity/heat production, `nrg_bal_peh`** | Rich fuel/producer/country/year relationships, tiny bounded downloads, explicit statistical-data reuse terms. Strongest accounting/quality-versus-planning collaboration. | JSON-stat decoding, overlapping aggregate categories, nuanced zeros/flags, and mutable upstream responses. |
| **3** | **World Development Indicators (WDI), tightly selected indicators** | Very small relational country/indicator/year bundle, verified anonymous JSON and CSV ZIP, indicator-specific CC BY 4.0 evidence. | More analytical than operational; licensing must be checked per indicator, annual revisions require retained snapshots. Example electricity access is flat for these countries. |

This ordering prioritizes verifiable redistribution, reproducibility, ingestion simplicity, and coherent team boundaries—not a claim that aviation is the human's preferred domain. Eurostat may be preferable if multi-agent reconciliation is more important than immutable upstream downloads. WDI is preferable for a compact development-planning demonstration. No option provides genuine private organizational records: the sample must create synthetic work products to demonstrate access control honestly.

## Evidence method and scope

- Primary sources only: publishers' data dictionaries, official APIs/download responses, official reuse notices, and first-party repository/license files.
- Anonymous verification used fresh Python `urllib` requests without credentials, cookies, or API keys. Small API bundles were inspected in memory; large CSVs were opened only for their header/initial row. **No dataset files were stored or committed.**
- HTTP 200 alone is insufficient: response media type, metadata, actual headers/records, pagination, and API error envelopes were inspected. An initial WDI request including `EN.ATM.CO2E.PC` returned HTTP 200 with error `120`; it is **not** part of the recommended reproducible bundle.
- Sizes and hashes below are observations, not promises of future availability. Every proposed agent, tool, synthetic schema, access rule, threshold, or workflow below is a **demo design suggestion**, not a field or permission in the source dataset.
- “No personal data” is not an absolute guarantee from a sampled header. Selected statistical outputs are aggregates; selected airport fields describe infrastructure. Avoid contributor profiles, comments, source-site contact metadata, and unnecessary free text. These are not datasets advertised here as having been anonymized.

## 1. OurAirports

### License, attribution, access

The publisher explicitly releases **all data to the public domain**, permits reuse including a competing website, requests credit but does not require it, and gives no accuracy/fitness guarantee. This is not a claim of CC0: the repository's `LICENSE` is the **Unlicense**, while the data page separately establishes data terms. Redistribution and modification are permitted; provide voluntary attribution to OurAirports and link the source/version in outputs. Do not imply operational certification. [OA1][OA3]

The official download page points to the publisher's `davidmegginson/ourairports-data` repository. The checked snapshot is:

```text
a5a1ab8c3d9d57568c4bf9a7d398a23a60623830
commit time: 2026-10-14T01:53:14Z
```

Use `https://raw.githubusercontent.com/davidmegginson/ourairports-data/a5a1ab8c3d9d57568c4bf9a7d398a23a60623830/{filename}`. Anonymous GETs to `airports.csv`, `runways.csv`, `countries.csv`, `regions.csv`, `airport-frequencies.csv`, and `navaids.csv` returned **200** and CSV headers; no login was needed. The download page updates nightly, so do not use its moving links for deterministic runs. The page's displayed airport byte count differed slightly from the pinned commit; the following numbers come from the actual pinned response/repository. [OA1][OA4]

| Core file | Observed bytes | Relational role |
| --- | ---: | --- |
| `airports.csv` | 12,746,366 | Airport parent |
| `runways.csv` | 3,969,042 | Landing-surface children |
| `countries.csv` | 24,583 | Country dimension |
| `regions.csv` | 485,265 | Region dimension |
| **Core total** | **17,225,256** | Approximately 17.2 MB uncompressed |

Optional frequencies add 1,302,196 bytes; navaids add 1,524,946 bytes. Exclude `airport-comments.csv` altogether: it contains member comments, not necessary infrastructure evidence. [OA1][OA4]

### Actual schema and relationships

Verified headers and dictionary establish: [OA2][OA4]

- `airports`: `id`, `ident`, `type`, `name`, `latitude_deg`, `longitude_deg`, `elevation_ft`, `continent`, `iso_country`, `iso_region`, `municipality`, `scheduled_service`, `icao_code`, `iata_code`, `gps_code`, `local_code`, `home_link`, `wikipedia_link`, `keywords`.
- `runways`: `id`, `airport_ref`, `airport_ident`, `length_ft`, `width_ft`, `surface`, `lighted`, `closed`, and `le_*` / `he_*` runway-end identifiers, coordinates, elevations, true headings, and displaced thresholds.
- `countries`: `id`, `code`, `name`, `continent`, `wikipedia_link`, `keywords`.
- `regions`: `id`, `code`, `local_code`, `name`, `continent`, `iso_country`, `wikipedia_link`, `keywords`.
- Join `runways.airport_ident → airports.ident` (preferred interoperability key); `airport_ref → airports.id` is also documented. Join `airports.iso_country → countries.code`, `airports.iso_region → regions.code`, and `regions.iso_country → countries.code`.
- Optional `airport-frequencies.airport_ident → airports.ident`; its header contains `type`, `description`, `frequency_mhz`. Optional navaids include `associated_airport`, but do not assume every navaid belongs to an airport or blindly join navaid `ident` to airport `ident`.

For a compact fixture, propose filtering airports to `iso_country ∈ {NL, BE, DE}`, retaining only their runway children and referenced dimensions. Pin the filter and sort order. Ingest only necessary typed fields and identifiers, not comments, links, or keywords. Parse UTF-8 CSV, preserve nulls, distinguish airport `yes/no` from runway `1/0`, and preserve feet rather than silently treating lengths/elevations as metres. Runway surface codes are not a controlled vocabulary. Missing information must produce “insufficient evidence,” not fabricated suitability. The dictionary notes `length_ft` can include overrun/displaced-threshold portions: this demo cannot establish aircraft landing performance or operational safety. [OA2]

### Suggested teams, agents, and MCP value

| Team | Owned capabilities/data | Agents |
| --- | --- | --- |
| **A — Infrastructure Assurance** | Synthetic assessment drafts, evidence checks, versioned assessment releases | **Inventory assessor** checks runway evidence; **Release reviewer** validates and releases summaries |
| **B — Exercise Planning** | Synthetic candidate lists, exercise requirements, planning drafts | **Candidate planner** proposes airport comparisons; **Briefing author** composes a cited exercise briefing |
| **C — Reference Data** | Pinned airport/runway/dimension snapshot and read-only MCP server | No agent count is required for C; its owned product is the server |

C's proposed MCP tools `lookup_airport(ident)`, `list_runways(ident)`, and `search_airports(country, type)` provide actual relational lookup, source-unit normalization, missing-value handling, bounded results, and snapshot provenance. This is more useful than exposing raw CSV retrieval or wrapping an LLM response. The tools return only selected reference fields and source keys. Team A publishes approved synthetic assessment summaries through its own narrow agent capability, not C's raw-data tools.

**Collaborative scenarios:**

1. B's planner asks C for a bounded candidate list, asks A's assessor for evidence-based completeness checks, and passes released findings to B's briefing author. A's reviewer controls which conclusions become shareable.
2. A's assessor finds an unknown surface or absent width; A's reviewer releases an “insufficient evidence” result. B's planner requests another candidate through C instead of filling in a field.
3. An operator-triggered fixture replay compares the same candidates before/after a **synthetic assessment release**, demonstrating why a versioned approved result differs from an unpublished draft. The source CSV is unchanged.

**Meaningful restricted path:** B's briefing author can read an approved summary but cannot read A's synthetic `assessment-drafts` container or overwrite its `assessment-releases` container. It requests an unpublished rejection rationale or tries to “approve” an unresolved assessment to finish the briefing. The read/write must fail under B's own identity; it then uses A's review capability. The rationale is preservation of review ownership and release integrity, **not secrecy of public airport metadata**. These are fictional assessments, not real airport defects, closures, or safety advisories.

## 2. Eurostat `nrg_bal_peh`

### License, attribution, privacy boundary

Eurostat's official copyright notice explicitly authorizes reuse of **statistical data and metadata for commercial or non-commercial purposes with source acknowledgment**, subject to listed exceptions. Its CC BY 4.0 statement explicitly concerns editorial website content; do **not** casually relabel all statistical data as CC BY 4.0. The energy metadata also states free commercial/non-commercial reuse under Eurostat's copyright rules. [ES1][ES2]

The proposed fixture is **Germany and the Netherlands**, not excluded non-European-country data or restricted detailed trade data. The checked API identifies the source as `ESTAT`; no third-party ownership exception was stated in the checked response/energy metadata. Retain the reuse notice, dataset DOI/datacode, access date, and change disclaimer. Acknowledge customized subsets using the datacode link as instructed by Eurostat; state that transformations and synthetic scenarios are the demo author's responsibility and Eurostat is not responsible for them. No special written-license procedure is required for material outside the exceptions. This is an explicit reuse authorization, not a bespoke prohibition invented for Citadel. [ES1]

The published API returns **national aggregate energy quantities**, not enterprise/household records. Underlying reporting units can include enterprises or households; that does not make this output anonymized microdata. The metadata discusses actual statistical confidentiality and cautions that reported zeros can conflate unavailable, confidential, negligible, and real-zero inputs. Do not infer absent privacy concerns across every Eurostat product or attempt to reconstruct suppressed source records. [ES2]

### Download, versioning, and size

Verified anonymous JSON-stat download:

```text
https://ec.europa.eu/eurostat/api/dissemination/statistics/1.0/data/nrg_bal_peh?lang=en&geo=NL&geo=DE&time=2019&time=2020&unit=GWH&nrg_bal=GEP&nrg_bal=GEP_MAPE&nrg_bal=GEP_MAPCHP
```

- HTTP **200**, **18,107 bytes**; no login or token.
- Response SHA-256: `f8a5ba4c7758a4feaceb44fd9dac9d4e985a06f4f9eb0e541edf905008efbef1`.
- `updated = 2026-06-02T23:00:00+0200`.
- Dimensions `[freq,nrg_bal,siec,unit,geo,time]`, sizes `[1,3,75,1,2,2]`: 900 possible cells, **676 provided numeric values**, with separate status flags.
- Response structure identifier `NRG_BAL_PEH`, structure version `57.0`; DOI `10.2908/NRG_BAL_PEH`. Neither a structure version nor a DOI pins observation bytes. [ES3]

The API documentation supports public JSON-stat and SDMX downloads including bounded subsets, TSV, and CSV alternatives. Use the verified bounded JSON response, not a whole-database download. Preserve a permitted snapshot and SHA-256 manifest for reproducible demos: querying old years does **not** prevent revisions. This research inspected the response but has **not** preserved a downloadable immutable snapshot. Snapshot creation remains downstream work. [ES4]

### Actual schema and relationships

This is a statistical cube, not source-provided relational CSV tables. A normalized demo model can be derived without inventing business entities: an observation fact keyed by the six dimension codes, joined to dimension labels from `dimension.*.category.index/label`. Those normalized tables would be **ingestion outputs**. [ES3]

- `freq=A`: annual; `unit=GWH`: gigawatt-hour.
- `geo=DE/NL`: Germany/Netherlands; `time=2019/2020`.
- `nrg_bal=GEP`: gross electricity production; `GEP_MAPE`: main-activity producer, electricity-only; `GEP_MAPCHP`: main-activity producer, combined heat and power.
- Verified `siec` categories include `TOTAL`, `G3000` (natural gas), `RA000` (renewables and biofuels), `RA300` (wind), `RA420` (solar photovoltaic), and `N900H` (nuclear heat). Labels and index positions are supplied in the response.
- The response's `value` and `status` are indexed against dimension positions. Decode using **dimension order and sizes**, not JSON iteration order. Missing cells are not automatically zero; preserve flags.

Ingestion effort is low-to-medium: a small response but careful cube decoding and category semantics. Keep unit, producer class, and fuel consistent. Do not add `TOTAL` to its own fuel components or add aggregate renewables to overlapping individual renewable categories; do not assume the two selected producer subclasses exhaust total production. The published energy metadata is the source for accounting/zero caveats. [ES2][ES3]

### Suggested teams, agents, MCP, scenarios

| Team | Owned capabilities/data | Agents |
| --- | --- | --- |
| **A — Energy Evidence** | Synthetic reconciliation drafts and approved evidence releases | **Balance analyst** checks producer/fuel slices; **Quality reviewer** qualifies comparisons |
| **B — Transition Planning** | Synthetic planning assumptions and scenario drafts | **Scenario planner** compares specified national mixes; **Briefing author** writes a provenance-backed explanation |
| **C — Statistical Data** | Captured cube, classification dictionaries, provenance, read-only MCP | Publishes the data product/server |

C's proposed `production_slice(country, year, producer_class, fuel)` and `describe_category(dimension, code)` tools make dimensional joins, GWh units, status flags, and retrieval versions explicit. They disallow unbounded extraction and reject unknown category combinations; they do not claim to supply forecasts or real-time grid data.

**Collaborations:** (1) B requests a 2019/2020 comparison; A checks whether the selected categories overlap before B publishes it. (2) A identifies an unavailable/flagged cell, B requests a coarser supported comparison, and B's author carries the caveat into the briefing. (3) B runs a declared synthetic planning assumption against a released evidence version; A independently reviews the interpretation. Neither generation mix nor production changes establish emissions without additional emissions-factor evidence, which this fixture does not contain.

**Restricted path:** B's planner may request A's approved reconciliation summary but may not overwrite A's evidence release or read A's unpublished synthetic reviewer notes to bypass review. A's analyst likewise cannot read B's unpublished synthetic scenario-assumptions container; it receives a bounded, deliberately shared assumption summary. Demonstrate at least B's real cloud denial and successful approved alternative. This is ownership of sample work products, **not invented confidentiality of Eurostat national totals**.

## 3. World Development Indicators

### License and data selection

The checked indicator pages explicitly label **both** selected series `CC BY-4.0` in the HTML and embedded `License_Type` metadata:

- `EG.ELC.ACCS.ZS` — access to electricity (% of population), provider metadata identifies the World Bank/SDG 7.1.1 electrification dataset.
- `EG.FEC.RNEW.ZS` — renewable energy consumption (% of total final energy consumption), provider metadata identifies IEA Energy Statistics Data Browser. [WB1][WB2][WB5]

Use the World Bank-distributed series under their **indicator-specific published terms**, not a blanket assertion that all IEA data or all World Bank data is open. WDI's reuse summary permits copying, distributing, and adapting commercially or non-commercially under CC BY 4.0 **unless metadata says otherwise**, requires World Bank/provider attribution, includes mediation/arbitration terms, disclaims endorsement, and warns of third-party exceptions. Preserve links to the terms when facilitating access through MCP. Credit example: “The World Bank: World Development Indicators: World Bank (electricity access), International Energy Agency (renewable share); accessed 2026-10-14; subset/transformation by this demo.” Include license link and indicate modifications. [WB3][WB7]

The full-dataset terms link currently redirects to the World Bank's general terms page; the data-specific summary and each indicator's license metadata are therefore important retained evidence, not merely a generic website footer. General terms distinguish dataset-specific API terms. Recheck before redistributing a different indicator or obtaining data directly from another provider. [WB3][WB8]

These outputs are **country/year aggregates**, not people-level survey responses. Their underlying collection may use surveys; this is not proof that all underlying data lacks personal information or that the output underwent a particular anonymization technique. Do not download survey microdata.

### Actual download and schema

Verified fixture: `NLD;DEU;BEL`, years `2010:2020`, the two indicators above, source `2` (WDI). Anonymous requests returned **200** with actual data:

```text
https://api.worldbank.org/v2/country/NLD;DEU;BEL/indicator/EG.ELC.ACCS.ZS;EG.FEC.RNEW.ZS?source=2&date=2010:2020&format=json&per_page=1000
https://api.worldbank.org/v2/country/NLD;DEU;BEL/indicator/EG.ELC.ACCS.ZS;EG.FEC.RNEW.ZS?source=2&date=2010:2020&downloadformat=csv
https://api.worldbank.org/v2/country/NLD;DEU;BEL?format=json
https://api.worldbank.org/v2/indicator/EG.ELC.ACCS.ZS?format=json
https://api.worldbank.org/v2/indicator/EG.FEC.RNEW.ZS?format=json
```

The first response was **15,338 bytes**, 66 observation records, one page, `lastupdated=2026-10-08`, SHA-256 `14ff5648a592969bb43d966bc496ba87013de9ebb0d07ad472ba0f1e38b584b2`. Country metadata was 1,151 bytes. The CSV ZIP was 2,006 bytes compressed with three members totaling 3,708 bytes uncompressed: data (1,188), indicator metadata (1,019), country metadata (1,501). ZIP names include a generated suffix; do not hardcode it. [WB4][WB5][WB6]

Actual relationships: [WB4][WB5]

- JSON observations contain `indicator.id/value`, `country.id/value`, `countryiso3code`, `date`, `value`, `unit`, `obs_status`, `decimal`. Country `id` within observations is two-letter; country endpoint `id` is three-letter. Join **`countryiso3code → country.id`**, not mismatched IDs.
- Indicator metadata contains `id`, `name`, `unit`, `source`, `sourceNote`, `sourceOrganization`, `topics`. Join observation `indicator.id → indicator metadata.id`.
- Country metadata includes `id`, `iso2Code`, `name`, nested `region`, `adminregion`, `incomeLevel`, `lendingType`, plus capital-location metadata. Capital coordinates are not country centroids.
- CSV data has `Country Name`, `Country Code`, `Indicator Name`, `Indicator Code`, year columns `2010` through `2020`; it begins with source/update lines and blank lines before its real header. Indicator metadata uses `INDICATOR_CODE`; country metadata uses `Country Code`.

Low ingestion effort: validate API error envelopes, use pagination metadata rather than assuming all results fit, unpivot CSV years if choosing CSV, and preserve nulls. The observed JSON `unit` is empty despite percentage descriptions: use verified indicator definitions, not an invented unit. Country income/region metadata is a **current classification**, not automatically a historical classification for each observation year.

Pin exact URLs, response bytes/hashes, source/update date, metadata, license evidence, and filter/transform version. World Bank does not provide an immutable historical-data snapshot through these verified URLs; save a small licensed snapshot downstream. An update date is not a byte-level version pin. This research has not stored such a snapshot.

### Suggested teams, agents, MCP, scenarios

| Team | Owned capabilities/data | Agents |
| --- | --- | --- |
| **A — Development Evidence** | Synthetic indicator-comparability notes and approved analytical summaries | **Indicator analyst** checks definitions/trends; **Comparability reviewer** checks interpretation and coverage |
| **B — Portfolio Planning** | Fictional project ideas, assumptions, and draft planning priorities | **Portfolio planner** builds a declared scoring exercise; **Briefing author** explains assumptions and limitations |
| **C — Development Data** | Licensed snapshot, country/indicator metadata, provenance, read-only MCP | Publishes the server |

Proposed `indicator_series(country, indicator, start, end)` and `indicator_definition(indicator)` tools jointly return values, units/definitions, provider attribution, and snapshot hashes. C prevents mixing percentages with unlike denominators; it does not turn these national aggregates into project-level impact or investment advice.

**Collaborations:** (1) B asks for trend evidence; A checks whether renewable consumption share and electricity-access share answer different questions before B writes its briefing. (2) A observes that electricity access is saturated in the checked country fixture, and B explicitly declines to rank countries on an uninformative dimension instead of fabricating differentiation. (3) B revises a fictional weighting scheme and asks A for an independent explanation of sensitivity; all priorities remain simulated.

**Restricted path:** A's reviewer may inspect the deliberately shared weighting summary but may not read B's unpublished fictional project/negotiation drafts; B's planner may not change A's comparability release to hide a caveat. Cloud-denied reads/writes protect the simulated organizations' decision process, not the public World Bank figures. Any apparent commercial sensitivity belongs **only to synthetic demo records**.

## Shared real-cloud boundary requirements for a downstream spec

The following is a dataset-neutral suggested acceptance contract, not provisioned infrastructure:

1. One **Operator**, one Azure tenant/subscription, three team-owned disposable resource groups. A and B each own at least two agents. C owns its snapshot storage and MCP server. Resource groups express modeled ownership; they alone do not enforce all access boundaries.
2. Give each of the four agents its **own managed identity**; give C's server a separate managed identity. The Operator's deployment privileges must not be substituted for agent runtime credentials. Runtime identities receive no inherited subscription-wide data/control rights. Azure RBAC scopes inherit permissions from broader scopes. [AZ1]
3. Use separate storage accounts by team, with explicit private containers for synthetic drafts, approved releases, and raw/reference snapshots as appropriate. Give runtime identities only required data-plane rights at container/resource scope. Microsoft documents managed identities as supported principals and distinguishes blob data roles from management access. [AZ2]
4. C's server reads C's snapshot using its identity; caller identities receive only the intended MCP invocation permission, not C's storage credentials. Enforce server-side authenticated caller identity, token audience, and tool allowlist. **Azure storage RBAC does not automatically authorize MCP methods.** Selecting the exact hosting/auth stack and proving its enforcement belongs to the downstream specification.
5. A/B agents receive only required access to their own synthetic working containers. Approved cross-team results are shared through bounded owner-controlled capabilities or explicitly read-only release containers. Do not give agent identities storage account keys, shared secrets, role-assignment rights, or management capabilities that defeat the demonstration. Disable anonymous blob access and avoid shared-key fallback on sample stores.
6. **Positive test:** execute the full collaborating-agent/MCP path with correlated caller IDs, source hash, tool inputs, approved result version, and output citations.
7. **Negative test:** using the actual foreign agent's managed identity, try reading a named other-team synthetic draft and writing a named other-team release. Expect the appropriate cloud data-plane authorization failure (for Blob RBAC, HTTP 403 after a valid token/settled role propagation), no returned content, and an unchanged target. A DNS failure, missing file, prompt refusal, or Operator-identity attempt is not access-control proof.
8. **Authorized control:** the owning agent reads the same existing synthetic draft with its own identity; the approved cross-team capability succeeds afterward. Capture status, scope/principal identifiers, and correlation IDs without secrets or denied contents. Also prove that the MCP server does not relay arbitrary URLs/container paths into privileged reads.
9. The Operator's sample-fixture setup may place synthetic canaries in private containers; never use personal records, actual negotiations, operational defects, or production cloud resources. All writes/deletes affect only disposable sample resources. Published research contains none of these runtime data.
10. Open-data licensing and runtime authority are separate. The sample must **not** claim that Azure denial makes open facts confidential or revokes licensed reuse. Keep publisher data obtainable under its actual terms; demonstrate ownership on synthetic work products and integrity of approved releases. For CC BY material, do not add legal restrictions or license-defeating technological measures to redistributed material. [WB7]

## Reproducibility and remaining decisions

Minimum future fixture manifest: source URL, dataset/version/commit, retrieval UTC, original media type/byte count, SHA-256 of retained bytes, applicable reuse/attribution evidence, subset rule, retained schema, transformation version, sorted output hash, and explicit separation of synthetic tables. Check schema and provenance before ingestion; do not silently refresh a pinned fixture.

**Already verified:** anonymous source access and actual structures; OurAirports commit pin; bounded Eurostat/WDI response sizes and hashes; publisher license/reuse evidence; plausible four-agent/third-team MCP divisions.

**Not verified or implemented:** full-file checksum/foreign-key validation for OurAirports; an immutable redistributed Eurostat/WDI fixture; absence of personal content in every source row; deployed identities, Azure denial, MCP authorization, provider quotas, cloud costs, or any agent framework. No claim that these cloud acceptance tests passed.

**Human/downstream choices remain:** domain/dataset; whether source-derived aggregates and synthetic work products are acceptable; final scenario thresholds and agent framework; exact hosting/auth services; snapshot-retention/distribution mechanism; costs and deployment/teardown acceptance. Dataset selection must precede a final implementation-ready spec.

### Investigated but not ranked

- **NOAA GHCN-Daily:** real station/inventory/day relationships and anonymous `.dly` access were verified; e.g. Phoenix `USW00023183.dly` was 3,985,740 bytes, station metadata 11,441,354, inventory 36,395,016. Live version was `3.35-upd-2026101217`. Official metadata requires dataset/article citations, supplies disclaimers, and warns observations are not homogenized for all climate-change analyses. Source files roll forward; no immutable snapshot was established. The metadata inspected did not state a standard blanket redistribution license for all constituent sources; a general **NWS** public-domain statement is not sufficient evidence for this **NCEI** compilation. Consequently it was not promoted above candidates with explicit dataset reuse evidence. The README's `ghcnd-all.tar.gz` spelling returned 404; the live index lists `ghcnd_all.tar.gz` at 3,822,187,469 bytes. [N1][N2][N3]
- **Open Power System Data time series, 2020-10-06:** versioned hourly CSV/schema and anonymous access were verified (130,339,665 bytes; published resource hash present). Its inspected package lacks a `licenses` entry; the page footer licenses **text**, not clearly the underlying data. The project's own legal discussion warns that free access does not establish reuse rights. Further upstream licensing work is needed; it is not a verified-open-license recommendation here. Household data was not used. [P1][P2]
- Kaggle was unnecessary: the shortlist has publisher-controlled, no-login downloads, avoiding an extra account-dependent distribution layer.

## Primary sources

- **[OA1]** OurAirports, downloads and explicit public-domain data terms: https://ourairports.com/data/
- **[OA2]** OurAirports, field dictionary and foreign-key/unit descriptions: https://ourairports.com/help/data-dictionary.html
- **[OA3]** Publisher repository license at the checked commit: https://github.com/davidmegginson/ourairports-data/blob/a5a1ab8c3d9d57568c4bf9a7d398a23a60623830/LICENSE
- **[OA4]** Publisher data snapshot, actual CSV headers and file sizes: https://github.com/davidmegginson/ourairports-data/tree/a5a1ab8c3d9d57568c4bf9a7d398a23a60623830
- **[ES1]** Eurostat, statistical-data reuse authorization, exceptions, attribution: https://ec.europa.eu/eurostat/web/main/help/copyright-notice
- **[ES2]** Eurostat, energy balance metadata, methodology, confidentiality and zero caveats (particularly sections 3, 6, 7): https://ec.europa.eu/eurostat/cache/metadata/en/nrg_bal_esms.htm
- **[ES3]** Eurostat, observed bounded API response: https://ec.europa.eu/eurostat/api/dissemination/statistics/1.0/data/nrg_bal_peh?lang=en&geo=NL&geo=DE&time=2019&time=2020&unit=GWH&nrg_bal=GEP&nrg_bal=GEP_MAPE&nrg_bal=GEP_MAPCHP
- **[ES4]** Eurostat, public APIs and downloadable formats: https://ec.europa.eu/eurostat/web/user-guides/data-browser/api-data-access/api-getting-started
- **[WB1]** World Bank, selected electricity-access definition and indicator-specific license (HTML/embedded metadata): https://data.worldbank.org/indicator/EG.ELC.ACCS.ZS
- **[WB2]** World Bank, selected renewable-consumption definition and indicator-specific license (HTML/embedded metadata): https://data.worldbank.org/indicator/EG.FEC.RNEW.ZS
- **[WB3]** World Bank, data-specific reuse summary, attribution, additional terms and exceptions: https://data.worldbank.org/summary-terms-of-use
- **[WB4]** World Bank, actual bounded observation response: https://api.worldbank.org/v2/country/NLD;DEU;BEL/indicator/EG.ELC.ACCS.ZS;EG.FEC.RNEW.ZS?source=2&date=2010:2020&format=json&per_page=1000
- **[WB5]** World Bank, actual metadata: https://api.worldbank.org/v2/country/NLD;DEU;BEL?format=json ; https://api.worldbank.org/v2/indicator/EG.ELC.ACCS.ZS?format=json ; https://api.worldbank.org/v2/indicator/EG.FEC.RNEW.ZS?format=json
- **[WB6]** World Bank, API argument, paging, multiple-indicator and download documentation: https://datahelpdesk.worldbank.org/knowledgebase/articles/898581-api-basic-call-structures
- **[WB7]** Creative Commons, BY 4.0 attribution/change and no-additional-restrictions requirements: https://creativecommons.org/licenses/by/4.0/
- **[WB8]** World Bank, general terms to which the dataset full-terms link redirected during research: https://www.worldbank.org/ext/en/legal/terms-conditions
- **[AZ1]** Microsoft, Azure RBAC scopes and inheritance: https://learn.microsoft.com/en-us/azure/role-based-access-control/scope-overview
- **[AZ2]** Microsoft, managed identities, data roles and container/resource scoping for blob data access: https://learn.microsoft.com/en-us/azure/storage/blobs/assign-azure-role-data-access
- **[N1]** NOAA NCEI, GHCN-Daily schema and element/quality/unit documentation: https://www.ncei.noaa.gov/pub/data/ghcn/daily/readme.txt
- **[N2]** NOAA NCEI, dataset-specific legal/use metadata: https://www.ncei.noaa.gov/access/metadata/landing-page/bin/iso?id=gov.noaa.ncdc:C00861
- **[N3]** NOAA NCEI, live archive index/version and station download: https://www.ncei.noaa.gov/pub/data/ghcn/daily/ ; https://www.ncei.noaa.gov/pub/data/ghcn/daily/ghcnd-version.txt ; https://www.ncei.noaa.gov/pub/data/ghcn/daily/all/USW00023183.dly
- **[P1]** Open Power System Data, time-series package metadata: https://data.open-power-system-data.org/time_series/2020-10-06/datapackage.json
- **[P2]** Open Power System Data, legal explanation distinguishing availability from reuse rights: https://open-power-system-data.org/legal/
