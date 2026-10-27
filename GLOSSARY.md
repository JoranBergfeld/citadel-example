# Citadel Sample

A sample organization demonstrating governed collaboration among teams and their agents.

## Language

**Team**:
An organizational group that owns agents, data, or shared capabilities and has a distinct boundary for access to them. A team need not own agents.
_Avoid_: Agent pool, individual user

**Cross-team collaboration**:
An exchange between agents owned by different teams to fulfill a shared use case, subject to each team's access rules.
_Avoid_: Unrestricted sharing

**Operator**:
The single human who deploys and runs the sample on behalf of its modeled teams.
_Avoid_: Team member identity

**Reference Data**:
The team that owns the shared airport reference dataset and its read-only lookup capability.
_Avoid_: Live airport operations

**Evidence Review**:
The team that owns checks of reference-data completeness, private assessment drafts, and approved findings.
_Avoid_: Airport safety authority, Infrastructure Assurance

**Exercise Planning**:
The team that owns candidate comparisons and fictional exercise briefs based on approved findings.
_Avoid_: Flight planning, operational dispatch

**Approved finding**:
A versioned conclusion about reference-data completeness released by Evidence Review's Release Reviewer. Approval permits sharing; it does not establish airport safety or remove missing-evidence caveats.
_Avoid_: Safety certification, operational clearance

**Insufficient evidence**:
A finding that the available reference data cannot support a requested comparison without unresolved gaps. It is not a negative judgment about the airport.
_Avoid_: Unsafe airport, failed airport

**Comparison profile**:
A fixed set of reference-data attributes used for a fictional airport comparison. It describes the evidence being compared, not operational suitability.
_Avoid_: Suitability criteria, safety score

**Complete evidence**:
Reference data that satisfies the completeness rules of a comparison profile. Completeness does not establish accuracy, airport safety, or permission to share a finding.
_Avoid_: Certified airport, operational readiness

**Assessment draft**:
An unpublished, versioned Evidence Review assessment of reference-data completeness. Release approval applies to one exact draft version; corrections produce a new version.
_Avoid_: Approved finding, provisional clearance
