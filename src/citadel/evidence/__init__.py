"""Deterministic reference-data evidence for fictional comparisons."""

import math
import re
from copy import deepcopy
from functools import wraps
from collections.abc import Mapping

from .manifests import canonical_bytes, profile_manifest, sha256

COUNTRIES = ("BE", "DE", "NL")
TYPES = ("small_airport", "medium_airport", "large_airport")
AIRPORT_FIELDS = (
    "id", "ident", "name", "type", "latitude_deg", "longitude_deg",
    "iso_country", "iso_region",
)
RUNWAY_FIELDS = (
    "id", "airport_ref", "airport_ident", "length_ft", "width_ft",
    "surface", "lighted", "closed",
)
COUNTRY_FIELDS = ("code", "name")
REGION_FIELDS = ("code", "name", "iso_country")
CAVEATS = (
    "fictional comparison",
    "not operational suitability",
    "source accuracy unverified",
    "recorded runway length is not usable landing distance",
)


class EvidenceError(ValueError):
    """A stable error code, distinct from successful missing-evidence results."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.provenance = None


def _with_provenance(method):
    @wraps(method)
    def call(self, *args, **kwargs):
        try:
            return method(self, *args, **kwargs)
        except EvidenceError as exc:
            exc.provenance = self.provenance
            raise
    return call


def _record(row, fields):
    if not isinstance(row, Mapping):
        raise EvidenceError("data_integrity", "Expected a source record object")
    result = {}
    for field in fields:
        if field not in row or not isinstance(row[field], str):
            raise EvidenceError("data_integrity", f"Missing or malformed source column: {field}")
        raw = row[field]
        value, reason = raw, None
        if not raw.strip():
            value, reason = None, "missing"
        elif field in ("latitude_deg", "longitude_deg", "length_ft", "width_ft"):
            try:
                value = float(raw)
            except ValueError:
                value, reason = None, "invalid_number"
            if value is not None and field in ("length_ft", "width_ft"):
                if not math.isfinite(value) or value <= 0:
                    value, reason = None, "not_positive_finite"
            if value is not None and field in ("latitude_deg", "longitude_deg"):
                bound = 90 if field == "latitude_deg" else 180
                if not math.isfinite(value) or not -bound <= value <= bound:
                    value, reason = None, "invalid_coordinate"
        elif field in ("closed", "lighted"):
            if raw in ("0", "1"):
                value = raw == "1"
            else:
                value, reason = None, "invalid_flag"
        elif field in ("id", "airport_ref"):
            if not re.fullmatch(r"[0-9]+", raw) or int(raw) <= 0:
                raise EvidenceError("data_integrity", f"Invalid structural key: {field}")
            value = int(raw)
        elif field in ("ident", "airport_ident") and not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", raw):
            raise EvidenceError("data_integrity", "Invalid source airport identifier")
        elif field == "surface" and raw.casefold() in ("unknown", "unk", "n/a", "na", "?"):
            value, reason = None, "unknown_surface"
        result[field] = {
            "raw": raw, "parsed": value, "quality_reasons": [reason] if reason else [],
        }
    return result


def _index(rows, field):
    result = {}
    for row in rows:
        key = row[field]["parsed"]
        if key is None or key in result:
            raise EvidenceError("data_integrity", f"Missing or duplicate structural key: {field}")
        result[key] = row
    return result


class EvidenceAssessment:
    """Assessment/projection rules over provenance-bound airport and runway reads."""

    def assess_airport(self, ident):
        resolved = self.lookup_airport(ident)
        airport = resolved["airport"]
        runways = self.list_runways(ident)["runways"]
        gaps = []
        for field in AIRPORT_FIELDS:
            gaps.extend(f"airport.{field}: {reason}" for reason in airport[field]["quality_reasons"])
        if not any(row["closed"]["parsed"] is False for row in runways):
            gaps.append("airport.runways: no_recorded_open_runway")
        for row in runways:
            fields = ("closed",)
            if row["closed"]["parsed"] is False:
                fields += ("length_ft", "width_ft", "surface", "lighted")
            for field in fields:
                gaps.extend(
                    f"runway[{row['id']['parsed']}].{field}: {reason}"
                    for reason in row[field]["quality_reasons"]
                )
        return {
            "classification": "insufficient_evidence" if gaps else "complete",
            "gap_reasons": gaps,
            "caveats": list(CAVEATS) + gaps,
            "evidence": {key: resolved[key] for key in ("airport", "country", "region")}
                        | {"runways": runways},
            "provenance": self.provenance,
        }

    def shareable_projection(self, draft):
        """Recheck facts and project them; does not approve, publish or persist."""
        if not isinstance(draft, dict):
            raise EvidenceError("invalid_input", "Expected a structured assessment draft")
        if type(draft.get("schema_version")) is not int or draft["schema_version"] != 1:
            raise EvidenceError("unsupported_version", "Unsupported draft schema version")
        if type(draft.get("version")) is not int or draft["version"] < 1:
            raise EvidenceError("invalid_input", "Draft version must be a positive integer")
        for field in ("artifact_id", "run_id", "operation_id", "airport_ident"):
            value = draft.get(field)
            if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value):
                raise EvidenceError("invalid_input", f"Invalid draft identity: {field}")
        actual = self.assess_airport(draft["airport_ident"])
        allowed = {
            "artifact_id", "version", "schema_version", "run_id", "operation_id", "airport_ident",
            "evidence", "classification", "gap_reasons", "caveats", "provenance",
            "private_notes", "prompts", "reviewer_deliberation", "credentials", "storage_path",
        }
        if draft.keys() - allowed:
            raise EvidenceError("data_integrity", "Unsupported structured draft fields or claims")
        try:
            for field in ("evidence", "classification", "gap_reasons", "caveats", "provenance"):
                if field not in draft or canonical_bytes(draft[field]) != canonical_bytes(actual[field]):
                    raise EvidenceError("data_integrity", f"Draft differs from source evidence: {field}")
            digest = sha256(draft)
        except (TypeError, ValueError) as exc:
            if isinstance(exc, EvidenceError):
                raise
            raise EvidenceError("invalid_input", "Draft is not canonical JSON data") from exc
        return {
            "schema_version": 1, "run_id": draft["run_id"], "operation_id": draft["operation_id"],
            "airport_ident": draft["airport_ident"],
            "draft": {"artifact_id": draft["artifact_id"], "version": draft["version"], "sha256": digest},
            **actual,
        }


class ReferenceData(EvidenceAssessment):
    """Read-only public evidence boundary; responses contain detached values."""

    @classmethod
    def from_directory(cls, directory):
        """Load only the exact approved snapshot; never infer a pin from a filename."""
        from .source import read_source, source_manifest

        instance = cls.from_rows(**read_source(directory))
        instance._source_manifest = source_manifest()
        instance._fixture_manifest = instance._base_fixture()
        return instance

    @classmethod
    def from_bundle(cls, directory, *, fixture="base-source"):
        from .preparation import load_bundle

        return load_bundle(directory, fixture=fixture)

    def export_rows(self):
        """Allowlisted base-source rows for immutable local packaging, not an MCP tool."""
        if self._fixture_manifest["id"] != "base-source":
            raise EvidenceError("invalid_input", "Do not export an overlay as base-source rows")
        return {
            name: [{field: value["raw"] for field, value in row.items()} for row in rows]
            for name, rows in (
                ("airports", self._airports), ("runways", self._runways),
                ("countries", self._countries), ("regions", self._regions),
            )
        }

    @classmethod
    def from_rows(cls, *, airports, runways, countries, regions,
                  schema_version=1, profile_version=1, fixture_version=1):
        for version in (schema_version, profile_version, fixture_version):
            if type(version) is not int or version != 1:
                raise EvidenceError("unsupported_version", "Only schema/profile/fixture version 1 is supported")
        instance = cls()
        instance._airports = [_record(row, AIRPORT_FIELDS) for row in airports]
        instance._runways = [_record(row, RUNWAY_FIELDS) for row in runways]
        instance._countries = [_record(row, COUNTRY_FIELDS) for row in countries]
        instance._regions = [_record(row, REGION_FIELDS) for row in regions]
        airport_index = _index(instance._airports, "ident")
        _index(instance._airports, "id")
        _index(instance._runways, "id")
        country_index = _index(instance._countries, "code")
        region_index = _index(instance._regions, "code")
        for airport in instance._airports:
            country = airport["iso_country"]["parsed"]
            region = region_index.get(airport["iso_region"]["parsed"])
            if country not in country_index or region is None:
                raise EvidenceError("data_integrity", "Unresolved airport country or region")
            if region["iso_country"]["parsed"] != country:
                raise EvidenceError("data_integrity", "Region country disagrees with airport")
        for runway in instance._runways:
            airport = airport_index.get(runway["airport_ident"]["parsed"])
            if airport is None or runway["airport_ref"]["parsed"] != airport["id"]["parsed"]:
                raise EvidenceError("data_integrity", "Broken runway identifier/ID join")
        instance._source_manifest = {
            "kind": "supplied_rows", "schema_version": 1, "snapshot": None,
            "content_sha256": sha256({
                "airports": sorted(instance._airports, key=lambda row: row["id"]["parsed"]),
                "runways": sorted(instance._runways, key=lambda row: row["id"]["parsed"]),
                "countries": sorted(instance._countries, key=lambda row: row["code"]["parsed"]),
                "regions": sorted(instance._regions, key=lambda row: row["code"]["parsed"]),
            }),
        }
        instance._fixture_manifest = instance._base_fixture()
        return instance

    def _base_fixture(self):
        return {
            "kind": "fixture", "schema_version": 1, "id": "base-source", "version": 1,
            "source_sha256": sha256(self._source_manifest),
            "profile_sha256": sha256(profile_manifest()), "mutations": [],
        }

    @property
    def provenance(self):
        profile = profile_manifest()
        fixture = self._fixture_manifest
        return {
            "schema_version": 1,
            "source": {
                "kind": self._source_manifest["kind"],
                "snapshot": self._source_manifest["snapshot"],
                "sha256": sha256(self._source_manifest),
            },
            "profile": {"id": profile["id"], "version": 1, "sha256": sha256(profile)},
            "fixture": {"id": fixture["id"], "version": 1, "sha256": sha256(fixture)},
            "evidence_origin": "base-source" if fixture["id"] == "base-source" else "synthetic-overlay",
        }

    @property
    def source_manifest(self):
        return deepcopy(self._source_manifest)

    @property
    def fixture_manifest(self):
        return deepcopy(self._fixture_manifest)

    @_with_provenance
    def search_airports(self, **arguments):
        if arguments.keys() - {"countries", "types", "limit"}:
            raise EvidenceError("invalid_input", "Unknown search argument")
        countries = arguments.get("countries", COUNTRIES)
        types = arguments.get("types", TYPES)
        limit = arguments.get("limit", 20)
        for values, allowed in ((countries, COUNTRIES), (types, TYPES)):
            if (
                not isinstance(values, (list, tuple, set, frozenset))
                or not values
                or any(not isinstance(value, str) or value not in allowed for value in values)
                or len(set(values)) != len(values)
            ):
                raise EvidenceError("invalid_input", "Filters must be nonempty, unique allowlisted sets")
        if type(limit) is not int or not 1 <= limit <= 20:
            raise EvidenceError("invalid_input", "Limit must be an integer from 1 through 20")
        matches = [
            row for row in self._airports
            if row["iso_country"]["parsed"] in countries and row["type"]["parsed"] in types
        ]
        matches.sort(key=lambda row: (row["iso_country"]["parsed"], row["ident"]["parsed"]))
        return {"airports": deepcopy(matches[:limit]), "provenance": self.provenance}

    @_with_provenance
    def lookup_airport(self, ident=None, **arguments):
        if arguments or not isinstance(ident, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", ident):
            raise EvidenceError("invalid_input", "Expected one exact airport identifier")
        airport = next((row for row in self._airports if row["ident"]["parsed"] == ident), None)
        if airport is None:
            raise EvidenceError("not_found", "Airport identifier not found")
        country = next(row for row in self._countries if row["code"]["parsed"] == airport["iso_country"]["parsed"])
        region = next(row for row in self._regions if row["code"]["parsed"] == airport["iso_region"]["parsed"])
        return deepcopy({
            "airport": airport, "country": country, "region": region, "provenance": self.provenance,
        })

    @_with_provenance
    def list_runways(self, ident=None, **arguments):
        self.lookup_airport(ident, **arguments)
        rows = [row for row in self._runways if row["airport_ident"]["parsed"] == ident]
        if len(rows) > 50:
            raise EvidenceError("result_limit", "Airport exceeds the 50-runway evidence bound")
        return {
            "runways": deepcopy(sorted(rows, key=lambda row: row["id"]["parsed"])),
            "provenance": self.provenance,
        }

    def fixture_gate(self):
        """Assess each member of the fixed first-20 pool exactly once."""
        matches = [
            row for row in self._airports
            if row["iso_country"]["parsed"] in COUNTRIES and row["type"]["parsed"] in TYPES
        ]
        matches.sort(key=lambda row: (row["iso_country"]["parsed"], row["ident"]["parsed"]))
        pool, complete = [], []
        for airport in matches[:20]:
            ident = airport["ident"]["parsed"]
            assessment = self.assess_airport(ident)
            pool.append({"ident": ident, "airport_id": airport["id"]["parsed"], **assessment})
            if assessment["classification"] == "complete":
                complete.append(ident)
        return {
            "status": "passed" if len(complete) >= 4 else "blocked",
            "required_complete": 4,
            "pool_count": len(pool),
            "complete_count": len(complete),
            "complete_identifiers": complete,
            "pool": pool,
            "provenance": self.provenance,
        }

    def fixture_manifests(self):
        if self._fixture_manifest["id"] != "base-source":
            raise EvidenceError("invalid_input", "Fixtures must be prepared from unchanged base source")
        gate = self.fixture_gate()
        if gate["status"] != "passed":
            raise EvidenceError("fixture_gate_failed", "First-20 pool has fewer than four complete candidates")
        mutations = []
        for candidate in gate["pool"]:
            if candidate["classification"] != "complete":
                continue
            runway = next(
                row for row in candidate["evidence"]["runways"] if row["closed"]["parsed"] is False
            )
            mutations.append({
                "record_type": "runway", "record_id": runway["id"]["parsed"],
                "airport_ident": candidate["ident"], "field": "width_ft",
                "source_raw": runway["width_ft"]["raw"], "value": None,
            })
        return {
            name: {
                **self._base_fixture(), "id": name,
                "label": "Synthetic missing-width evidence; not a real airport defect",
                "mutations": deepcopy(changes),
            }
            for name, changes in (
                ("missing-width-replacement", mutations[:1]), ("no-alternative", mutations),
            )
        }

    def with_overlay(self, manifest):
        if not isinstance(manifest, dict):
            raise EvidenceError("invalid_input", "Expected a fixture manifest")
        for field in ("schema_version", "version"):
            if type(manifest.get(field)) is not int or manifest[field] != 1:
                raise EvidenceError("unsupported_version", "Unsupported fixture/schema version")
        expected = self.fixture_manifests()
        name = manifest.get("id")
        if not isinstance(name, str) or name not in expected:
            raise EvidenceError("unsupported_version", "Unknown fixture identity")
        try:
            if canonical_bytes(manifest) != canonical_bytes(expected[name]):
                raise EvidenceError("data_integrity", "Fixture manifest differs from deterministic source-bound overlay")
        except (TypeError, ValueError) as exc:
            if isinstance(exc, EvidenceError):
                raise
            raise EvidenceError("data_integrity", "Fixture manifest is not canonical JSON") from exc
        result = deepcopy(self)
        result._fixture_manifest = deepcopy(manifest)
        rows = {row["id"]["parsed"]: row for row in result._runways}
        for mutation in manifest["mutations"]:
            rows[mutation["record_id"]]["width_ft"] = {
                "raw": None, "parsed": None, "source_raw": mutation["source_raw"],
                "quality_reasons": ["synthetic_missing_width"],
            }
        return result

    def select_candidates(self):
        """Pure evidence selection, not release approval or an agent invocation."""
        pool = self.search_airports()["airports"]
        assessed, selected = [], []
        for airport in pool:
            ident = airport["ident"]["parsed"]
            assessment = self.assess_airport(ident)
            assessed.append({"ident": ident, **assessment})
            if assessment["classification"] == "complete":
                selected.append(ident)
            if len(selected) == 3:
                break
        return {
            "status": "complete" if len(selected) == 3 else "bounded_pool_exhausted",
            "pool_count": len(pool), "selected_identifiers": selected,
            "assessed": assessed, "provenance": self.provenance,
        }
