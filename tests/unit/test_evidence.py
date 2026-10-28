import hashlib
import json
import unittest
from copy import deepcopy

from citadel.evidence import EvidenceError, ReferenceData
from citadel.evidence.manifests import profile_manifest


def source(airports=None, runways=None, countries=None, regions=None):
    return ReferenceData.from_rows(
        airports=airports if airports is not None else [airport()],
        runways=runways if runways is not None else [runway()],
        countries=countries if countries is not None else [{"code": "BE", "name": "Belgium"}],
        regions=regions if regions is not None else [
            {"code": "BE-VAN", "name": "Antwerp", "iso_country": "BE"}
        ],
    )


def airport(**changes):
    return {
        "id": "1", "ident": "EB01", "name": "Fictional airport",
        "type": "small_airport", "latitude_deg": "51.2", "longitude_deg": "4.4",
        "iso_country": "BE", "iso_region": "BE-VAN", **changes,
    }


def runway(**changes):
    return {
        "id": "10", "airport_ref": "1", "airport_ident": "EB01",
        "length_ft": "1200", "width_ft": "80", "surface": "grass",
        "lighted": "0", "closed": "0", **changes,
    }


class CompletenessTests(unittest.TestCase):
    def test_complete_evidence_preserves_literal_source_and_mandatory_caveats(self):
        assessment = source().assess_airport("EB01")
        self.assertEqual(assessment["classification"], "complete")
        self.assertEqual(assessment["gap_reasons"], [])
        self.assertEqual(
            assessment["evidence"]["runways"][0]["width_ft"],
            {"raw": "80", "parsed": 80.0, "quality_reasons": []},
        )
        self.assertEqual(
            assessment["caveats"],
            [
                "fictional comparison",
                "not operational suitability",
                "source accuracy unverified",
                "recorded runway length is not usable landing distance",
            ],
        )
        self.assertEqual(profile_manifest()["mandatory_caveats"], assessment["caveats"])
        self.assertEqual(profile_manifest()["field_allowlists"]["runways"], [
            "id", "airport_ref", "airport_ident", "length_ft", "width_ft", "surface",
            "lighted", "closed",
        ])


class IntegrityTests(unittest.TestCase):
    def test_source_schema_failures_are_distinct_from_literal_and_missing_field_evidence(self):
        for kwargs in [
            {"airports": [None]},
            {"airports": [{}]},
            {"airports": [airport(id=1)]},
            {"airports": [airport(ident="ÉB01")], "runways": []},
            {"airports": [airport(ident="A" * 65)], "runways": []},
            {"airports": [airport(), airport(id="01", ident="EB02")]},
            {"runways": [runway(width_ft=None)]},
        ]:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(EvidenceError) as caught:
                    source(**kwargs)
                self.assertEqual(caught.exception.code, "data_integrity")
        data = source(runways=[runway(surface=" Mixed literal / grass ", lighted="1", length_ft="1.2e3")])
        assessment = data.assess_airport("EB01")
        self.assertEqual(assessment["classification"], "complete")
        fields = assessment["evidence"]["runways"][0]
        self.assertEqual(fields["surface"]["parsed"], " Mixed literal / grass ")
        self.assertEqual(fields["length_ft"]["raw"], "1.2e3")
        self.assertEqual(fields["length_ft"]["parsed"], 1200.0)
        self.assertIs(fields["lighted"]["parsed"], True)
        self.assertIs(fields["closed"]["parsed"], False)
        ident = "A_" + "x" * 62
        self.assertEqual(
            source(airports=[airport(ident=ident)], runways=[runway(airport_ident=ident)])
            .lookup_airport(ident)["airport"]["ident"]["parsed"], ident,
        )

    def test_duplicate_keys_and_broken_joins_are_integrity_failures(self):
        cases = [
            {"airports": [airport(), airport()]},
            {"airports": [airport(), airport(ident="OTHER")]},
            {"airports": [airport(), airport(id="2")]},
            {"runways": [runway(), runway()]},
            {"countries": [{"code": "BE", "name": "Belgium"}] * 2},
            {"regions": [{"code": "BE-VAN", "name": "Antwerp", "iso_country": "BE"}] * 2},
            {"airports": [airport(id="")]},
            {"airports": [airport(ident="")]},
            {"airports": [airport(id="NaN")]},
            {"airports": [airport(iso_country="")]},
            {"airports": [airport(iso_region="")]},
            {"runways": [runway(id="")]},
            {"runways": [runway(airport_ident="OTHER")]},
            {"runways": [runway(airport_ref="2")]},
            {"countries": []},
            {"regions": []},
            {"regions": [{"code": "BE-VAN", "name": "Antwerp", "iso_country": "NL"}]},
        ]
        for kwargs in cases:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(EvidenceError) as caught:
                    source(**kwargs)
                self.assertEqual(caught.exception.code, "data_integrity")

    def test_missing_and_invalid_evidence_never_becomes_complete_or_false(self):
        cases = [
            ("width_ft", "", "missing"),
            ("width_ft", " ", "missing"),
            ("width_ft", "0", "not_positive_finite"),
            ("length_ft", "-1", "not_positive_finite"),
            ("length_ft", "NaN", "not_positive_finite"),
            ("length_ft", "inf", "not_positive_finite"),
            ("width_ft", "not-a-number", "invalid_number"),
            ("surface", "", "missing"),
            ("surface", "UnKnOwN", "unknown_surface"),
            ("surface", "unk", "unknown_surface"),
            ("surface", "n/a", "unknown_surface"),
            ("surface", "NA", "unknown_surface"),
            ("surface", "?", "unknown_surface"),
            ("lighted", "", "missing"),
            ("lighted", "false", "invalid_flag"),
            ("closed", "2", "invalid_flag"),
            ("closed", " 0", "invalid_flag"),
        ]
        for field, raw, reason in cases:
            with self.subTest(field=field, raw=raw):
                assessment = source(runways=[runway(**{field: raw})]).assess_airport("EB01")
                self.assertEqual(assessment["classification"], "insufficient_evidence")
                self.assertEqual(
                    assessment["evidence"]["runways"][0][field],
                    {"raw": raw, "parsed": None, "quality_reasons": [reason]},
                )
                gap = f"runway[10].{field}: {reason}"
                self.assertIn(gap, assessment["gap_reasons"])
                self.assertIn(gap, assessment["caveats"])

    def test_completeness_uses_all_open_runways_and_valid_airport_evidence(self):
        for rows, expected, gap in [
            ([], "insufficient_evidence", "airport.runways: no_recorded_open_runway"),
            ([runway(closed="1", width_ft="")], "insufficient_evidence",
             "airport.runways: no_recorded_open_runway"),
            ([runway(), runway(id="11", closed="1", width_ft="")], "complete", None),
            ([runway(), runway(id="11", width_ft="")], "insufficient_evidence",
             "runway[11].width_ft: missing"),
            ([runway(), runway(id="11", closed="")], "insufficient_evidence",
             "runway[11].closed: missing"),
        ]:
            with self.subTest(runways=rows):
                assessment = source(runways=rows).assess_airport("EB01")
                self.assertEqual(assessment["classification"], expected)
                self.assertEqual(len(assessment["evidence"]["runways"]), len(rows))
                if gap:
                    self.assertIn(gap, assessment["gap_reasons"])
        for field, raw, reason in [
            ("name", "", "missing"), ("type", "", "missing"),
            ("latitude_deg", "", "missing"),
            ("latitude_deg", "91", "invalid_coordinate"),
            ("latitude_deg", "-91", "invalid_coordinate"),
            ("longitude_deg", "181", "invalid_coordinate"),
            ("longitude_deg", "-181", "invalid_coordinate"),
            ("latitude_deg", "NaN", "invalid_coordinate"),
            ("longitude_deg", "inf", "invalid_coordinate"),
            ("latitude_deg", "north", "invalid_number"),
        ]:
            with self.subTest(field=field, raw=raw):
                assessment = source(airports=[airport(**{field: raw})]).assess_airport("EB01")
                self.assertEqual(assessment["classification"], "insufficient_evidence")
                self.assertIn(f"airport.{field}: {reason}", assessment["gap_reasons"])
        for lat, lon in [("-90", "-180"), ("90", "180"), ("0", "0")]:
            with self.subTest(lat=lat, lon=lon):
                self.assertEqual(
                    source(airports=[airport(latitude_deg=lat, longitude_deg=lon)])
                    .assess_airport("EB01")["classification"],
                    "complete",
                )


class GateTests(unittest.TestCase):
    def test_gate_never_widens_first_twenty_to_find_four_complete_candidates(self):
        airports = [airport(id=str(i), ident=f"EB{i:02}") for i in range(1, 22)]
        for first_complete, expected_status, expected_complete in [
            (18, "blocked", ["EB18", "EB19", "EB20"]),
            (17, "passed", ["EB17", "EB18", "EB19", "EB20"]),
        ]:
            with self.subTest(first_complete=first_complete):
                runways = [
                    runway(id=str(i), airport_ref=str(i), airport_ident=f"EB{i:02}")
                    for i in range(first_complete, 22)
                ]
                result = source(airports=reversed(airports), runways=runways).fixture_gate()
                self.assertEqual(result["status"], expected_status)
                self.assertEqual(result["required_complete"], 4)
                self.assertEqual(result["complete_identifiers"], expected_complete)
                self.assertEqual(result["complete_count"], len(expected_complete))
                self.assertEqual(
                    [row["ident"] for row in result["pool"]],
                    [f"EB{i:02}" for i in range(1, 21)],
                )

    def test_search_defaults_bounds_exact_sets_and_country_identifier_order(self):
        data = source(
            airports=[
                airport(id="3", ident="AA", iso_country="NL", iso_region="NL-ZH"),
                airport(id="2", ident="ZZ"),
                airport(),
                airport(id="4", ident="HELI", type="heliport"),
            ],
            countries=[{"code": "BE", "name": "Belgium"}, {"code": "NL", "name": "Netherlands"}],
            regions=[
                {"code": "BE-VAN", "name": "Antwerp", "iso_country": "BE"},
                {"code": "NL-ZH", "name": "South Holland", "iso_country": "NL"},
            ],
        )
        self.assertEqual(
            [row["ident"]["parsed"] for row in data.search_airports()["airports"]],
            ["EB01", "ZZ", "AA"],
        )
        self.assertEqual(
            data.search_airports(countries=["NL"], types=["small_airport"], limit=1)
            ["airports"][0]["ident"]["parsed"], "AA",
        )
        self.assertEqual(data.search_airports(countries=["DE"])["airports"], [])
        for kwargs in [
            {"countries": []}, {"countries": None}, {"countries": ["BE", "BE"]},
            {"countries": "BE"}, {"countries": ["FR"]}, {"countries": ["be"]},
            {"countries": [1]}, {"countries": [{}]},
            {"types": []}, {"types": None}, {"types": ["heliport"]},
            {"types": ["small_airport", "small_airport"]},
            {"limit": 0}, {"limit": 21}, {"limit": True}, {"limit": 1.0},
            {"limit": "1"}, {"limit": None}, {"query": "all"}, {"url": "https://example.com"},
        ]:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(EvidenceError) as caught:
                    data.search_airports(**kwargs)
                self.assertEqual(caught.exception.code, "invalid_input")

    def test_lookup_and_runways_are_exact_allowlisted_detached_and_never_truncated(self):
        data = source(
            airports=[airport(comment="private", home_link="unneeded")],
            runways=[runway(id="100", le_ident="unneeded"), runway(id="2")],
        )
        lookup = data.lookup_airport("EB01")
        self.assertEqual(set(lookup["airport"]), {
            "id", "ident", "name", "type", "latitude_deg", "longitude_deg",
            "iso_country", "iso_region",
        })
        self.assertEqual(set(lookup["country"]), {"code", "name"})
        self.assertEqual(set(lookup["region"]), {"code", "name", "iso_country"})
        lookup["airport"]["name"]["parsed"] = "changed"
        self.assertEqual(data.lookup_airport("EB01")["airport"]["name"]["parsed"], "Fictional airport")
        rows = data.list_runways("EB01")["runways"]
        self.assertEqual([row["id"]["parsed"] for row in rows], [2, 100])
        self.assertEqual(set(rows[0]), {
            "id", "airport_ref", "airport_ident", "length_ft", "width_ft", "surface",
            "lighted", "closed",
        })
        for ident, code in [
            ("eb01", "not_found"), ("UNKNOWN", "not_found"),
            ("", "invalid_input"), ("A" * 65, "invalid_input"),
            ("ÉB01", "invalid_input"), (" EB01", "invalid_input"),
            ("EB/01", "invalid_input"), (None, "invalid_input"), (1, "invalid_input"),
        ]:
            for tool in (data.lookup_airport, data.list_runways, data.assess_airport):
                with self.subTest(ident=ident, tool=tool.__name__):
                    with self.assertRaises(EvidenceError) as caught:
                        tool(ident)
                    self.assertEqual(caught.exception.code, code)
                    self.assertEqual(caught.exception.provenance, data.provenance)
        for tool in (data.lookup_airport, data.list_runways):
            with self.assertRaises(EvidenceError) as caught:
                tool("EB01", extra="unexpected")
            self.assertEqual(caught.exception.code, "invalid_input")
            with self.assertRaises(EvidenceError) as caught:
                tool()
            self.assertEqual(caught.exception.code, "invalid_input")
        self.assertEqual(len(source(runways=[runway(id=str(i)) for i in range(1, 51)])
                             .list_runways("EB01")["runways"]), 50)
        over_limit = source(runways=[runway(id=str(i)) for i in range(1, 52)])
        for tool in (over_limit.list_runways, over_limit.assess_airport):
            with self.assertRaises(EvidenceError) as caught:
                tool("EB01")
            self.assertEqual(caught.exception.code, "result_limit")
        with self.assertRaises(EvidenceError) as caught:
            over_limit.fixture_gate()
        self.assertEqual(caught.exception.code, "result_limit")

    def test_every_response_has_detached_versioned_provenance_without_claiming_a_pin_for_test_rows(self):
        data = source()
        provenance = data.provenance
        self.assertEqual(provenance["schema_version"], 1)
        self.assertEqual(provenance["source"]["kind"], "supplied_rows")
        self.assertIsNone(provenance["source"]["snapshot"])
        self.assertEqual(provenance["profile"]["version"], 1)
        self.assertEqual(provenance["fixture"]["id"], "base-source")
        self.assertEqual(provenance["evidence_origin"], "base-source")
        self.assertRegex(provenance["source"]["sha256"], r"^[0-9a-f]{64}$")
        for response in (
            data.search_airports(), data.lookup_airport("EB01"), data.list_runways("EB01"),
            data.assess_airport("EB01"), data.fixture_gate(),
        ):
            self.assertEqual(response["provenance"], provenance)
            response["provenance"]["fixture"]["id"] = "fake"
        self.assertEqual(data.provenance, provenance)
        for field in ("schema_version", "profile_version", "fixture_version"):
            for version in (0, 2, "1", True, None):
                with self.subTest(field=field, version=version):
                    with self.assertRaises(EvidenceError) as caught:
                        ReferenceData.from_rows(
                            airports=[], runways=[], countries=[], regions=[], **{field: version},
                        )
                    self.assertEqual(caught.exception.code, "unsupported_version")


class ProjectionTests(unittest.TestCase):
    def test_shareable_projection_rechecks_facts_caveats_and_excludes_private_content(self):
        data = source(runways=[runway(width_ft="")])
        draft = {
            "artifact_id": "draft-1", "version": 2, "schema_version": 1,
            "run_id": "run-1", "operation_id": "op-1", "airport_ident": "EB01",
            **data.assess_airport("EB01"),
            "private_notes": "DO-NOT-SHARE", "prompts": ["DO-NOT-SHARE"],
            "reviewer_deliberation": "DO-NOT-SHARE", "credentials": "DO-NOT-SHARE",
            "storage_path": "DO-NOT-SHARE",
        }
        projection = data.shareable_projection(draft)
        self.assertNotIn("DO-NOT-SHARE", json.dumps(projection))
        self.assertEqual(set(projection), {
            "schema_version", "run_id", "operation_id", "airport_ident", "draft",
            "evidence", "classification", "gap_reasons", "caveats", "provenance",
        })
        self.assertEqual(projection["draft"]["artifact_id"], "draft-1")
        self.assertEqual(projection["draft"]["version"], 2)
        expected_hash = hashlib.sha256(json.dumps(
            draft, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
        ).encode()).hexdigest()
        self.assertEqual(projection["draft"]["sha256"], expected_hash)
        self.assertEqual(projection["classification"], "insufficient_evidence")
        self.assertIn("runway[10].width_ft: missing", projection["caveats"])
        for field, value, code in [
            ("classification", "complete", "data_integrity"),
            ("gap_reasons", [], "data_integrity"),
            ("caveats", [], "data_integrity"),
            ("provenance", {}, "data_integrity"),
            ("schema_version", 2, "unsupported_version"),
            ("version", True, "invalid_input"),
            ("version", 0, "invalid_input"),
            ("artifact_id", "", "invalid_input"),
            ("run_id", "", "invalid_input"),
        ]:
            with self.subTest(field=field):
                changed = deepcopy(draft)
                changed[field] = value
                with self.assertRaises(EvidenceError) as caught:
                    data.shareable_projection(changed)
                self.assertEqual(caught.exception.code, code)
        changed = deepcopy(draft)
        changed["evidence"]["airport"]["private_notes"] = "DO-NOT-SHARE"
        with self.assertRaises(EvidenceError) as caught:
            data.shareable_projection(changed)
        self.assertEqual(caught.exception.code, "data_integrity")
        changed = deepcopy(draft)
        changed["safety_certified"] = True
        with self.assertRaises(EvidenceError) as caught:
            data.shareable_projection(changed)
        self.assertEqual(caught.exception.code, "data_integrity")
        projection["evidence"]["airport"]["name"]["parsed"] = "changed"
        self.assertEqual(draft["evidence"]["airport"]["name"]["parsed"], "Fictional airport")


class FixtureTests(unittest.TestCase):
    def test_overlay_manifests_reject_unknown_versions_tampering_and_boolean_record_ids(self):
        data = source(
            airports=[airport(id=str(i), ident=f"EB{i:02}") for i in range(1, 5)],
            runways=[runway(id=str(i), airport_ref=str(i), airport_ident=f"EB{i:02}") for i in range(1, 5)],
        )
        original = data.fixture_manifests()["missing-width-replacement"]
        for field, value, code in [
            ("schema_version", True, "unsupported_version"),
            ("schema_version", 2, "unsupported_version"),
            ("version", 2, "unsupported_version"),
            ("id", "unapproved-fixture", "unsupported_version"),
            ("source_sha256", "0" * 64, "data_integrity"),
            ("profile_sha256", "0" * 64, "data_integrity"),
            ("extra", "unexpected", "data_integrity"),
        ]:
            with self.subTest(field=field):
                changed = deepcopy(original)
                changed[field] = value
                with self.assertRaises(EvidenceError) as caught:
                    data.with_overlay(changed)
                self.assertEqual(caught.exception.code, code)
        for field, value in [
            ("record_id", True), ("record_id", 1.0), ("field", "length_ft"),
            ("value", 0), ("airport_ident", "EB02"), ("source_raw", "79"),
        ]:
            with self.subTest(mutation_field=field, value=value):
                changed = deepcopy(original)
                changed["mutations"][0][field] = value
                with self.assertRaises(EvidenceError) as caught:
                    data.with_overlay(changed)
                self.assertEqual(caught.exception.code, "data_integrity")
        overlay = data.with_overlay(original)
        with self.assertRaises(EvidenceError) as caught:
            overlay.with_overlay(original)
        self.assertEqual(caught.exception.code, "invalid_input")
        with self.assertRaises(EvidenceError) as caught:
            overlay.export_rows()
        self.assertEqual(caught.exception.code, "invalid_input")

    def test_candidate_selection_skips_gaps_once_stops_at_three_and_reports_bounded_exhaustion(self):
        data = source(
            airports=[airport(id=str(i), ident=f"EB{i:02}") for i in range(1, 6)],
            runways=[
                runway(id=str(i), airport_ref=str(i), airport_ident=f"EB{i:02}")
                for i in (2, 3, 4, 5)
            ],
        )
        result = data.select_candidates()
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["selected_identifiers"], ["EB02", "EB03", "EB04"])
        self.assertEqual([row["ident"] for row in result["assessed"]], ["EB01", "EB02", "EB03", "EB04"])
        insufficient = source(runways=[]).select_candidates()
        self.assertEqual(insufficient["status"], "bounded_pool_exhausted")
        self.assertEqual(insufficient["selected_identifiers"], [])
        self.assertEqual(insufficient["pool_count"], 1)
        fewer = source().select_candidates()
        self.assertEqual(fewer["status"], "bounded_pool_exhausted")
        self.assertEqual(fewer["selected_identifiers"], ["EB01"])
        self.assertEqual(fewer["provenance"], source().provenance)

    def test_labelled_overlays_mutate_only_lowest_open_width_and_preserve_source(self):
        data = source(
            airports=[airport(id="5", ident="EB00")]
                     + [airport(id=str(i), ident=f"EB{i:02}") for i in range(1, 5)],
            runways=[
                runway(id="1", closed="1"), runway(id="8"), runway(id="3"),
                runway(id="20", airport_ref="5", airport_ident="EB00", width_ft=""),
                *[runway(id=str(10 + i), airport_ref=str(i), airport_ident=f"EB{i:02}")
                  for i in range(2, 5)],
            ],
        )
        manifests = data.fixture_manifests()
        replacement = manifests["missing-width-replacement"]
        self.assertEqual(replacement["mutations"], [{
            "record_type": "runway", "record_id": 3, "airport_ident": "EB01",
            "field": "width_ft", "source_raw": "80", "value": None,
        }])
        changed = data.with_overlay(replacement)
        assessment = changed.assess_airport("EB01")
        self.assertEqual(assessment["classification"], "insufficient_evidence")
        self.assertEqual(assessment["provenance"]["evidence_origin"], "synthetic-overlay")
        self.assertEqual(assessment["provenance"]["fixture"]["id"], "missing-width-replacement")
        self.assertEqual(assessment["evidence"]["runways"][1]["width_ft"], {
            "raw": None, "parsed": None, "source_raw": "80",
            "quality_reasons": ["synthetic_missing_width"],
        })
        self.assertEqual(changed.fixture_gate()["complete_identifiers"], ["EB02", "EB03", "EB04"])
        self.assertEqual(data.assess_airport("EB01")["classification"], "complete")
        self.assertEqual(data.list_runways("EB01")["runways"][1]["width_ft"]["raw"], "80")
        no_alternative = data.with_overlay(manifests["no-alternative"])
        self.assertEqual(no_alternative.fixture_gate()["complete_count"], 0)
        self.assertEqual(len(manifests["no-alternative"]["mutations"]), 4)
        self.assertEqual(no_alternative.assess_airport("EB00")["gap_reasons"],
                         ["runway[20].width_ft: missing"])
        replacement["mutations"][0]["record_id"] = 8
        with self.assertRaises(EvidenceError) as caught:
            data.with_overlay(replacement)
        self.assertEqual(caught.exception.code, "data_integrity")
        with self.assertRaises(EvidenceError) as caught:
            source().fixture_manifests()
        self.assertEqual(caught.exception.code, "fixture_gate_failed")


if __name__ == "__main__":
    unittest.main()
