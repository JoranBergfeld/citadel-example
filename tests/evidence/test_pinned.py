import io
import hashlib
import json
import os
import shutil
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from citadel.evidence import EvidenceError, ReferenceData
from citadel.evidence.preparation import prepare_bundle
from citadel.evidence.source import acquire_source


@unittest.skipUnless(os.environ.get("CITADEL_EVIDENCE_DATA"), "Set CITADEL_EVIDENCE_DATA to retained pinned data")
class PinnedSourceTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(__file__).parent / f".scratch-{uuid.uuid4().hex}"
        self.directory.mkdir()
        self.addCleanup(shutil.rmtree, self.directory)

    def test_genuine_snapshot_has_sixteen_complete_in_exact_twenty_member_pool(self):
        data = ReferenceData.from_directory(Path(os.environ["CITADEL_EVIDENCE_DATA"]))
        gate = data.fixture_gate()
        self.assertEqual(gate["status"], "passed")
        self.assertEqual(gate["pool_count"], 20)
        self.assertEqual(gate["complete_count"], 16)
        self.assertEqual(gate["complete_identifiers"], [
            "BE-0052", "EBAM", "EBAR", "EBAW", "EBBE", "EBBL", "EBBR", "EBBT",
            "EBBX", "EBBY", "EBCF", "EBCI", "EBCV", "EBDT", "EBFN", "EBFS",
        ])
        self.assertEqual([row["ident"] for row in gate["pool"]], [
            "BE-0052", "EBAM", "EBAR", "EBAV", "EBAW", "EBBE", "EBBL", "EBBN",
            "EBBR", "EBBT", "EBBX", "EBBY", "EBBZ", "EBCF", "EBCI", "EBCV",
            "EBDT", "EBFN", "EBFS", "EBGB",
        ])
        self.assertEqual(data.provenance["source"]["snapshot"],
                         "a5a1ab8c3d9d57568c4bf9a7d398a23a60623830")
        self.assertEqual(data.source_manifest["files"]["airports.csv"]["sha256"],
                         "f219659218d1f27e7907c284b87778047b84102435d3483c7ee0ce6990b95e77")

    def test_acquisition_and_immutable_portable_bundle_reproduce_both_real_fixture_outcomes(self):
        retained = Path(os.environ["CITADEL_EVIDENCE_DATA"])
        acquired, bundle = self.directory / "source", self.directory / "bundle"
        with patch("citadel.evidence.source.urlopen",
                   side_effect=lambda url, timeout: io.BytesIO((retained / url.rsplit("/", 1)[1]).read_bytes())) as fetch:
            acquire_source(acquired)
            self.assertEqual(fetch.call_count, 5)
        with patch("citadel.evidence.source.urlopen", side_effect=AssertionError("Unexpected refresh")):
            acquire_source(acquired)
        recorded_manifest = json.loads((acquired / "source-manifest.json").read_text())
        self.assertEqual(recorded_manifest["snapshot"], "a5a1ab8c3d9d57568c4bf9a7d398a23a60623830")
        manifest = prepare_bundle(acquired, bundle)
        self.assertEqual(manifest["schema_version"], 1)
        original = {path.name: path.read_bytes() for path in bundle.iterdir()}
        self.assertEqual(prepare_bundle(acquired, bundle), manifest)
        self.assertEqual({path.name: path.read_bytes() for path in bundle.iterdir()}, original)
        base = ReferenceData.from_bundle(bundle)
        self.assertEqual(base.select_candidates()["selected_identifiers"], ["BE-0052", "EBAM", "EBAR"])
        replacement = ReferenceData.from_bundle(bundle, fixture="missing-width-replacement")
        self.assertEqual(replacement.select_candidates()["selected_identifiers"], ["EBAM", "EBAR", "EBAW"])
        exhausted = ReferenceData.from_bundle(bundle, fixture="no-alternative").select_candidates()
        self.assertEqual(exhausted["status"], "bounded_pool_exhausted")
        self.assertEqual(exhausted["selected_identifiers"], [])
        self.assertEqual(len(exhausted["assessed"]), 20)
        rows = json.loads((bundle / "reference-data.json").read_text())
        self.assertEqual(len(rows["airports"]), 1927)
        self.assertEqual(set(rows["airports"][0]), {
            "id", "ident", "name", "type", "latitude_deg", "longitude_deg", "iso_country", "iso_region",
        })
        with self.assertRaises(EvidenceError) as caught:
            ReferenceData.from_bundle(bundle, fixture="unknown")
        self.assertEqual(caught.exception.code, "unsupported_version")
        with (bundle / "reference-data.json").open("ab") as stream:
            stream.write(b" ")
        with self.assertRaises(EvidenceError) as caught:
            ReferenceData.from_bundle(bundle)
        self.assertEqual(caught.exception.code, "data_integrity")
        with self.assertRaises(EvidenceError) as caught:
            prepare_bundle(acquired, bundle)
        self.assertEqual(caught.exception.code, "data_integrity")
        recorded_manifest["schema_version"] = 2
        (acquired / "source-manifest.json").write_text(json.dumps(recorded_manifest))
        with self.assertRaises(EvidenceError) as caught:
            ReferenceData.from_directory(acquired)
        self.assertEqual(caught.exception.code, "unsupported_version")

    def test_bundle_rejects_rehashed_tampering_unknown_versions_and_noncanonical_json(self):
        bundle = self.directory / "bundle"
        prepare_bundle(os.environ["CITADEL_EVIDENCE_DATA"], bundle)
        originals = {path.name: path.read_bytes() for path in bundle.iterdir()}
        altered_rows = json.loads(originals["reference-data.json"])
        altered_rows["runways"][0]["width_ft"] = "9999"
        altered_profile = json.loads(originals["profile-manifest.json"])
        altered_profile["version"] = 2
        altered_fixture = json.loads(originals["missing-width-replacement-v1.json"])
        altered_fixture["version"] = 2
        for name, content, code in [
            ("reference-data.json", json.dumps(altered_rows).encode(), "data_integrity"),
            ("profile-manifest.json", json.dumps(altered_profile).encode(), "unsupported_version"),
            ("missing-width-replacement-v1.json", json.dumps(altered_fixture).encode(), "unsupported_version"),
            ("reference-data.json", b'{"airports": NaN}', "data_integrity"),
            ("reference-data.json", b'{"airports": 1e999}', "data_integrity"),
            ("reference-data.json", b'{"airports":[],"airports":[]}', "data_integrity"),
        ]:
            with self.subTest(name=name, code=code):
                for filename, original in originals.items():
                    (bundle / filename).write_bytes(original)
                (bundle / name).write_bytes(content)
                manifest = json.loads(originals["bundle-manifest.json"])
                manifest["files"][name] = hashlib.sha256(content).hexdigest()
                (bundle / "bundle-manifest.json").write_text(json.dumps(manifest))
                with self.assertRaises(EvidenceError) as caught:
                    ReferenceData.from_bundle(bundle)
                self.assertEqual(caught.exception.code, code)


if __name__ == "__main__":
    unittest.main()
