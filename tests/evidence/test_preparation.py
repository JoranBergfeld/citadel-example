import io
import json
import shutil
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from contextlib import redirect_stderr, redirect_stdout

from citadel.evidence import EvidenceError, ReferenceData
from citadel.evidence.__main__ import main
from citadel.evidence.source import acquire_source


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(__file__).parent / f".scratch-{uuid.uuid4().hex}"
        self.directory.mkdir()
        self.addCleanup(shutil.rmtree, self.directory)

    def test_pinned_acquisition_distinguishes_corruption_access_and_unavailability(self):
        cases = [
            (io.BytesIO(b"not-the-pinned-source"), "data_integrity"),
            (HTTPError("https://example.invalid", 403, "forbidden", {}, None), "forbidden"),
            (OSError("connection unavailable"), "temporary_unavailability"),
        ]
        for response, expected in cases:
            with self.subTest(expected=expected):
                mock_args = {"side_effect": response} if isinstance(response, Exception) else {"return_value": response}
                with patch("citadel.evidence.source.urlopen", **mock_args) as fetch:
                    with self.assertRaises(EvidenceError) as caught:
                        acquire_source(self.directory)
                self.assertEqual(caught.exception.code, expected)
                self.assertEqual(fetch.call_args.args[0],
                    "https://raw.githubusercontent.com/davidmegginson/ourairports-data/"
                    "a5a1ab8c3d9d57568c4bf9a7d398a23a60623830/airports.csv")
                self.assertEqual(list(self.directory.iterdir()), [])
        with self.assertRaises(EvidenceError) as caught:
            ReferenceData.from_directory(self.directory)
        self.assertEqual(caught.exception.code, "temporary_unavailability")
        (self.directory / "airports.csv").write_bytes(b"corrupt")
        with self.assertRaises(EvidenceError) as caught:
            ReferenceData.from_directory(self.directory)
        self.assertEqual(caught.exception.code, "data_integrity")

    def test_local_cli_reports_missing_source_as_unavailable_not_insufficient_evidence(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = main(["gate", "--source-dir", str(self.directory)])
        self.assertEqual(result, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(json.loads(stderr.getvalue())["error"]["code"], "temporary_unavailability")


if __name__ == "__main__":
    unittest.main()
