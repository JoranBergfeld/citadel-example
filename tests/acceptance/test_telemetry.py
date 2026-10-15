import io
import json
import unittest

from citadel.acceptance.telemetry import Telemetry, correlate


class TelemetryTests(unittest.TestCase):
    def test_export_records_only_allowlisted_metadata_not_payloads(self):
        output = io.StringIO()
        telemetry = Telemetry("candidate-planner", "11111111-1111-1111-1111-111111111111",
                              output=output)
        with correlate("run1", "op1", "operator"):
            telemetry.emit("SendMessage", request_id="service-id", status_code=202,
                           facts={"generation": 1, "private_notes": "private",
                                  "prompt": "hidden", "read_attempts": 7})
        record = json.loads(output.getvalue())
        self.assertEqual(record["run_id"], "run1")
        self.assertEqual(record["operation_id"], "op1")
        self.assertEqual(record["caller"], "operator")
        self.assertEqual(record["facts"], {"generation": 1, "read_attempts": 7})
        self.assertNotIn("private", output.getvalue())
        self.assertNotIn("11111111", output.getvalue())

    def test_arbitrary_payload_method_or_caller_cannot_enter_logs(self):
        telemetry = Telemetry("candidate-planner", "11111111-1111-1111-1111-111111111111",
                              output=io.StringIO())
        with self.assertRaises(ValueError):
            telemetry.emit("raw prompt", request_id="id", status_code=200)
        with self.assertRaises(ValueError):
            with correlate("run1", "op1", "Bearer private"):
                pass
