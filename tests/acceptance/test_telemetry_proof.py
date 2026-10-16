import copy
import io
import json
import unittest
from uuid import UUID

from citadel.acceptance.coverage import STORAGE
from citadel.acceptance.monitor import MonitorExporter
from citadel.acceptance.telemetry import Telemetry, correlate
from citadel.acceptance.proof_gate import evaluate_check
from citadel.acceptance.reports import sanitize
from tests.acceptance.test_monitor import Credential, Transport


class TelemetryProofTests(unittest.TestCase):
    def test_actual_exported_stream_counts_require_every_ingested_event_and_healthy_exporter(self):
        from citadel.acceptance.telemetry_proof import collect_application
        identities, records = {}, []
        for index, role in enumerate(STORAGE, 1):
            principal, output = str(UUID(int=index)), io.StringIO()
            exporter = MonitorExporter(role, client_id=principal, principal_id=principal,
                connection_string="InstrumentationKey=33333333-3333-3333-3333-333333333333;"
                                  "IngestionEndpoint=https://westeurope-0.in.applicationinsights.azure.com/",
                credential_factory=Credential, transport=Transport())
            telemetry = Telemetry(role, principal, output=output, exporter=exporter)
            identities[role] = telemetry.identity
            with correlate("run1", "op1", role):
                telemetry.emit("execution", request_id=role + "-service", status_code=201)
            telemetry.finish()
            records.extend(json.loads(line) | {"source": "application", "observed": 100}
                           for line in output.getvalue().splitlines())
        report = {"runtime_identities": identities, "operation_ids": ["run1", "op1"], "evidence": records,
                  "checks": [], "started": 90, "finished": 101}
        check = collect_application(report)
        self.assertEqual(evaluate_check(check, report)["status"], "pass")
        self.assertEqual(evaluate_check(sanitize(check), sanitize(report))["status"], "pass")
        self.assertEqual(check["actual"]["count"], 5)
        for changes in (
            records[1:],
            [row | {"source": "console"} for row in records],
            [row for row in records if row["method"] != "exporter.health"],
            [*records, records[0]],
        ):
            self.assertEqual(evaluate_check(check, report | {"evidence": changes})["status"], "blocked")
        altered = copy.deepcopy(report)
        next(row for row in altered["evidence"] if row["method"] == "exporter.health")["facts"]["failed_records"] = 1
        self.assertEqual(evaluate_check(check, altered)["status"], "fail")
        altered = copy.deepcopy(report)
        next(row for row in altered["evidence"] if row["method"] == "exporter.health")["facts"]["stream_sha256"] = "f" * 64
        self.assertEqual(evaluate_check(check, altered)["status"], "fail")
