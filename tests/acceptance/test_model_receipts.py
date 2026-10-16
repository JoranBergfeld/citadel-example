import io
import json
import time
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch
from types import SimpleNamespace

import httpx2

from citadel.acceptance.telemetry import configure, correlate
from citadel.operations.limits import Accounting
from citadel.operations.testing import MemoryLedger
from citadel.runtime.model import GovernedModel


class ModelReceiptTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_framework_model_response_exports_only_correlated_usage_and_target(self):
        rows, requests, clock = [], [], [time.time()]

        async def response(request):
            requests.append(request)
            document = {"id": "model-response", "object": "chat.completion", "created": 0,
                    "model": "citadel-gpt-41-mini", "choices": [{"index": 0,
                        "message": {"role": "assistant", "content": "PRIVATE MODEL PROSE"},
                        "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 17, "completion_tokens": 4, "total_tokens": 21}}

            class Stream(httpx2.AsyncByteStream):
                async def __aiter__(self):
                    clock[0] += 2
                    yield json.dumps(document).encode()

            return httpx2.Response(200, headers={"apim-request-id": "actual-model-gateway-receipt"},
                                   stream=Stream())

        accounting = Accounting(MemoryLedger(), workload="candidate-planner")
        await accounting.start_run("run1", deadline=time.time() + 120)
        await accounting.start_agent("run1", "execution1")
        with (patch("citadel.acceptance.monitor.MonitorExporter",
                    lambda *args, **kwargs: SimpleNamespace(emit=rows.append)),
              patch("citadel.acceptance.telemetry._exporter", None), redirect_stdout(io.StringIO())):
            configure("candidate-planner", "11111111-1111-1111-1111-111111111111",
                      client_id="22222222-2222-2222-2222-222222222222", connection_string="fixture")
            async with httpx2.AsyncClient(transport=httpx2.MockTransport(response)) as client:
                model = GovernedModel("candidate-planner", "https://gateway.example",
                                      "allocated-test-key", "citadel-gpt-41-mini", http_client=client,
                                      clock=lambda: clock[0])
                with correlate("run1", "execution1", "candidate-planner"):
                    result = await model.explain(accounting, "run1", "execution1", {"private": "PROMPT"})
                await model.close()
        self.assertEqual(result, "PRIVATE MODEL PROSE")
        self.assertEqual(len(requests), 1)
        row = next(row for row in rows if row["method"] == "chat.completions")
        self.assertEqual({key: row["facts"].get(key) for key in ("input_tokens", "output_tokens", "tokens")},
                         {"input_tokens": 17, "output_tokens": 4, "tokens": 21})
        self.assertEqual(row["facts"]["finished"] - row["facts"]["started"], 2)
        self.assertEqual(row["run_id"], "run1")
        self.assertEqual(row["operation_id"], "execution1")
        self.assertEqual(row["request_id"], "actual-model-gateway-receipt")
        self.assertEqual(len(row["target"]), 64)
        self.assertNotIn("PRIVATE MODEL PROSE", str(rows))
        self.assertNotIn("PROMPT", str(rows))
        self.assertNotIn("allocated-test-key", str(rows))
