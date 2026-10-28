"""Server-only narrow submission. The Planner owns durable idempotence."""

import asyncio

import httpx

from citadel.operations import OperationError, identity
from citadel.runtime.submission import SCENARIOS, submission_run


class SubmissionClient:
    def __init__(self, observation, *, related=()):
        self.observation = observation
        self.related = related

    async def submit(self, request_id, scenario):
        identity(request_id)
        if scenario not in SCENARIOS:
            raise OperationError("invalid_input", "Unsupported scenario")
        run_id = submission_run(request_id)
        observer = self.observation
        try:
            async with asyncio.timeout(30):
                response = await observer.client.post(
                    observer.gateway + "/candidate-planner/operator/scenarios",
                    headers={"Ocp-Apim-Subscription-Key": observer.credential},
                    json={"request_id": request_id, "scenario": scenario}, timeout=30)
                data = response.json()
                if response.status_code == 409:
                    return {"run_id": run_id, "execution": "unknown", "state": "conflict"}
                if response.status_code != 200 or data.get("run_id") != run_id:
                    return {"run_id": run_id, "execution": "unknown", "state": "unknown"}
                return data
        except (httpx.HTTPError, TimeoutError, ValueError, TypeError):
            return {"run_id": run_id, "execution": "unknown", "state": "unknown"}
        finally:
            observer.invalidate(run_id)
            for projection in self.related:
                projection.invalidate(run_id)
