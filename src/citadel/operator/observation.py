"""Server-only, read-only Planner client and single-process shared view cache."""

import asyncio
from collections import OrderedDict
from copy import deepcopy
from dataclasses import dataclass
import time

import httpx

from citadel.evidence.manifests import sha256
from citadel.operations import OperationError, identity
from citadel.runtime.configuration import endpoint
from citadel.runtime.state import read_deadline


@dataclass
class Observed:
    data: dict | None = None
    last_success: float | None = None
    state: str = "unknown"
    stale: bool = False


class ObservationClient:
    def __init__(self, gateway, credential, admission, *, client=None, clock=time.time):
        self.gateway, self.credential = endpoint(gateway), credential
        self.admission, self.clock = admission, clock
        self.client = client or httpx.AsyncClient(
            transport=httpx.AsyncHTTPTransport(retries=0), follow_redirects=False)
        self.cache, self.inflight, self.aliases = OrderedDict(), {}, {}

    def key(self, run_id, cursor):
        if run_id is not None:
            identity(run_id)
        if cursor is not None:
            identity(cursor)
        return (self.admission.deployment, run_id, "planner-summary" if run_id else "run-list", cursor)

    async def observe(self, run_id=None, *, cursor=None, refresh=False):
        key = self.key(run_id, cursor)
        if key in self.inflight:
            return deepcopy(await asyncio.shield(self.inflight[key]))
        exact_key = self.aliases.get(key)
        previous = self.cache.get(exact_key, Observed())
        if exact_key in self.cache and not refresh:
            return deepcopy(previous)
        if len(self.inflight) >= 32:
            return Observed(previous.data, previous.last_success, "unavailable", previous.data is not None)
        # No await between checking and publishing: all tabs share this task.
        task = asyncio.create_task(self._fetch(key, run_id, cursor, previous))
        self.inflight[key] = task
        task.add_done_callback(lambda completed: self.inflight.pop(key, None))
        return deepcopy(await asyncio.shield(task))

    async def _fetch(self, key, run_id, cursor, previous):
        try:
            async with self.admission.request():
                path = ("/operator/runs/" + run_id if run_id is not None else
                        "/operator/runs/page/" + cursor if cursor else "/operator/runs")
                await self.admission.charge()
                response = await self.client.get(self.gateway + "/candidate-planner" + path,
                    headers={"Ocp-Apim-Subscription-Key": self.credential,
                             "X-Citadel-Observation-Deadline": str(read_deadline.get())},
                    timeout=max(0.001, read_deadline.get() - self.clock()))
                state = {403: "denied", 404: "missing", 429: "exhausted"}.get(response.status_code)
                if response.status_code != 200:
                    raise OperationError(state or "unavailable", "Observation did not succeed")
                data = response.json()
                if not isinstance(data, dict) or data.get("state") not in ("ok", "empty", "partial"):
                    raise OperationError("unavailable", "Unknown observation result")
                observed = Observed(data, self.clock(), data["state"], False)
        except OperationError as exc:
            state = {"forbidden": "denied"}.get(exc.code, exc.code)
            if state not in ("denied", "missing", "exhausted", "unavailable"):
                state = "unavailable"
            observed = Observed(previous.data, previous.last_success, state, previous.data is not None)
        except (httpx.HTTPError, TimeoutError, ValueError, TypeError):
            observed = Observed(previous.data, previous.last_success, "unavailable", previous.data is not None)
        exact = key + (sha256((observed.data or {}).get("bindings", {})),)
        old = self.aliases.get(key)
        if old is not None and old != exact:
            self.cache.pop(old, None)
        self.aliases[key] = exact
        self.cache[exact] = observed
        self.cache.move_to_end(exact)
        while len(self.cache) > 300:
            removed, _ = self.cache.popitem(last=False)
            self.aliases = {k: v for k, v in self.aliases.items() if v != removed}
        return observed

    def invalidate(self, run_id):
        """Explicit future control actions invalidate mutable projections only."""
        for key in list(self.aliases):
            if key[1] == run_id or key[2] == "run-list":
                self.cache.pop(self.aliases.pop(key), None)

    async def close(self):
        for task in self.inflight.values():
            task.cancel()
        await asyncio.gather(*self.inflight.values(), return_exceptions=True)
        await self.client.aclose()
