"""Ephemeral owner evidence of actual in-flight calls, not workflow stages."""

import asyncio
from contextlib import contextmanager
from contextvars import ContextVar


_call = ContextVar("citadel_owner_activity", default=None)


def dispatched():
    """Called only after protocol/model admission at the outgoing HTTP boundary."""
    call = _call.get()
    if call is not None:
        call["dispatched_at"] = call["clock"]()


class OwnerActivity:
    def __init__(self, owner, clock):
        self.owner, self.clock = owner, clock
        self.pending = {}

    @contextmanager
    def calling(self, run_id, target, deadline):
        task = asyncio.current_task()
        tracked = len(self.pending) < 32
        call = {"run_id": run_id, "target": target, "deadline": deadline,
                "dispatched_at": None, "clock": self.clock}
        token = _call.set(call if tracked else None)
        if tracked:
            self.pending[task] = call
        try:
            yield
        finally:
            if tracked:
                self.pending.pop(task, None)
            _call.reset(token)

    def observe(self, run_id):
        now = self.clock()
        matches = [call for task, call in self.pending.items()
                   if call["run_id"] == run_id and not task.done()
                   and call["dispatched_at"] is not None and now < call["deadline"]]
        if len(matches) != 1:
            return None
        call = matches[0]
        started = call["dispatched_at"]
        return {"owner": self.owner, "run_id": run_id, "target": call["target"],
                "kind": "inflight", "observed_at": started,
                "expires_at": min(started + 15, call["deadline"])}
