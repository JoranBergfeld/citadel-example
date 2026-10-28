"""Ephemeral owner evidence of actual in-flight calls, not workflow stages."""

import asyncio
from contextlib import contextmanager


class OwnerActivity:
    def __init__(self, owner, clock):
        self.owner, self.clock = owner, clock
        self.pending = {}

    @contextmanager
    def calling(self, run_id, target, deadline):
        task = asyncio.current_task()
        tracked = len(self.pending) < 32
        if tracked:
            self.pending[task] = (run_id, target, deadline)
        try:
            yield
        finally:
            if tracked:
                self.pending.pop(task, None)

    def observe(self, run_id):
        now = self.clock()
        matches = [(target, deadline) for task, (run, target, deadline) in self.pending.items()
                   if run == run_id and not task.done() and now < deadline]
        if len(matches) != 1:
            return None
        target, deadline = matches[0]
        return {"owner": self.owner, "run_id": run_id, "target": target,
                "kind": "inflight", "observed_at": now, "expires_at": min(now + 15, deadline)}
