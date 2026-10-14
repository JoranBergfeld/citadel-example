"""Durably admitted physical reads and ETag-backed request-local snapshots."""

from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy

from citadel.operations import OperationError
from citadel.operations.blob import AzureBlobLedger
from citadel.operations.limits import ReadAllowance


reads = ContextVar("citadel_prepaid_reads", default=None)
snapshots = ContextVar("citadel_read_snapshots", default=None)
read_deadline = ContextVar("citadel_read_deadline", default=None)


@contextmanager
def read_scope(pool, *, deadline, cache=None):
    tokens = (reads.set(pool), snapshots.set({} if cache is None else cache),
              read_deadline.set(deadline))
    try:
        yield
    finally:
        reads.reset(tokens[0])
        snapshots.reset(tokens[1])
        read_deadline.reset(tokens[2])


class ScopedLedger:
    def __init__(self, ledger):
        self.ledger = ledger

    async def read(self):
        pool, cache = reads.get(), snapshots.get()
        if pool is None or cache is None:
            raise OperationError("exhausted", "No durably admitted read scope")
        if self in cache:
            return deepcopy(cache[self])
        deadline = await pool.admit()
        if isinstance(self.ledger, AzureBlobLedger):
            reader = AzureBlobLedger(self.ledger.client, clock=self.ledger.clock,
                                     read_allowance=ReadAllowance(1, deadline, self.ledger.clock))
            result = await reader.read()
        else:
            result = await self.ledger.read()
        cache[self] = deepcopy(result)
        return result

    async def commit(self, document, etag, *, deadline):
        cache = snapshots.get()
        try:
            committed_etag = await self.ledger.commit(document, etag, deadline=deadline)
        except BaseException:
            if cache is not None:
                cache.pop(self, None)
            raise
        if cache is not None:
            if committed_etag is None:
                cache.pop(self, None)
            else:
                cache[self] = (deepcopy(document), committed_etag)
        return committed_etag
