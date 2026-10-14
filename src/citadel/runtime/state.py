"""Per-task read envelopes without a process-wide counter or mutable shared allowance."""

import time
from contextlib import contextmanager
from contextvars import ContextVar

from citadel.operations import OperationError
from citadel.operations.blob import AzureBlobLedger
from citadel.operations.limits import ReadAllowance


reads = ContextVar("citadel_prepaid_reads", default=None)


@contextmanager
def read_scope(allowance):
    token = reads.set(allowance)
    try:
        yield
    finally:
        reads.reset(token)


def control_reads(count, *, clock=time.time):
    """Fixed-purpose admission/status only; never used by workflow execution."""
    return read_scope(ReadAllowance(count, clock() + 10, clock))


class ScopedLedger:
    def __init__(self, ledger):
        self.ledger = ledger

    async def read(self):
        allowance = reads.get()
        if allowance is None:
            raise OperationError("exhausted", "No admitted read envelope")
        if isinstance(self.ledger, AzureBlobLedger):
            reader = AzureBlobLedger(self.ledger.client, clock=self.ledger.clock,
                                     read_allowance=allowance)
            return await reader.read()
        allowance.take()
        return await self.ledger.read()

    async def commit(self, document, etag, *, deadline):
        return await self.ledger.commit(document, etag, deadline=deadline)
