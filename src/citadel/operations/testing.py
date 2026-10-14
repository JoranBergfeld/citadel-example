"""Deterministic ETag/expiry storage boundary. Never use for production persistence."""

import asyncio
import time
from copy import deepcopy

from . import OperationError, empty_ledger


class MemoryLedger:
    def __init__(self, *, clock=time.time):
        self.clock = clock
        self.document, self.etag = empty_ledger(), 0
        self.lock = asyncio.Lock()
        self.lose_response = False
        self.before_commit = None

    async def read(self):
        return deepcopy(self.document), str(self.etag)

    async def commit(self, document, etag, *, deadline):
        if self.before_commit:
            await self.before_commit()
        async with self.lock:
            if self.clock() >= deadline:
                raise OperationError("deadline", "Storage rejected expired commit")
            if str(self.etag) != etag:
                raise OperationError("conflict", "Conditional ETag update lost")
            self.document = deepcopy(document)
            self.etag += 1
            if self.lose_response:
                self.lose_response = False
                raise OperationError("indeterminate", "Committed response was lost")
