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
        self.ticket_store = MemoryTicketStore()

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
            return str(self.etag)


class MemoryTicketStore:
    """Test-only conditional marker/lease transport; share it across process doubles."""
    def __init__(self):
        self.pools, self.markers, self.active = set(), set(), None
        self.active_generation = 0
        self.cursors = {}
        self.lock = asyncio.Lock()

    async def open_pool(self, scope, *, exclusive=False):
        async with self.lock:
            if scope in self.pools:
                return False
            if exclusive and self.active not in (None, scope):
                raise OperationError("conflict", "Another durable run owns admission")
            if exclusive:
                self.active = scope
                self.active_generation = 0
            self.pools.add(scope)
            return True

    async def require_pool(self, scope):
        if scope not in self.pools:
            raise OperationError("missing", "No durably funded read pool")

    async def create_marker(self, scope, index, disposition):
        async with self.lock:
            key = (scope, index)
            if key in self.markers:
                return False
            self.markers.add(key)
            return True

    async def acquire_run(self, scope, *, generation=0):
        async with self.lock:
            if self.active is not None and (self.active, self.active_generation) != (scope, generation):
                raise OperationError("conflict", "Another fenced generation owns admission")
            self.active, self.active_generation = scope, generation

    async def release_run(self, scope, *, generation=0):
        async with self.lock:
            if (self.active, self.active_generation) == (scope, generation):
                self.active = None

    async def bind_finding(self, scope, artifact_id, version):
        await self.open_pool(f"{scope}/finding/{artifact_id}/{version}")

    async def require_finding(self, scope, artifact_id, version):
        await self.require_pool(f"{scope}/finding/{artifact_id}/{version}")
