"""Finite distributed read pools using conditional writes, never recursive meter GETs.

Each physical read first creates one immutable spent marker. Delegating N reads
first creates N nonreturnable markers in the parent's pool. Child pools have
exactly that capacity. Failed/ambiguous creates never authorize dispatch.
"""

import asyncio
import time
from uuid import NAMESPACE_URL, uuid5

from azure.core.exceptions import AzureError, HttpResponseError, ResourceExistsError, ResourceNotFoundError
from azure.storage.blob.aio import BlobLeaseClient

from citadel.evidence.manifests import sha256
from citadel.operations import OperationError
from .state import read_deadline


# The assessor's reservation includes eleven reviewer reads and owner polling.
CAPACITY = {"candidate-planner": 512, "evidence-assessor": 22,
            "release-reviewer": 11, "briefing-author": 16}


def run_lease_scope(scope, generation):
    if type(generation) is not int or generation < 0:
        raise OperationError("invalid_input", "Invalid fenced admission generation")
    return scope if generation == 0 else scope + "/generation/" + str(generation)


class TicketPool:
    def __init__(self, store, scope, capacity, *, clock=time.time):
        self.store, self.scope, self.capacity, self.clock = store, scope, capacity, clock

    async def _claim(self, disposition):
        deadline = read_deadline.get()
        if deadline is None or self.clock() >= deadline:
            raise OperationError("deadline", "Read admission deadline expired")
        # Cursor is only a speed hint. Conditional storage creates, including
        # after a lost response or reset cursor, are the sole spending authority.
        index = self.store.cursors.get(self.scope, 0)
        async with asyncio.timeout(max(0, min(30, deadline - self.clock()))):
            while index < self.capacity:
                created = await self.store.create_marker(self.scope, index, disposition)
                self.store.cursors[self.scope] = max(self.store.cursors.get(self.scope, 0), index + 1)
                if created:
                    if self.clock() >= deadline:
                        raise OperationError("deadline", "Read admission completed after its deadline")
                    return min(deadline, self.clock() + 30)
                index += 1
        raise OperationError("exhausted", "Durable run read tickets exhausted")

    async def admit(self):
        return await self._claim("spent")

    async def delegate(self, count):
        if type(count) is not int or count < 1:
            raise OperationError("invalid_input", "Invalid read delegation")
        for _ in range(count):
            await self._claim("delegated")


class AzureTicketStore:
    """Uses only the workload's allocated operations container and explicit MI."""
    def __init__(self, container):
        self.container, self.cursors = container, {}

    def _descriptor(self, scope):
        return self.container.get_blob_client("ticket-pools/" + sha256(scope) + ".json")

    @staticmethod
    def _lease(blob, scope):
        return BlobLeaseClient(blob, lease_id=str(uuid5(NAMESPACE_URL, "citadel-ticket-pool:" + scope)))

    async def require_pool(self, scope):
        try:
            await self._lease(self._descriptor(scope), scope).renew(timeout=5)
        except ResourceNotFoundError:
            raise OperationError("missing", "No durably funded read pool") from None
        except HttpResponseError as exc:
            raise OperationError("forbidden" if exc.status_code == 403 else "indeterminate",
                                 "Read pool lease was not verified") from None
        except AzureError:
            raise OperationError("indeterminate", "Read pool lease response was ambiguous") from None

    async def _acquire(self, blob, scope):
        lease = self._lease(blob, scope)
        try:
            await lease.acquire(lease_duration=-1, timeout=5)
        except HttpResponseError as exc:
            if exc.status_code != 409:
                raise
            await lease.renew(timeout=5)

    async def open_pool(self, scope, *, exclusive=False):
        try:
            await self.require_pool(scope)
            return False
        except OperationError as exc:
            if exc.code != "missing":
                raise
        if exclusive:
            await self.acquire_run(scope)
        descriptor = self._descriptor(scope)
        created = False
        try:
            await descriptor.upload_blob(b'{"kind":"finite-read-pool"}', overwrite=False, timeout=5)
            created = True
        except ResourceExistsError:
            pass
        except AzureError:
            raise OperationError("indeterminate", "Read pool creation was not reconciled") from None
        await self._acquire(descriptor, scope)
        return created

    async def create_marker(self, scope, index, disposition):
        blob = self.container.get_blob_client(f"read-tickets/{sha256(scope)}/{index:03}.json")
        try:
            await blob.upload_blob(disposition.encode(), overwrite=False, timeout=5)
            return True
        except ResourceExistsError:
            return False
        except HttpResponseError as exc:
            if exc.status_code == 412:
                return False
            raise OperationError("forbidden" if exc.status_code == 403 else "indeterminate",
                                 "Read-ticket admission did not complete") from None
        except AzureError:
            raise OperationError("indeterminate", "Read-ticket admission response was ambiguous") from None

    async def acquire_run(self, scope, *, generation=0):
        try:
            # Lifecycle-preinitialized; absence never authorizes a new run.
            await self._acquire(self.container.get_blob_client("active-run-slot.json"),
                                run_lease_scope(scope, generation))
        except HttpResponseError:
            raise OperationError("conflict", "Durable run admission unavailable or already owned") from None
        except AzureError:
            raise OperationError("indeterminate", "Run admission acquisition was ambiguous") from None

    async def release_run(self, scope, *, generation=0):
        try:
            await self._lease(self.container.get_blob_client("active-run-slot.json"),
                              run_lease_scope(scope, generation)).release(timeout=5)
        except HttpResponseError as exc:
            if exc.status_code != 412:
                raise OperationError("indeterminate", "Completed run admission release was not reconciled") from None
        except AzureError:
            raise OperationError("indeterminate", "Completed run admission release response was ambiguous") from None

    async def bind_finding(self, scope, artifact_id, version):
        await self.open_pool(f"{scope}/finding/{artifact_id}/{version}")

    async def require_finding(self, scope, artifact_id, version):
        await self.require_pool(f"{scope}/finding/{artifact_id}/{version}")
