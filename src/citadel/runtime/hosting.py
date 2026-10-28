"""Real Azure construction and lifespan; no local/developer credential fallback."""

import asyncio
import os
from contextlib import AsyncExitStack, asynccontextmanager

from azure.identity.aio import ManagedIdentityCredential
from azure.keyvault.secrets.aio import SecretClient
from azure.storage.blob.aio import ContainerClient
from citadel.operations.blob import managed_ledger

from .agents import Runtime, agent_application
from .configuration import Configuration
from .model import GovernedModel
from .network import GatewayPeers
from .tickets import AzureTicketStore
from .observation import DeploymentReads, RunIndex


async def _checkpoint_loop():
    from citadel.acceptance.telemetry import checkpoint
    while True:
        await asyncio.sleep(15)
        checkpoint()


async def _stop_checkpoints(task):
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)


@asynccontextmanager
async def application(config):
    from citadel.acceptance.telemetry import configure, finish
    from citadel.acceptance.acceptance_timeout import CachedAcceptanceHold
    acceptance_hold = CachedAcceptanceHold.from_environment(os.environ, workload=config.target)
    from citadel.acceptance.workflow_timeout import WorkflowHold
    workflow_hold = WorkflowHold.from_environment(os.environ, workload=config.target)
    if acceptance_hold is not None and workflow_hold is not None:
        raise ValueError("Only one fixed private runtime hold may be enabled")
    async with AsyncExitStack() as stack:
        configure(config.target, os.environ["AZURE_PRINCIPAL_ID"],
            client_id=config.client_id, connection_string=os.environ["APPLICATIONINSIGHTS_CONNECTION_STRING"])
        stack.callback(finish)
        checkpoint_task = asyncio.create_task(_checkpoint_loop())
        stack.push_async_callback(_stop_checkpoints, checkpoint_task)
        if config.target == "reference-data":
            from .storage import download_reference_bundle
            from .reference import reference_application
            credential = await stack.enter_async_context(ManagedIdentityCredential(client_id=config.client_id))
            reference = await download_reference_bundle(config.blob, credential, ".runtime-reference")
            app = reference_application(reference, config.trust)
        else:
            credential = await stack.enter_async_context(ManagedIdentityCredential(client_id=config.client_id))
            vault = await stack.enter_async_context(SecretClient(
                config.vault, credential, api_version="2025-07-01",
                retry_total=0, connection_timeout=5, read_timeout=30,
            ))
            async with asyncio.timeout(30):
                secret = await vault.get_secret(config.subscription_secret)
            if not secret.value:
                raise ValueError("Allocated subscription credential is absent")
            ledger = await stack.enter_async_context(managed_ledger(
                account_url=config.blob, container=config.operations_container, client_id=config.client_id))
            ticket_container = await stack.enter_async_context(ContainerClient(
                config.blob, config.operations_container, credential=credential,
                api_version="2026-10-06", retry_total=0, retry_connect=0, retry_read=0,
                retry_status=0, connection_timeout=5, read_timeout=30))
            artifacts = drafts = None
            if config.target in ("evidence-assessor", "release-reviewer"):
                artifacts = await stack.enter_async_context(managed_ledger(
                    account_url=config.blob, container="drafts" if config.target == "evidence-assessor" else "findings",
                    client_id=config.client_id))
                if config.target == "release-reviewer":
                    drafts = await stack.enter_async_context(managed_ledger(
                        account_url=config.blob, container="drafts", client_id=config.client_id))
            model = GovernedModel(config.target, config.gateway, secret.value, config.model_deployment)
            peers = GatewayPeers(config.target, config.gateway, secret.value)
            stack.push_async_callback(model.close)
            stack.push_async_callback(peers.close)
            run_index = None
            accounting = await stack.enter_async_context(ContainerClient(
                config.observation_blob,
                "read-accounting", credential=credential, api_version="2026-10-06",
                retry_total=0, retry_connect=0, retry_read=0, retry_status=0,
                connection_timeout=5, read_timeout=30))
            admission = DeploymentReads(AzureTicketStore(accounting), config.deployment_id)
            if config.target == "candidate-planner":
                index_ledger = await stack.enter_async_context(managed_ledger(
                    account_url=config.blob, container=config.operations_container,
                    client_id=config.client_id, blob_name="retained-runs-v1.json"))
                run_index = RunIndex(index_ledger, admission)
            runtime = Runtime(config.target, ledger, model=model, peers=peers, gateway_url=config.gateway,
                              artifacts=artifacts, drafts=drafts, tokens_per_minute=config.tokens_per_minute,
                              ticket_store=AzureTicketStore(ticket_container), acceptance_hold=acceptance_hold,
                              workflow_hold=workflow_hold, run_index=run_index,
                              recovery_admission=admission)
            stack.push_async_callback(runtime.shutdown)
            app = agent_application(runtime, config.trust)
        await stack.enter_async_context(app.app.router.lifespan_context(app.app))
        yield app


class ProductionHost:
    """Listen only after successful startup; failed bootstrap never serves success."""
    def __init__(self, config):
        self.config, self.app = config, None

    async def __call__(self, scope, receive, send):
        if scope["type"] != "lifespan":
            if self.app is None:
                await send({"type": "http.response.start", "status": 503, "headers": []})
                await send({"type": "http.response.body", "body": b""})
                return
            return await self.app(scope, receive, send)
        message = await receive()
        if message["type"] != "lifespan.startup":
            return
        started = False
        try:
            async with application(self.config) as app:
                self.app = app
                await send({"type": "lifespan.startup.complete"})
                started = True
                await receive()
                self.app = None
            await send({"type": "lifespan.shutdown.complete"})
        except Exception:
            # SDK exception text may include credential-bearing URLs or request data.
            await send({"type": "lifespan.shutdown.failed" if started else "lifespan.startup.failed",
                        "message": "Allocated runtime lifecycle failed"})


def create_app():
    return ProductionHost(Configuration.from_environment(os.environ))
