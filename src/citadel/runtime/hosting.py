"""Real Azure construction and lifespan; no local/developer credential fallback."""

import asyncio
import os
from contextlib import AsyncExitStack, asynccontextmanager

from azure.identity.aio import ManagedIdentityCredential
from azure.keyvault.secrets.aio import SecretClient
from citadel.operations.blob import managed_ledger

from .agents import Runtime, agent_application
from .configuration import Configuration
from .model import GovernedModel
from .network import GatewayPeers


@asynccontextmanager
async def application(config):
    async with AsyncExitStack() as stack:
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
            runtime = Runtime(config.target, ledger, model=model, peers=peers, gateway_url=config.gateway,
                              artifacts=artifacts, drafts=drafts, tokens_per_minute=config.tokens_per_minute)
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
