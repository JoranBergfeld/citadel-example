"""Check supported client construction only; never acquire tokens or send HTTP."""

import unittest

from azure.identity.aio import ManagedIdentityCredential
from azure.keyvault.secrets.aio import SecretClient
from azure.storage.blob.aio import BlobServiceClient


class AzureStackTests(unittest.IsolatedAsyncioTestCase):
    async def test_assigned_identity_clients_accept_explicit_data_api_versions(self):
        async with ManagedIdentityCredential(
            client_id="00000000-0000-0000-0000-000000000001"
        ) as credential:
            async with BlobServiceClient(
                account_url="https://stack.invalid",
                credential=credential,
                api_version="2026-10-06",
            ) as blob:
                self.assertEqual(blob.api_version, "2026-10-06")
            async with SecretClient(
                vault_url="https://stack.invalid",
                credential=credential,
                api_version="2025-07-01",
            ) as secrets:
                self.assertEqual(secrets.api_version, "2025-07-01")


if __name__ == "__main__":
    unittest.main()
