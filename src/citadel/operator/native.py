"""Actual native tools with pipe-only sensitive inputs and private scratch files."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
import time
from uuid import uuid4

from .state import Blocked, ROOT, private, write_private


# Run the exact isolated Azure CLI distribution, not an application dependency.
# argv visible to the OS contains neither target IDs nor credentials.
AZURE_DRIVER = """
import json, logging, sys
from azure.cli.core import get_default_cli
logging.disable(logging.CRITICAL)
args = json.load(sys.stdin)
sys.exit(get_default_cli().invoke(args))
"""


class Native:
    def __init__(self, config, directory, *, process=subprocess.run):
        self.config, self.directory, self.process = config, Path(directory).absolute(), process
        self.tools = config["tools"]
        self.deadline = None

    @contextmanager
    def document(self, value):
        path = self.directory / ("request-" + uuid4().hex + ".json")
        write_private(path, value)
        try:
            yield str(path)
        finally:
            path.unlink(missing_ok=True)

    def run(self, args, *, data=None, timeout=120, env=None):
        if self.deadline is not None:
            timeout = min(timeout, self.deadline - time.monotonic())
            if timeout <= 0:
                raise Blocked("evidence_collection_deadline")
        environment = os.environ.copy()
        environment.update({"AZURE_CORE_COLLECT_TELEMETRY": "false",
                            "AZURE_CORE_ONLY_SHOW_ERRORS": "true",
                            "AZURE_LOGGING_ENABLE_LOG_FILE": "false"})
        context = self.directory / "azure"
        context.mkdir(mode=0o700, exist_ok=True)
        environment["AZURE_CONFIG_DIR"] = str(private(context, directory=True))
        if env:
            environment.update(env)
        try:
            completed = self.process(args, cwd=ROOT, input=data, capture_output=True,
                                     timeout=timeout, env=environment, umask=0o077)
        except (OSError, subprocess.TimeoutExpired):
            raise Blocked("native_command_unavailable_or_ambiguous") from None
        if completed.returncode:
            raise Blocked("native_command_failed")
        return completed.stdout.decode()

    def az(self, *args, timeout=120):
        try:
            text = self.run([self.tools["azurePython"], "-c", AZURE_DRIVER],
                            data=json.dumps([*args, "--only-show-errors", "--output", "json"]).encode(),
                            timeout=timeout)
        except Blocked:
            raise Blocked("azure_command_failed") from None
        try:
            return json.loads(text) if text.strip() else None
        except ValueError:
            raise Blocked("azure_response_invalid") from None

    def rest(self, method, resource, api, body=None):
        args = ["rest", "--method", method, "--url",
                "https://management.azure.com" + resource + "?api-version=" + api]
        if body is None:
            return self.az(*args)
        with self.document(body) as path:
            return self.az(*args, "--body", "@" + path)

    def collection(self, resource, api):
        result = self.rest("get", resource, api)
        values = list(result["value"])
        link = result.get("nextLink")
        seen = set()
        while link:
            if not link.startswith("https://management.azure.com/") or link in seen or len(seen) >= 100:
                raise Blocked("unsafe_or_unbounded_management_pagination")
            seen.add(link)
            result = self.az("rest", "--method", "get", "--url", link)
            values.extend(result["value"])
            link = result.get("nextLink")
        return values

    def blob(self, account, container, name):
        from azure.core.credentials import AccessToken
        from azure.storage.blob import BlobClient

        native = self

        class OperatorCredential:
            def get_token(self, *scopes, **kwargs):
                value = native.az("account", "get-access-token", "--subscription",
                                  native.config["subscriptionId"], "--resource", "https://storage.azure.com/")
                return AccessToken(value["accessToken"], int(value["expires_on"]))

        # Operator data loading only. Workloads continue using their distinct MI.
        return BlobClient(account, container, name, credential=OperatorCredential(),
                          api_version="2026-10-06", retry_total=0, retry_connect=0,
                          retry_read=0, retry_status=0, connection_timeout=5, read_timeout=30)

    def blob_read(self, account, container, name):
        from azure.core.exceptions import ResourceNotFoundError, AzureError
        sent = False

        def one_get(request):
            nonlocal sent
            if sent:
                raise Blocked("hidden_blob_download_retry")
            sent = True

        try:
            with self.blob(account, container, name) as client:
                stream = client.download_blob(max_concurrency=1, raw_request_hook=one_get)
                if stream.size > 16 * 1024 * 1024:
                    raise Blocked("bootstrap_blob_too_large")
                return stream.readall()
        except ResourceNotFoundError:
            return None
        except AzureError:
            raise Blocked("bootstrap_read_denied_or_unavailable") from None

    def blob_create(self, account, container, name, content):
        from azure.core.exceptions import AzureError
        try:
            with self.blob(account, container, name) as client:
                client.upload_blob(content, overwrite=False, timeout=30)
        except AzureError:
            # Never retry a write after an ambiguous outcome.
            raise Blocked("bootstrap_write_requires_reconciliation") from None

    def blob_pool_lease(self, account, container, name, scope):
        from azure.core.exceptions import AzureError, HttpResponseError
        from azure.storage.blob import BlobLeaseClient
        from uuid import NAMESPACE_URL, uuid5
        try:
            with self.blob(account, container, name) as client:
                lease = BlobLeaseClient(client, lease_id=str(uuid5(
                    NAMESPACE_URL, "citadel-ticket-pool:" + scope)))
                try:
                    lease.acquire(lease_duration=-1, timeout=5)
                except HttpResponseError as exc:
                    if exc.status_code != 409:
                        raise
                    lease.renew(timeout=5)
        except AzureError:
            raise Blocked("observation_descriptor_lease_unverified") from None

    def telemetry(self, workspace_id, *, since, timeout):
        query = (
            "union withsource=CitadelTelemetryTable AppRequests, AppDependencies, AppTraces, "
            "ApiManagementGatewayLogs, StorageBlobLogs, AZKVAuditLogs "
            f"| where TimeGenerated >= datetime({since}) "
            "| project TimeGenerated, Source=CitadelTelemetryTable, "
            "OperationId=tostring(column_ifexists('OperationId','')), "
            "RequestId=tostring(column_ifexists('RequestId','')), "
            "OperationName=tostring(column_ifexists('OperationName','')), "
            "StatusCode=tostring(column_ifexists('ResultCode',column_ifexists('StatusCode',''))), "
            "RunId=tostring(column_ifexists('Properties',dynamic({}))['citadel.run_id']), "
            "ExecutingIdentity=tostring(column_ifexists('RequesterObjectId','')) "
            "| take 100001"
        )
        with self.document({"query": query}) as path:
            result = self.az("rest", "--method", "post", "--url",
                             "https://api.loganalytics.azure.com/v1/workspaces/" + workspace_id + "/query",
                             "--resource", "https://api.loganalytics.io", "--body", "@" + path,
                             timeout=timeout)
        if result.get("error") or not result.get("tables") or any(len(t["rows"]) > 100000 for t in result["tables"]):
            raise Blocked("telemetry_incomplete_or_export_bound_exceeded")
        return result
