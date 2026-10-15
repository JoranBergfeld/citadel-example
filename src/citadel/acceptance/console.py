"""The approved pinned-CLI console path, restricted to one-shot Reference Data probes."""

import base64
import errno
import hashlib
import json
import math
import os
import re
import select
import signal
import subprocess
import time
from types import SimpleNamespace
from uuid import UUID

from citadel.evidence.manifests import canonical_bytes, sha256
from citadel.operations import identity
from citadel.operator.state import Blocked, ROOT, private
from citadel.runtime.configuration import endpoint
from .reference_worker import PREFIX, validate_request
from .revision import template


DRIVER = """
import importlib.metadata, json, logging, os, sys
logging.disable(logging.CRITICAL)
if importlib.metadata.version("azure-cli") != "2.91.0":
    sys.exit(2)
with os.fdopen(int(os.environ.pop("CITADEL_CONSOLE_REQUEST_FD"))) as stream:
    arguments = json.load(stream)
from azure.cli.core import get_default_cli
sys.exit(get_default_cli().invoke(arguments))
"""


def decode_result(line):
    try:
        if not isinstance(line, bytes) or len(line) > 512 * 1024 or not line.startswith(PREFIX.encode()):
            raise ValueError()
        encoded, digest = line[len(PREFIX):].rsplit(b":", 1)
        content = base64.b64decode(encoded, validate=True)
        if hashlib.sha256(content).hexdigest().encode() != digest:
            raise ValueError()
        value = json.loads(content)
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (ValueError, TypeError, UnicodeError):
        raise Blocked("console_result_integrity_missing") from None


class PtyConsole:
    def __init__(self, native, *, process=subprocess.Popen):
        self.native, self.process = native, process

    def run(self, arguments, *, deadline):
        keys = {"--name", "--resource-group", "--subscription", "--revision",
                "--replica", "--container", "--command"}
        if (not isinstance(arguments, list) or len(arguments) != 16
                or not all(isinstance(value, str) for value in arguments)
                or arguments[:2] != ["containerapp", "exec"]
                or set(arguments[2::2]) != keys
                or type(deadline) not in (int, float) or not math.isfinite(deadline)
                or not time.time() < deadline <= time.time() + 900):
            raise Blocked("fixed_reference_console_required")
        values = dict(zip(arguments[2::2], arguments[3::2]))
        if (values["--container"] != "reference-data"
                or not values["--name"].endswith("-reference-data")
                or not re.fullmatch(
                    r"python -m citadel\.acceptance\.reference_worker --enabled --manifest [A-Za-z0-9+/=]{1,8192}",
                    values["--command"])):
            raise Blocked("fixed_reference_console_required")
        context = self.native.directory / "azure"
        context.mkdir(mode=0o700, exist_ok=True)
        extensions = context / "acceptance-no-extensions"
        extensions.mkdir(mode=0o700, exist_ok=True)
        if any(private(extensions, directory=True).iterdir()):
            raise Blocked("console_extension_override_refused")
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        environment.update({
            "AZURE_CONFIG_DIR": str(private(context, directory=True)),
            "AZURE_EXTENSION_DIR": str(extensions),
            "AZURE_EXTENSION_USE_DYNAMIC_INSTALL": "no",
            "AZURE_CORE_COLLECT_TELEMETRY": "false", "AZURE_CORE_ONLY_SHOW_ERRORS": "true",
            "AZURE_LOGGING_ENABLE_LOG_FILE": "false",
        })
        master, slave = os.openpty()
        process = None
        try:
            with self.native.document([*arguments, "--only-show-errors"]) as path:
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    environment["CITADEL_CONSOLE_REQUEST_FD"] = str(descriptor)
                    process = self.process([self.native.tools["azurePython"], "-c", DRIVER],
                        stdin=slave, stdout=slave, stderr=slave, cwd=ROOT, env=environment,
                        pass_fds=(descriptor,), start_new_session=True, umask=0o077)
                finally:
                    os.close(descriptor)
                os.close(slave)
                slave = None
                buffer, total, result = b"", 0, None
                while time.time() < deadline:
                    if not select.select([master], [], [], max(0, min(1, deadline - time.time())))[0]:
                        continue
                    try:
                        chunk = os.read(master, 4096)
                    except OSError as error:
                        if error.errno == errno.EIO:
                            break
                        raise
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > 1024 * 1024:
                        raise Blocked("console_output_bound_exceeded")
                    buffer += chunk
                    while b"\n" in buffer:
                        line, buffer = buffer.split(b"\n", 1)
                        line = line.rstrip(b"\r")
                        if line.startswith(PREFIX.encode()):
                            if result is not None:
                                raise Blocked("console_duplicate_result")
                            result = decode_result(line)
                if time.time() >= deadline or result is None:
                    raise Blocked("console_outcome_indeterminate")
                if process.wait(timeout=max(.001, deadline - time.time())) != 0:
                    raise Blocked("console_process_incomplete")
                return result
        except (OSError, subprocess.TimeoutExpired):
            raise Blocked("console_outcome_indeterminate") from None
        finally:
            if process is not None and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
            os.close(master)
            if slave is not None:
                os.close(slave)


def reference_template(app, deployed):
    value = template(deployed["properties"]["template"])
    containers = value["containers"]
    assigned = deployed["identity"]["userAssignedIdentities"]
    if (deployed["identity"]["type"] != "UserAssigned" or set(assigned) != {app["identity"]}
            or str(UUID(assigned[app["identity"]]["clientId"])) != app["identityClientId"]
            or str(UUID(assigned[app["identity"]]["principalId"])) != app["identityPrincipalId"]
            or len(containers) != 1 or containers[0]["name"] != "reference-data"
            or containers[0]["image"] != app["image"]
            or not re.fullmatch(r".+@sha256:[a-f0-9]{64}", app["image"])
            or containers[0].get("command") != ["python", "-m", "citadel.runtime"]
            or deployed["properties"]["configuration"]["activeRevisionsMode"] != "Single"):
        raise Blocked("reference_console_image_or_identity_conflict")
    env = {row["name"]: row.get("value") for row in containers[0]["env"]}
    if (len(env) != len(containers[0]["env"]) or env.get("CITADEL_TARGET") != "reference-data"
            or env.get("AZURE_CLIENT_ID") != app["identityClientId"]
            or env.get("AZURE_PRINCIPAL_ID") != app["identityPrincipalId"]
            or {"CITADEL_OPERATIONS_CONTAINER", "CITADEL_SUBSCRIPTION_SECRET_NAME"} & env.keys()):
        raise Blocked("reference_console_readonly_authority_conflict")
    return value


class ConsoleProbe:
    # Six built-in CLI ARM calls; each requests.Session permits at most 30 redirects.
    # This is one conservative local reservation, not 186 prepaid Azure ticket writes.
    CONTROL_CEILING = 186

    def __init__(self, lifecycle, *, admit, console=None):
        self.lifecycle, self.admit = lifecycle, admit
        self.console = console or PtyConsole(lifecycle.native)

    def execute(self, app, workload, run_id, *, mode, storage=None, deadline=None):
        identity(run_id)
        if workload != "reference-data" or app["app"].rsplit("/", 1)[-1] != self.lifecycle.id + "-reference-data":
            raise Blocked("reference_console_only")
        intents = self.lifecycle.value.setdefault("probe_intents", {})
        if run_id in intents:
            raise Blocked("reference_console_intent_requires_reconciliation")
        intent = {"state": "preparing", "workload": workload}
        intents[run_id] = intent
        self.lifecycle.state.save()
        native = self.lifecycle.native
        try:
            self.admit()
            deployed = native.rest("get", app["app"], "2025-01-01")
            original = reference_template(app, deployed)
            revision = deployed["properties"]["latestReadyRevisionName"]
            if (revision != deployed["properties"]["latestRevisionName"]
                    or not re.fullmatch(r"[a-z0-9-]{1,100}", revision)):
                raise Blocked("reference_console_ready_revision_required")
            resource = app["app"] + "/revisions/" + revision
            self.admit()
            active = native.rest("get", resource, "2025-07-01")
            if active["properties"].get("active") is not True or template(active["properties"]["template"]) != original:
                raise Blocked("reference_console_revision_conflict")
            self.admit()
            replicas = native.rest("get", resource + "/replicas", "2025-07-01")
            if replicas.get("nextLink") or len(replicas["value"]) != 1:
                raise Blocked("reference_console_single_replica_required")
            replica = replicas["value"][0]
            containers = replica["properties"]["containers"]
            if (len(containers) != 1 or containers[0].get("name") != "reference-data"
                    or containers[0].get("ready") is not True
                    or not re.fullmatch(r"[a-zA-Z0-9-]{1,200}", replica["name"])):
                raise Blocked("reference_console_ready_container_required")
            request = {"schema_version": 1, "run_id": run_id, "workload": workload,
                "client_id": app["identityClientId"], "mode": mode,
                "deadline": min(deadline or float("inf"), time.time() + 900)}
            if mode == "storage-boundaries":
                request["storage"] = storage
            elif mode == "origin-boundary":
                request["origin"] = endpoint(
                    "https://" + deployed["properties"]["configuration"]["ingress"]["fqdn"],
                    ".azurecontainerapps.io")
                intent["origin"] = request["origin"]
            validate_request(SimpleNamespace(target=workload, client_id=app["identityClientId"],
                operations_container=None, subscription_secret=None), request, enabled=True)
            encoded = base64.b64encode(canonical_bytes(request)).decode()
            pieces = app["app"].split("/")
            if (len(pieces) != 9 or pieces[1] != "subscriptions" or pieces[3] != "resourceGroups"
                    or pieces[5:8] != ["providers", "Microsoft.App", "containerApps"]):
                raise Blocked("reference_console_resource_binding_required")
            arguments = ["containerapp", "exec", "--subscription", str(UUID(pieces[2])),
                "--resource-group", pieces[4], "--name", pieces[8], "--revision", revision,
                "--replica", replica["name"], "--container", "reference-data", "--command",
                "python -m citadel.acceptance.reference_worker --enabled --manifest " + encoded]
            self.admit(self.CONTROL_CEILING)
            intent.update(state="dispatching", manifest=request, manifest_sha256=sha256(request),
                          reserved_control_requests=self.CONTROL_CEILING)
            self.lifecycle.state.save()
            result = self.console.run(arguments, deadline=request["deadline"])
            principal = hashlib.sha256(str(UUID(app["identityPrincipalId"])).encode()).hexdigest()
            if (not isinstance(result, dict) or type(result.get("schema_version")) is not int
                    or result["schema_version"] != 1 or result.get("run_id") != run_id
                    or result.get("manifest_sha256") != intent["manifest_sha256"]
                    or result.get("runtime_identity") != principal
                    or result.get("state") not in ("complete", "blocked")
                    or not isinstance(result.get("observations"), list) or len(result["observations"]) > 36
                    or type(result.get("read_attempts")) is not int or not 0 <= result["read_attempts"] <= 512):
                raise Blocked("reference_console_result_binding_conflict")
            self.admit()
            after = native.rest("get", app["app"], "2025-01-01")
            if (reference_template(app, after) != original
                    or after["properties"]["latestReadyRevisionName"] != revision):
                raise Blocked("reference_console_concurrent_revision_change")
            intent.update(state="observed", sha256=sha256(result))
            self.lifecycle.state.save()
            return result
        except (Blocked, ValueError, KeyError, TypeError, TimeoutError):
            intent["state"] = "indeterminate"
            self.lifecycle.state.save()
            raise Blocked("reference_console_requires_reconciliation") from None
