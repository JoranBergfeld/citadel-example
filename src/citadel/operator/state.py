"""Private, locked operator state. Never use a missing file as cloud reconciliation."""

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from uuid import UUID, uuid4

from citadel.evidence.manifests import canonical_bytes


ROOT = Path(__file__).resolve().parents[3]


class Blocked(Exception):
    def __init__(self, code):
        self.code = code


def digest(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def private(path, *, directory=False):
    path = Path(path)
    info = path.lstat()
    if (info.st_uid != os.getuid() or stat.S_ISLNK(info.st_mode)
            or info.st_mode & 0o077
            or (directory and not stat.S_ISDIR(info.st_mode))
            or (not directory and not stat.S_ISREG(info.st_mode))):
        raise Blocked("private_owner_permissions_required")
    return path


def read_private(path):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise Blocked("duplicate_private_input_key")
            value[key] = item
        return value
    return json.loads(private(path).read_text(), object_pairs_hook=unique)


def public_output(value, config, credentials=None):
    sensitive = {config["subscriptionId"], config["publisherEmail"]}
    if credentials:
        sensitive.add(credentials["gatewayCertificatePfx"])
        sensitive.update(v for item in credentials["callerKeys"].values() for v in item.values())
        sensitive.update(v for item in credentials["contextKeys"].values() for v in item["keys"].values())

    def scrub(item):
        if isinstance(item, str):
            for secret in sensitive:
                item = item.replace(secret, "[redacted]")
            return item
        if isinstance(item, list):
            return [scrub(v) for v in item]
        if isinstance(item, dict):
            return {k: scrub(v) for k, v in item.items()
                    if k.lower() not in {"authorization", "credentials", "private_notes", "prompts",
                                         "reviewer_deliberation", "callerkeys", "contextkeys",
                                         "gatewaycertificatepfx", "subscriptionid"}}
        return item
    return scrub(value)


def write_private(path, value):
    write_private_bytes(path, canonical_bytes(value))


def write_private_bytes(path, content):
    path = Path(path)
    pending = path.with_name("." + path.name + "-" + uuid4().hex)
    try:
        fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, path)
    finally:
        pending.unlink(missing_ok=True)


def validate_config(config):
    required = {"deploymentId", "subscriptionId", "tenantId", "publisherEmail",
                "collectorPrincipalIds", "location", "modelCapacity", "modelTokensPerMinute",
                "createResourceGroups", "bundleDir", "tools"}
    if set(config) != required:
        raise Blocked("configuration_fields")
    if not re.fullmatch(r"[a-z0-9]{3,12}", config["deploymentId"]):
        raise Blocked("deployment_id")
    for value in [config["subscriptionId"], config["tenantId"], *config["collectorPrincipalIds"]]:
        UUID(value)
    if not config["collectorPrincipalIds"] or config["location"] != "westeurope":
        raise Blocked("target_configuration")
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", config["publisherEmail"]):
        raise Blocked("publisher_contact")
    if type(config["createResourceGroups"]) is not bool:
        raise Blocked("group_configuration")
    for key, maximum in (("modelCapacity", 120), ("modelTokensPerMinute", 120000)):
        if type(config[key]) is not int or not 1 <= config[key] <= maximum:
            raise Blocked("model_configuration")
    if not config["tools"].get("azurePython"):
        raise Blocked("explicit_azure_cli_interpreter_required")
    return config


def source_fingerprint():
    files = [ROOT / name for name in ("stack.toml", "pyproject.toml", "uv.lock",
                                      "requirements.lock", "Dockerfile", ".dockerignore", "azure.yaml")]
    files += sorted((ROOT / "infra").rglob("*"))
    files += sorted((ROOT / "src/citadel").rglob("*.py"))
    return digest({str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                   for p in files if p.is_file()})


class State:
    def __init__(self, directory):
        self.directory = Path(directory).absolute()

    @contextmanager
    def locked(self, *, create=False):
        if create:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        private(self.directory, directory=True)
        fd = os.open(self.directory / "lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            for stale in self.directory.glob("request-*.json"):
                if re.fullmatch(r"request-[a-f0-9]{32}\.json", stale.name):
                    private(stale).unlink()
            yield self
        except BlockingIOError:
            raise Blocked("operator_state_busy") from None
        finally:
            os.close(fd)

    def load(self):
        self.value = read_private(self.directory / "state.json")
        validate_config(self.value["config"])
        return self.value

    def save(self):
        write_private(self.directory / "state.json", self.value)

    def initialize(self, config):
        validate_config(config)
        expected = {"config": config, "software": source_fingerprint()}
        if (self.directory / "state.json").exists():
            actual = self.load()
            if any(actual[key] != expected[key] for key in expected):
                raise Blocked("immutable_deployment_conflict")
            return
        from datetime import datetime, timezone
        self.value = {**expected, "schema_version": 1, "created": datetime.now(timezone.utc).isoformat(),
                      "phase": "initialized", "inventory": [], "runs": {}, "bootstrap": {},
                      "events": []}
        self.save()

    def event(self, action, status):
        from datetime import datetime, timezone
        self.value["events"].append({"action": action, "status": status,
                                     "time": datetime.now(timezone.utc).isoformat()})
        self.save()
