"""Local validation hooks for lifecycle tooling; never retrieve Azure secrets."""

import base64
import re
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs12

from .trust import INVOCATION_CALLERS, TrustConfiguration


def validate_gateway_certificate(pfx_base64: str, allowlist: list[dict]) -> None:
    """Check externally generated material in memory; never generate, persist or return a key."""
    try:
        private_key, certificate, chain = pkcs12.load_key_and_certificates(
            base64.b64decode(pfx_base64, validate=True), None,
        )
        if private_key is None or certificate is None or chain:
            raise ValueError("One self-signed certificate with private key required")
        certificate.verify_directly_issued_by(certificate)
        start, end = certificate.not_valid_before_utc, certificate.not_valid_after_utc
        if (end - start).total_seconds() != 90 * 86400:
            raise ValueError("Gateway certificate validity must be exactly 90 days")
        if not start <= datetime.now(timezone.utc) < end:
            raise ValueError("Gateway certificate is not currently valid")
    except (ValueError, TypeError, InvalidSignature) as error:
        raise ValueError("Invalid gateway certificate import") from error
    metadata = {
        "sha256": certificate.fingerprint(hashes.SHA256()).hex(),
        "not_before": start,
        "not_after": end,
    }
    if not any(
        item["sha256"] == metadata["sha256"]
        and datetime.fromisoformat(item["not_before"]) == start
        and datetime.fromisoformat(item["not_after"]) == end
        for item in allowlist
    ):
        raise ValueError("Imported certificate does not match public allowlist")
    try:
        usage = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH not in usage:
            raise ValueError("Gateway certificate does not allow TLS client authentication")
    except x509.ExtensionNotFound:
        pass


def validate_deployment_inputs(parameters: dict) -> None:
    """Validate resolved (not ARM {value: ...}) inputs without returning secrets."""
    if not re.fullmatch(r"[a-z0-9]{3,12}", parameters.get("deploymentId", "")):
        raise ValueError("deploymentId must be 3-12 lowercase alphanumeric characters")
    applications = parameters.get("applications", {})
    for app in applications.values():
        if not re.fullmatch(r"[a-z0-9]+\.azurecr\.io/[a-z0-9/_.-]+@sha256:[a-f0-9]{64}", app.get("image", "")):
            raise ValueError("Applications require an immutable ACR sha256 digest")
        if not app.get("command") or not isinstance(app.get("args"), list):
            raise ValueError("Actual application command and args arrays are required")
        if any(not isinstance(value, str) or not value for value in app["command"]):
            raise ValueError("Application command must contain nonempty strings")
    if parameters.get("deployRuntime", True) and set(applications) != set(INVOCATION_CALLERS):
        raise ValueError("Exactly five named applications are required")
    certificates = parameters.get("gatewayCertificates", [])
    material = {
        item["sha256"]: (datetime.fromisoformat(item["not_before"]), datetime.fromisoformat(item["not_after"]))
        for item in certificates
    }
    if len(material) != len(certificates):
        raise ValueError("Duplicate certificate allowlist entry")
    context = parameters.get("contextKeys", {})
    if set(context) != set(INVOCATION_CALLERS):
        raise ValueError("Exactly one isolated context-key set per backend is required")
    all_context_keys = []
    for target, entry in context.items():
        TrustConfiguration(target, material, entry["keys"])
        if entry["activeId"] not in entry["keys"]:
            raise ValueError("Active context key missing")
        for key in entry["keys"].values():
            if not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", key):
                raise ValueError("Use 32+ random bytes encoded base64url without padding for context keys")
            all_context_keys.append(key)
    if len(all_context_keys) != len(set(all_context_keys)):
        raise ValueError("Context signing keys must be isolated by backend and rotation version")
    callers = parameters.get("callerKeys", {})
    expected = (set(INVOCATION_CALLERS) - {"reference-data"}) | {"operator"}
    if set(callers) != expected:
        raise ValueError("Exactly four agent and one operator credentials required")
    all_caller_keys = []
    for entry in callers.values():
        for name in ("primary", "secondary"):
            if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", entry[name]):
                raise ValueError("Caller credentials require 32-128 safe characters")
            all_caller_keys.append(entry[name])
    if len(all_caller_keys) != len(set(all_caller_keys)) or set(all_caller_keys) & set(all_context_keys):
        raise ValueError("Caller credentials must be distinct and separate from context keys")
    states = parameters.get("callerStates", dict.fromkeys(expected, "active"))
    if set(states) != expected or set(states.values()) - {"active", "suspended"}:
        raise ValueError("Explicit caller states must be active or suspended")
    if parameters.get("location", "westeurope") != "westeurope":
        raise ValueError("Region substitution is not authorized")
    if not isinstance(parameters.get("modelCapacity"), int) or not 1 <= parameters["modelCapacity"] <= 120:
        raise ValueError("Validated Standard model capacity 1-120 required")
    if not parameters.get("gatewayCertificatePfx"):
        raise ValueError("A real gateway certificate import is required")
    validate_gateway_certificate(parameters["gatewayCertificatePfx"], certificates)
