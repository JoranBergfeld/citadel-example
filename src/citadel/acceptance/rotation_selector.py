"""Select only pending retired material inside APIM; never change backend trust."""

import base64
import copy
from itertools import permutations
from urllib.parse import urlsplit

from citadel.evidence.manifests import sha256
from citadel.gateway.trust import INVOCATION_CALLERS
from citadel.operator.state import ROOT


class RetiredSigner:
    def __init__(self, lifecycle, pending, *, save, admit):
        self.lifecycle, self.pending, self.save, self.admit = lifecycle, pending, save, admit
        self.gateway = lifecycle.value["outputs"]["inventory"]["gateway"]

    def _read(self, resource):
        self.admit()
        return copy.deepcopy(self.lifecycle.native.rest("get", resource, "2024-05-01")["properties"])

    def _write(self, resource, properties):
        self.admit()
        method = "put" if "/policies/" in resource or "/certificates/" in resource else "patch"
        self.lifecycle.native.rest(method, resource, "2024-05-01", {"properties": properties})

    def _certificate(self, properties):
        return {"keyVault": {key: copy.deepcopy(value) for key, value in properties["keyVault"].items()
                             if key in ("secretIdentifier", "identityClientId")}}

    def _certificate_fingerprint(self, properties, credentials):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.serialization.pkcs12 import load_pkcs12
        certificate = load_pkcs12(base64.b64decode(credentials["gatewayCertificatePfx"]), None).cert.certificate
        # APIM publishes SHA-1 metadata; backend authorization still uses SHA-256.
        if properties.get("thumbprint", "").lower() != certificate.fingerprint(hashes.SHA1()).hex():
            raise ValueError("APIM selected certificate differs from the exact pending owned material")

    def switch(self):
        if "selector_intent" in self.pending:
            raise ValueError("A dispatched signer selection requires reconciliation, never replay")
        kind = self.pending["kind"]
        if kind == "certificate":
            matches = [r for r in self.gateway["resources"] if r.endswith("/certificates/gateway-client")]
            if len(matches) != 1:
                raise ValueError("Exact owned gateway certificate required")
            resource = matches[0]
            actual = self._read(resource)
            self._certificate_fingerprint(actual, self.lifecycle.credentials())
            original = self._certificate(actual)
            old = self.pending["old_secret_id"]
            current = original["keyVault"]["secretIdentifier"]
            parsed = urlsplit(old)
            if (parsed.scheme != "https" or parsed.query or parsed.fragment or parsed.username
                    or not parsed.hostname or not parsed.hostname.endswith(".vault.azure.net")
                    or not old.startswith(current.rstrip("/") + "/")
                    or len(parsed.path.split("/")) != 4):
                raise ValueError("Only the pending owned certificate version may be selected")
            retired = copy.deepcopy(original)
            retired["keyVault"]["secretIdentifier"] = old
            changes = [{"name": resource, "before": original, "after": retired}]
        elif kind == "context":
            target = self.pending["target"]
            values = [r for r in self.gateway["contextValues"] if r.endswith("/namedValues/context-" + target)]
            policies = [r["policy"] for r in self.lifecycle.value["outputs"]["inventory"]["gatewayApis"]
                        if r["api"].endswith("/apis/" + target)]
            if len(values) != 1 or len(policies) != 1:
                raise ValueError("Exact owned backend context selectors required")
            current = self.lifecycle.credentials()["contextKeys"][target]
            old = self.pending["old"]["contextKeys"][target]
            policy = self._read(policies[0])
            source = (ROOT / "infra/policies/workload.xml").read_text()
            expected = [source.replace("__TARGET__", target).replace("__KEY_ID__", current["activeId"])
                .replace("__CALLERS__", ", ".join("&quot;" + caller + "&quot;" for caller in callers))
                for callers in permutations(INVOCATION_CALLERS[target])]
            if policy.get("value", "").strip() not in [text.strip() for text in expected]:
                raise ValueError("Only the unchanged pinned gateway policy may select a retired key ID")
            named = self._read(values[0])
            self.admit()
            actual = self.lifecycle.native.rest("post", values[0] + "/listValue", "2024-05-01")["value"]
            encoded = base64.b64encode(current["keys"][current["activeId"]].encode()).decode()
            if actual != encoded or named.get("secret") is not True:
                raise ValueError("Current owned named-value binding differs from the rotation")
            named["value"] = encoded
            stale = copy.deepcopy(named)
            stale["value"] = base64.b64encode(old["keys"][old["activeId"]].encode()).decode()
            old_policy = copy.deepcopy(policy)
            old_policy["value"] = next(text for text in expected if text.strip() == policy["value"].strip()
                                      ).replace(current["activeId"], old["activeId"])
            changes = [{"name": values[0], "before": named, "after": stale},
                       {"name": policies[0], "before": policy, "after": old_policy}]
        else:
            raise ValueError("Only retired certificate/context selectors require gateway writes")
        self.pending["selector_intent"] = {"state": "dispatching", "changes": changes}
        self.save()
        for change in changes:
            self._write(change["name"], change["after"])
            if kind == "certificate":
                self.admit()
                self.lifecycle.native.rest("post", change["name"] + "/refreshSecret", "2024-05-01")
        self._verify("after")
        self.pending["selector_intent"]["state"] = "selected"
        self.save()
        return sha256([change["before"] for change in changes])

    def _verify(self, side):
        for change in self.pending["selector_intent"]["changes"]:
            actual = self._read(change["name"])
            expected = change[side]
            if self.pending["kind"] == "certificate":
                self._certificate_fingerprint(actual, self.pending["old"] if side == "after"
                                              else self.lifecycle.credentials())
                actual = self._certificate(actual)
            elif "/namedValues/" in change["name"]:
                self.admit()
                actual["value"] = self.lifecycle.native.rest(
                    "post", change["name"] + "/listValue", "2024-05-01")["value"]
            if actual != expected:
                raise ValueError("Gateway selector readback differs; retain intent and exclusion")

    def restore(self):
        intent = self.pending["selector_intent"]
        if intent["state"] != "selected":
            raise ValueError("Ambiguous selector intent requires explicit reconciliation")
        self._verify("after")
        intent["state"] = "restoring"
        self.save()
        for change in reversed(intent["changes"]):
            self._write(change["name"], change["before"])
            if self.pending["kind"] == "certificate":
                self.admit()
                self.lifecycle.native.rest("post", change["name"] + "/refreshSecret", "2024-05-01")
        self._verify("before")
        intent["state"] = "restored"
        self.save()
        return sha256([change["before"] for change in intent["changes"]])
