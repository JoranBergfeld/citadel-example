"""Local signing fixtures shared with optional protocol diagnostics."""

import base64
import hashlib
import hmac
import time
from datetime import datetime, timedelta, timezone

from citadel.gateway import TrustConfiguration


KEY = "runtime-test-only-context-secret-32bytes"
PIN = "a" * 64


def trust(target):
    now = datetime.now(timezone.utc)
    return TrustConfiguration(target, {PIN: (now - timedelta(days=1), now + timedelta(days=89))},
                              {"test": KEY})


def signed(body, target, path, caller="candidate-planner", method="POST", request_id="test-request"):
    timestamp = str(int(time.time()))
    canonical = "\n".join(("v1", "test", timestamp, request_id, caller, target,
                           method, path, hashlib.sha256(body).hexdigest()))
    return {
        "x-forwarded-client-cert": f"Hash={PIN}",
        "x-citadel-key-id": "test", "x-citadel-timestamp": timestamp,
        "x-citadel-request-id": request_id, "x-citadel-caller": caller,
        "x-citadel-target": target,
        "x-citadel-signature": base64.b64encode(hmac.digest(KEY.encode(), canonical.encode(), "sha256")).decode(),
    }
