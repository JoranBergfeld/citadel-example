"""Gateway-only ASGI authorization; no HTTP forwarding or credential fallback."""

from .trust import GatewayTrust, TrustConfiguration

__all__ = ["GatewayTrust", "TrustConfiguration"]
