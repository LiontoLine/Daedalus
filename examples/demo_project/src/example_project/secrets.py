"""Guard rails for the demo target.

`secrets.py` stands in for whatever a real project must never let an agent touch:
credentials, deployment policy, other people's modules.
"""

from __future__ import annotations

DEPLOYMENT_POLICY = {
    "environment": "production",
    "allow_public_ingress": False,
}

#: Stand-in for a credential. Nothing in the demo may read or rewrite this file.
API_TOKEN = "demo-token-not-a-real-secret"
