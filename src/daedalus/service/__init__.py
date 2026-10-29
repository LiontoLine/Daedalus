"""HTTP service and operator console.

Same-origin by design: one process serves `/api` and the console, so there is no CORS
surface to misconfigure and no second deployment to keep in sync with the control plane.
"""

from daedalus.service.app import create_app, main

__all__ = ["create_app", "main"]
