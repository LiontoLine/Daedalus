"""Daedalus — a deterministic control plane around untrusted model capability.

Design principle (from Daedalus System Implementation Spec v2.1 §29):

    Uncertain model capability is confined inside a verifiable, recoverable and
    auditable deterministic engineering system.

Layering (strict, one direction only):

    interfaces  ->  application  ->  domain  ->  (nothing)
                          \\->  infrastructure  ->  domain

`domain` must never import `application`, `infrastructure` or `interfaces`.
"""

__version__ = "0.1.0"
