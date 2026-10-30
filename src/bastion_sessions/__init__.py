"""Offline OCI Bastion session manager.

Mirrors the built-in OCI Bastion flow: a bastion fronts private resources,
session requests are validated against its allowlist and TTL policy, sessions
are time-boxed and audited. Everything runs locally on synthetic data; no OCI
credentials, SDK, or tenancy are involved.
"""
__version__ = "1.0.0"
