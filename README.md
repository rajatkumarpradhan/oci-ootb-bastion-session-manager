# oci-ootb-bastion-session-manager

Managed access to private OCI instances the way the built-in service does it - offline, on synthetic data.

## The OOTB mapping

OCI **Bastion** is a built-in, managed service for exactly this problem: your instances sit in private subnets with no public IP, and instead of maintaining your own jump box, you create a bastion on the target subnet and open **time-boxed sessions** through it:

1. **Bastion resource** - pinned to a target subnet, with a client CIDR allowlist and a maximum session TTL (3 hours).
2. **Session requests** - SSH (or RDP / port-forwarding) sessions to a private IP in that subnet; accepted only when the client is in the allowlist and the TTL is within the maximum.
3. **Audit** - session create/expire lifecycle lands in OCI Audit automatically.

This repo reproduces that policy + lifecycle locally: a validation engine, time-boxed session records, an expiry sweep, and an audit trail. No credentials or tenancy involved.

## Cost grounding (free)

The Oracle Bastion page lists the service's price, quoted verbatim (checked 2026-10-31):

> Oracle Cloud Infrastructure Bastion | Free

Source: https://www.oracle.com/security/cloud-security/bastion/

**This repo itself provisions nothing and talks to no tenancy** - it runs entirely on local synthetic data, so running it costs nothing.

## Usage

```
PYTHONPATH=src python -m bastion_sessions.demo      # run the scenario: accepts, rejects, expiry sweep, audit
python scripts/validate.py                          # assert the scenario invariants
```

Real demo output:

```
request: opc@10.0.2.10 from 203.0.113.5/32 ttl=3600s  # valid: on-call engineer to app-1
  ACCEPTED session-001, expires at 1793503600
request: opc@10.0.2.10 from 198.51.100.9/32 ttl=3600s  # INVALID: client outside allowlist
  REJECTED client 198.51.100.9/32 is not in the bastion allowlist ['203.0.113.0/28']
...
audit trail:
  1793500000  session.created   session-001 -> opc@10.0.2.10 from 203.0.113.5/32 ttl=3600s
```

## What the engine enforces

- Target IP must be inside the bastion's target subnet CIDR.
- Client CIDR must be a subnet of an allowlist entry (a wider range than allowed is rejected).
- TTL must be positive and within the bastion maximum.
- Sessions expire exactly at creation + TTL; `SessionManager.expire(now)` closes them and writes audit events.
- Every decision - create, reject (with reason), expire - lands in the audit trail in order.

## Honest limits

- **Offline only.** No OCI SDK, credentials, or tenancy. Instances, IPs (documentation ranges 203.0.113.0/24, 198.51.100.0/24) and timelines are synthetic.
- **Policy + lifecycle only.** A real bastion session also involves SSH key upload, plugin/agent or managed-SSH targets, and IAM checks; none of that is simulated. The demo models the decision layer (allowlist, subnet, TTL, expiry, audit), not packet forwarding.
- Session types here map to OCI's `MANAGED_SSH` / `PORT_FORWARDING` sessions in spirit; exact API shapes differ.
- To go live: create a Bastion on the target subnet in the OCI Console, add your egress CIDR to its allowlist, and create a session - those steps need your tenancy and are not done here.

## Tests

```
PYTHONPATH=src python -m unittest discover -s tests
```

12 tests: policy validation (subnet, allowlist incl. wider-than-allowed rejection, TTL, malformed input), session lifecycle and expiry sweep, audit ordering/completeness, demo end-to-end, and the validate script. CI runs the suite, `scripts/validate.py`, and the full demo on every push.

## License

MIT
