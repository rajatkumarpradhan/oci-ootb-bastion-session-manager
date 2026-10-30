"""Demo: synthetic bastion + private instances, mixed valid/invalid requests, expiry sweep, audit trail."""
import argparse
import json
from pathlib import Path

from .core import Bastion, SessionManager

T0 = 1_793_500_000  # synthetic epoch


def run_demo() -> SessionManager:
    bastion = Bastion(
        name="bastion-prod-app",
        target_subnet_cidr="10.0.2.0/24",       # private app subnet
        client_allowlist=("203.0.113.0/28",),    # corporate egress range (documentation prefix)
        max_ttl_seconds=10800,                   # 3h, the OCI Bastion maximum session TTL
    )
    mgr = SessionManager(bastion)
    print(f"bastion {bastion.name}: subnet {bastion.target_subnet_cidr}, "
          f"allowlist {list(bastion.client_allowlist)}, max ttl {bastion.max_ttl_seconds}s\n")

    requests = [
        # (target, client, ttl, user, offset_s, note)
        ("10.0.2.10", "203.0.113.5/32", 3600, "opc", 0, "valid: on-call engineer to app-1"),
        ("10.0.2.20", "203.0.113.6/32", 7200, "opc", 30, "valid: DBA to db-1"),
        ("10.0.2.10", "198.51.100.9/32", 3600, "opc", 60, "INVALID: client outside allowlist"),
        ("10.0.3.10", "203.0.113.5/32", 3600, "opc", 90, "INVALID: target outside bastion subnet"),
        ("10.0.2.10", "203.0.113.5/32", 86400, "opc", 120, "INVALID: ttl above bastion max"),
    ]
    for target, client, ttl, user, off, note in requests:
        print(f"request: {user}@{target} from {client} ttl={ttl}s  # {note}")
        try:
            s = mgr.request_session(target, client, ttl, user, now=T0 + off)
            print(f"  ACCEPTED {s.id}, expires at {s.expires_at}")
        except Exception as e:
            print(f"  REJECTED {mgr.reject(target, client, ttl, user, now=T0 + off)}")

    print(f"\nactive sessions at t+1h: {len(mgr.active(T0 + 3600))}")
    print("sweeping expiry at t+2h05m ...")
    for s in mgr.expire(T0 + 7500):
        print(f"  expired {s.id} ({s.username}@{s.target_ip})")
    print(f"active sessions at t+2h05m: {len(mgr.active(T0 + 7500))}")

    print("\naudit trail:")
    for line in mgr.audit_lines():
        print(f"  {line}")
    return mgr


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="bastion-session-demo",
                                 description="Offline OCI Bastion session-manager demo (synthetic data).")
    ap.add_argument("--dump", help="write sessions + audit trail to this JSON file")
    a = ap.parse_args(argv)
    mgr = run_demo()
    if a.dump:
        Path(a.dump).write_text(json.dumps({
            "bastion": {"name": mgr.bastion.name, "target_subnet_cidr": mgr.bastion.target_subnet_cidr,
                        "client_allowlist": list(mgr.bastion.client_allowlist),
                        "max_ttl_seconds": mgr.bastion.max_ttl_seconds},
            "sessions": [{**vars(s)} for s in mgr.sessions],
            "audit": [vars(e) for e in mgr.audit],
        }, indent=2) + "\n")
        print(f"\nwrote session state to {a.dump}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
