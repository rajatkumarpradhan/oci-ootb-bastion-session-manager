#!/usr/bin/env python3
"""Validate the repo: run the demo flow and assert accept/reject/expiry invariants."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from bastion_sessions.demo import T0, run_demo  # noqa: E402


def main() -> int:
    mgr = run_demo()
    problems = []
    if len(mgr.sessions) != 2:
        problems.append(f"expected 2 accepted sessions, got {len(mgr.sessions)}")
    rejected = [a for a in mgr.audit if a.event == "session.rejected"]
    if len(rejected) != 3:
        problems.append(f"expected 3 rejections, got {len(rejected)}")
    expired = [a for a in mgr.audit if a.event == "session.expired"]
    if len(expired) != 2:
        problems.append(f"expected 2 expiries, got {len(expired)}")
    if mgr.active(T0 + 7500):
        problems.append("sessions still active after final sweep")
    for p in problems:
        print(f"FAIL  {p}")
    if problems:
        print(f"validate: {len(problems)} problem(s)")
        return 1
    print("validate: OK (2 accepted, 3 rejected, 2 expired, none active after sweep)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
