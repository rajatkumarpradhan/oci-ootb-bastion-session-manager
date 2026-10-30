import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from bastion_sessions.core import Bastion, PolicyError, SessionManager, validate_request

ROOT = Path(__file__).resolve().parents[1]
T0 = 1_793_500_000


def bastion():
    return Bastion("b1", "10.0.2.0/24", ("203.0.113.0/28",), 10800)


class PolicyTests(unittest.TestCase):
    def test_valid_request_accepted(self):
        mgr = SessionManager(bastion())
        s = mgr.request_session("10.0.2.10", "203.0.113.5/32", 3600, "opc", now=T0)
        self.assertEqual(s.state, "ACTIVE")
        self.assertEqual(s.expires_at, T0 + 3600)

    def test_target_outside_subnet_rejected(self):
        with self.assertRaises(PolicyError):
            validate_request(bastion(), "10.0.3.10", "203.0.113.5/32", 3600, "opc")

    def test_client_outside_allowlist_rejected(self):
        with self.assertRaises(PolicyError):
            validate_request(bastion(), "10.0.2.10", "198.51.100.9/32", 3600, "opc")

    def test_ttl_above_max_rejected(self):
        with self.assertRaises(PolicyError):
            validate_request(bastion(), "10.0.2.10", "203.0.113.5/32", 86400, "opc")
        with self.assertRaises(PolicyError):
            validate_request(bastion(), "10.0.2.10", "203.0.113.5/32", 0, "opc")

    def test_bad_inputs_rejected(self):
        with self.assertRaises(PolicyError):
            validate_request(bastion(), "10.0.2.10", "not-a-cidr", 3600, "opc")
        with self.assertRaises(PolicyError):
            validate_request(bastion(), "10.0.2.10", "203.0.113.5/32", 3600, "  ")
        with self.assertRaises(ValueError):
            Bastion("b2", "10.0.9.0/99", (), 100)

    def test_allowlist_subnet_membership(self):
        b = Bastion("b3", "10.0.2.0/24", ("203.0.113.0/28",), 10800)
        validate_request(b, "10.0.2.10", "203.0.113.0/28", 100, "opc")  # whole range ok
        with self.assertRaises(PolicyError):
            validate_request(b, "10.0.2.10", "203.0.113.0/24", 100, "opc")  # wider than allowed


class SessionLifecycleTests(unittest.TestCase):
    def test_expiry_sweep(self):
        mgr = SessionManager(bastion())
        s1 = mgr.request_session("10.0.2.10", "203.0.113.5/32", 1800, "opc", now=T0)
        s2 = mgr.request_session("10.0.2.20", "203.0.113.6/32", 7200, "opc", now=T0)
        self.assertEqual(len(mgr.active(T0 + 100)), 2)
        closed = mgr.expire(T0 + 1800)
        self.assertEqual([s.id for s in closed], [s1.id])
        self.assertEqual([s.id for s in mgr.active(T0 + 1800)], [s2.id])
        mgr.expire(T0 + 7200)
        self.assertEqual(mgr.active(T0 + 7200), [])

    def test_reject_records_audit_reason(self):
        mgr = SessionManager(bastion())
        reason = mgr.reject("10.0.3.10", "203.0.113.5/32", 3600, "opc", now=T0)
        self.assertIn("outside bastion subnet", reason)
        self.assertIn("session.rejected", "\n".join(mgr.audit_lines()))

    def test_reject_on_valid_request_raises(self):
        mgr = SessionManager(bastion())
        with self.assertRaises(RuntimeError):
            mgr.reject("10.0.2.10", "203.0.113.5/32", 3600, "opc", now=T0)

    def test_audit_trail_ordered_and_complete(self):
        mgr = SessionManager(bastion())
        mgr.request_session("10.0.2.10", "203.0.113.5/32", 100, "opc", now=T0)
        mgr.reject("10.0.3.10", "203.0.113.5/32", 100, "opc", now=T0 + 1)
        mgr.expire(T0 + 200)
        kinds = [a.event for a in mgr.audit]
        self.assertEqual(kinds, ["session.created", "session.rejected", "session.expired"])


class DemoTests(unittest.TestCase):
    def test_demo_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            dump = Path(d) / "state.json"
            proc = subprocess.run([sys.executable, "-m", "bastion_sessions.demo", "--dump", str(dump)],
                                  capture_output=True, text=True, cwd=ROOT,
                                  env={"PYTHONPATH": str(ROOT / "src"), "PATH": "/usr/bin:/bin"})
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("ACCEPTED session-001", proc.stdout)
            self.assertIn("REJECTED", proc.stdout)
            self.assertIn("audit trail:", proc.stdout)
            state = json.loads(dump.read_text())
            self.assertEqual(len(state["sessions"]), 2)
            self.assertEqual(len(state["audit"]), 7)  # 2 created + 3 rejected + 2 expired

    def test_validate_script(self):
        proc = subprocess.run([sys.executable, str(ROOT / "scripts" / "validate.py")],
                              capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("validate: OK", proc.stdout)


if __name__ == "__main__":
    unittest.main()
