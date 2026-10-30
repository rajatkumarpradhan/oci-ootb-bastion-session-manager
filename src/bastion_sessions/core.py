"""Bastion policy engine: validate requests, mint time-boxed sessions, expire them.

Model mirrors OCI Bastion concepts:
- bastion: target subnet + client CIDR allowlist + max session TTL
- session request: target private IP, client CIDR, requested TTL, SSH public key id
- session: accepted request with an expiry; expired sessions are closed
"""
from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, field


class PolicyError(ValueError):
    """A session request that violates the bastion policy."""


@dataclass(frozen=True)
class Bastion:
    name: str
    target_subnet_cidr: str
    client_allowlist: tuple[str, ...]  # CIDRs permitted to open sessions
    max_ttl_seconds: int

    def __post_init__(self):
        ipaddress.ip_network(self.target_subnet_cidr)
        for c in self.client_allowlist:
            ipaddress.ip_network(c)
        if self.max_ttl_seconds <= 0:
            raise ValueError("max_ttl_seconds must be positive")


@dataclass
class Session:
    id: str
    bastion: str
    target_ip: str
    username: str
    client_cidr: str
    ttl_seconds: int
    created_at: int
    state: str = "ACTIVE"

    @property
    def expires_at(self) -> int:
        return self.created_at + self.ttl_seconds


@dataclass
class AuditEvent:
    ts: int
    event: str
    detail: str


def validate_request(b: Bastion, target_ip: str, client_cidr: str,
                     ttl_seconds: int, username: str) -> None:
    """Raise PolicyError unless the request is fully inside bastion policy."""
    target = ipaddress.ip_address(target_ip)
    if target not in ipaddress.ip_network(b.target_subnet_cidr):
        raise PolicyError(f"target {target_ip} is outside bastion subnet {b.target_subnet_cidr}")
    try:
        client = ipaddress.ip_network(client_cidr, strict=False)
    except ValueError as e:
        raise PolicyError(f"bad client cidr {client_cidr!r}") from e
    if not any(client.subnet_of(ipaddress.ip_network(c)) for c in b.client_allowlist):
        raise PolicyError(f"client {client_cidr} is not in the bastion allowlist {list(b.client_allowlist)}")
    if ttl_seconds <= 0:
        raise PolicyError("ttl must be positive")
    if ttl_seconds > b.max_ttl_seconds:
        raise PolicyError(f"ttl {ttl_seconds}s exceeds bastion max {b.max_ttl_seconds}s")
    if not username.strip():
        raise PolicyError("username must not be empty")


class SessionManager:
    """Mints and tracks sessions for one bastion; keeps an audit trail."""

    def __init__(self, bastion: Bastion):
        self.bastion = bastion
        self.sessions: list[Session] = []
        self.audit: list[AuditEvent] = []
        self._seq = 0

    def request_session(self, target_ip: str, client_cidr: str, ttl_seconds: int,
                        username: str, now: int) -> Session:
        validate_request(self.bastion, target_ip, client_cidr, ttl_seconds, username)
        self._seq += 1
        s = Session(id=f"session-{self._seq:03d}", bastion=self.bastion.name,
                    target_ip=target_ip, username=username, client_cidr=client_cidr,
                    ttl_seconds=ttl_seconds, created_at=now)
        self.sessions.append(s)
        self.audit.append(AuditEvent(now, "session.created",
                                     f"{s.id} -> {username}@{target_ip} from {client_cidr} ttl={ttl_seconds}s"))
        return s

    def reject(self, target_ip: str, client_cidr: str, ttl_seconds: int,
               username: str, now: int) -> str:
        """Validate and record a rejection; returns the reason."""
        try:
            validate_request(self.bastion, target_ip, client_cidr, ttl_seconds, username)
        except PolicyError as e:
            self.audit.append(AuditEvent(now, "session.rejected",
                                         f"{username}@{target_ip} from {client_cidr}: {e}"))
            return str(e)
        raise RuntimeError("request is valid; use request_session")

    def expire(self, now: int) -> list[Session]:
        """Close sessions past their TTL; returns the ones closed this call."""
        closed = []
        for s in self.sessions:
            if s.state == "ACTIVE" and now >= s.expires_at:
                s.state = "EXPIRED"
                closed.append(s)
                self.audit.append(AuditEvent(now, "session.expired", f"{s.id} (ttl {s.ttl_seconds}s elapsed)"))
        return closed

    def active(self, now: int) -> list[Session]:
        self.expire(now)
        return [s for s in self.sessions if s.state == "ACTIVE"]

    def audit_lines(self) -> list[str]:
        return [f"{a.ts}  {a.event:16s}  {a.detail}" for a in self.audit]
