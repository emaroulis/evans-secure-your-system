"""Core data structures shared by every part of Secure Your System."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Optional


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.title()


# What area of compromise a finding points to. The analysis engine uses these
# to decide where an attack came from, what was exposed and what to do next.
CATEGORIES = {
    "malware": "Malicious or suspicious software",
    "sniffer": "Network sniffing / traffic interception",
    "exfiltration": "Possible data leaving the device",
    "persistence": "Auto-start / persistence mechanism",
    "remote_access": "Remote-control software",
    "exposure": "Sensitive data at risk",
    "config": "Tampered or weak system setting",
    "posture": "Security protection status",
}


@dataclass
class Finding:
    check: str                    # which scanner module produced it
    title: str                    # short, plain-English headline
    severity: Severity
    category: str                 # key of CATEGORIES
    description: str              # what it is and why it matters
    evidence: dict = field(default_factory=dict)
    paths: list = field(default_factory=list)     # affected file locations
    remotes: list = field(default_factory=list)   # remote "ip:port" endpoints
    pid: Optional[int] = None
    first_seen: Optional[float] = None            # epoch secs, if known
    origin_hints: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "check": self.check,
            "title": self.title,
            "severity": self.severity.label,
            "category": self.category,
            "description": self.description,
            "evidence": {k: _plain(v) for k, v in self.evidence.items()},
            "paths": list(self.paths),
            "remotes": list(self.remotes),
            "pid": self.pid,
            "first_seen": fmt_time(self.first_seen) if self.first_seen else None,
            "origin_hints": list(self.origin_hints),
        }


@dataclass
class CheckResult:
    name: str
    findings: list = field(default_factory=list)
    ran: bool = True
    limited: list = field(default_factory=list)   # parts reduced by permissions
    error: str = ""
    stats: dict = field(default_factory=dict)
    duration: float = 0.0


@dataclass
class SensitiveItem:
    label: str
    kind: str          # e.g. "Browser passwords", "SSH key"
    path: str
    modified: Optional[float] = None
    accessed: Optional[float] = None
    in_window: bool = False
    opened_by: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "kind": self.kind,
            "path": self.path,
            "modified": fmt_time(self.modified),
            "accessed": fmt_time(self.accessed),
            "touched_in_window": self.in_window,
            "opened_by": self.opened_by,
        }


@dataclass
class ScanResult:
    started: float
    finished: float = 0.0
    host: dict = field(default_factory=dict)
    options: dict = field(default_factory=dict)
    checks: list = field(default_factory=list)          # list[CheckResult]
    sensitive: list = field(default_factory=list)       # list[SensitiveItem]
    connections: list = field(default_factory=list)     # snapshot dicts
    analysis: dict = field(default_factory=dict)
    cancelled: bool = False

    @property
    def findings(self) -> list:
        out = []
        for c in self.checks:
            out.extend(c.findings)
        return sorted(out, key=lambda f: (-int(f.severity), f.check, f.title))

    def to_dict(self) -> dict:
        return {
            "tool": "Evan's Secure Your System",
            "started": fmt_time(self.started),
            "finished": fmt_time(self.finished),
            "host": self.host,
            "options": self.options,
            "cancelled": self.cancelled,
            "findings": [f.to_dict() for f in self.findings],
            "checks": [
                {
                    "name": c.name,
                    "ran": c.ran,
                    "findings": len(c.findings),
                    "limited": c.limited,
                    "error": c.error,
                    "stats": c.stats,
                    "seconds": round(c.duration, 2),
                }
                for c in self.checks
            ],
            "sensitive_data": [s.to_dict() for s in self.sensitive],
            "connections": self.connections,
            "analysis": self.analysis,
        }


def fmt_time(ts: Optional[float]) -> str:
    if not ts:
        return ""
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    except (OverflowError, OSError, ValueError):
        return ""


def _plain(v: Any) -> Any:
    if isinstance(v, (str, int, float, bool)) or v is None:
        return v
    if isinstance(v, (list, tuple, set)):
        return [_plain(x) for x in v]
    if isinstance(v, dict):
        return {str(k): _plain(x) for k, x in v.items()}
    return str(v)
