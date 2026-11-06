"""Shared scan context: one snapshot of processes/connections used by all checks."""
from __future__ import annotations

import os
import re
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Optional

from .. import ioc_data
from ..platform_utils import HAS_PSUTIL, IS_LINUX, is_admin, os_name, psutil


def app_root() -> Path:
    """Folder that holds custom_iocs/ (next to the exe when packaged)."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parents[2]


class ScanContext:
    def __init__(self, window_days: int = 7, deep: bool = False,
                 progress: Optional[Callable[[str], None]] = None,
                 cancel: Optional[threading.Event] = None):
        self.window_days = window_days
        self.window_start = time.time() - window_days * 86400
        self.deep = deep
        self.admin = is_admin()
        self.os = os_name()
        self._progress = progress or (lambda m: None)
        self.cancel = cancel or threading.Event()
        self.processes: list = []
        self.proc_denied = 0
        self.connections: list = []
        self.conn_limited = ""
        self.bad_hashes = dict(ioc_data.BUILTIN_BAD_HASHES)
        self.yara_rules = None
        self.notes: list = []
        self.sensitive: list = []
        self._load_custom_iocs()

    # -- helpers ---------------------------------------------------------------
    def progress(self, msg: str) -> None:
        self._progress(msg)

    @property
    def cancelled(self) -> bool:
        return self.cancel.is_set()

    def in_window(self, ts: Optional[float]) -> bool:
        return bool(ts) and ts >= self.window_start

    def proc_by_pid(self, pid):
        for p in self.processes:
            if p["pid"] == pid:
                return p
        return None

    # -- custom indicators -----------------------------------------------------
    def _load_custom_iocs(self) -> None:
        root = app_root() / "custom_iocs"
        hf = root / "hashes.txt"
        if hf.is_file():
            try:
                for line in hf.read_text(errors="replace").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = re.split(r"[\s,;]+", line, maxsplit=1)
                    h = parts[0].lower()
                    if re.fullmatch(r"[0-9a-f]{64}", h):
                        self.bad_hashes[h] = parts[1] if len(parts) > 1 else "Custom indicator"
            except OSError:
                pass
        rules_dir = root / "rules"
        files = {p.stem: str(p) for p in rules_dir.glob("*.yar*")} if rules_dir.is_dir() else {}
        if files:
            try:
                import yara  # type: ignore
                self.yara_rules = yara.compile(filepaths=files)
            except ImportError:
                self.notes.append("YARA rules found but yara-python is not installed; "
                                  "rule matching skipped.")
            except Exception as e:  # bad rule file
                self.notes.append(f"Could not load YARA rules: {e}")

    # -- process snapshot ------------------------------------------------------
    def snapshot_processes(self) -> None:
        if not HAS_PSUTIL:
            return
        procs = []
        attrs = ["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]
        for p in psutil.process_iter(attrs, ad_value=None):
            info = p.info
            if info.get("exe") is None and info.get("cmdline") is None and info.get("pid", 0) > 4:
                self.proc_denied += 1
            exe = info.get("exe") or ""
            deleted = False
            if IS_LINUX:
                try:
                    link = os.readlink(f"/proc/{info['pid']}/exe")
                    deleted = link.endswith(" (deleted)")
                except OSError:
                    pass
            procs.append({
                "pid": info["pid"],
                "ppid": info.get("ppid"),
                "name": (info.get("name") or "").strip(),
                "exe": exe,
                "cmdline": " ".join(info.get("cmdline") or []),
                "username": info.get("username") or "",
                "create_time": info.get("create_time"),
                "exe_deleted": deleted,
                "cpu": 0.0,
                "_p": p,
            })
        # sample CPU over one second to spot hidden miners
        for pr in procs:
            try:
                pr["_p"].cpu_percent(None)
            except Exception:
                pass
        time.sleep(1.0)
        for pr in procs:
            try:
                pr["cpu"] = pr["_p"].cpu_percent(None)
            except Exception:
                pr["cpu"] = 0.0
        names = {pr["pid"]: pr["name"] for pr in procs}
        for pr in procs:
            pr["parent_name"] = names.get(pr["ppid"], "")
        self.processes = procs

    # -- network snapshot ------------------------------------------------------
    def snapshot_connections(self) -> None:
        if not HAS_PSUTIL:
            return
        conns = []
        try:
            raw = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            raw = []
            self.conn_limited = ("Could not list every program's network connections "
                                 "without administrator rights; only your own programs were checked.")
            for pr in self.processes:
                try:
                    p = pr["_p"]
                    getter = getattr(p, "net_connections", None) or p.connections
                    for c in getter(kind="inet"):
                        raw.append((c, pr["pid"]))
                except Exception:
                    continue
            raw = [_with_pid(c, pid) for c, pid in raw]
        for c in raw:
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
            raddr_ip = c.raddr.ip if c.raddr else ""
            rport = c.raddr.port if c.raddr else None
            pid = getattr(c, "pid", None)
            proc = self.proc_by_pid(pid) if pid else None
            conns.append({
                "pid": pid,
                "process": proc["name"] if proc else "",
                "exe": proc["exe"] if proc else "",
                "local": laddr,
                "remote_ip": raddr_ip,
                "remote_port": rport,
                "status": c.status,
                "type": "TCP" if c.type == 1 else "UDP",
            })
        self.connections = conns


class _Conn:
    def __init__(self, c, pid):
        self.laddr, self.raddr, self.status, self.type = c.laddr, c.raddr, c.status, c.type
        self.pid = pid


def _with_pid(c, pid):
    return _Conn(c, pid)
