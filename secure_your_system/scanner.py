"""Runs every check and hands the results to the analysis engine."""
from __future__ import annotations

import threading
import time
import traceback
from typing import Callable, Optional

from . import analysis
from .checks import ALL_CHECKS
from .checks.base import ScanContext
from .models import CheckResult, ScanResult
from .platform_utils import host_info


def run_scan(window_days: int = 7, deep: bool = False,
             progress: Optional[Callable[[str, float], None]] = None,
             cancel: Optional[threading.Event] = None) -> ScanResult:
    progress = progress or (lambda msg, frac: None)
    steps = len(ALL_CHECKS) + 2
    state = {"step": 0}

    def say(msg: str):
        progress(msg, min(state["step"] / steps, 0.99))

    ctx = ScanContext(window_days=window_days, deep=deep, progress=say, cancel=cancel)
    result = ScanResult(started=time.time(), host=host_info(),
                        options={"window_days": window_days, "scan_type": "Deep" if deep else "Quick"})

    say("Taking a snapshot of running programs…")
    ctx.snapshot_processes()
    say("Listing network connections…")
    ctx.snapshot_connections()
    state["step"] = 1

    for mod in ALL_CHECKS:
        if ctx.cancelled:
            result.cancelled = True
            break
        say(f"Checking: {mod.NAME}…")
        t0 = time.time()
        try:
            cr = mod.run(ctx)
        except Exception as e:
            cr = CheckResult(mod.NAME, ran=False, error=f"{type(e).__name__}: {e}")
            cr.stats["trace"] = traceback.format_exc(limit=3)
        cr.duration = time.time() - t0
        result.checks.append(cr)
        state["step"] += 1

    result.sensitive = ctx.sensitive
    result.connections = [
        {k: v for k, v in c.items()} for c in ctx.connections if c.get("remote_ip")
    ][:500]
    say("Analysing results…")
    result.analysis = analysis.analyse(result, ctx)
    result.finished = time.time()
    progress("Scan complete", 1.0)
    return result
