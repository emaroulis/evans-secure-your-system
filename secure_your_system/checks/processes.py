"""Running-program analysis: malware locations, disguises, hacking tools, scripts."""
from __future__ import annotations

import os
import re

from .. import ioc_data as ioc
from ..models import CheckResult, Finding, Severity
from ..platform_utils import (HAS_PSUTIL, IS_LINUX, IS_MAC, IS_WINDOWS, norm,
                              path_in, powershell, run_cmd, temp_dirs, user_drop_dirs)

NAME = "Running programs"
# Real Windows programs whose names happen to be one letter from another.
_LEGIT_LOOKALIKES = {"taskhost.exe", "taskhostex.exe", "csrss.exe", "lsass.exe",
                     "lsm.exe", "dwm.exe", "smss.exe"}


def _base(name: str) -> str:
    n = (name or "").lower()
    return n[:-4] if n.endswith(".exe") else n


def _lev1(a: str, b: str) -> bool:
    """True if a and b differ by exactly one edit (typo-squatting)."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diffs = sum(x != y for x, y in zip(a, b))
        if diffs == 1:
            return True
        # adjacent swap
        idx = [i for i in range(len(a)) if a[i] != b[i]]
        return len(idx) == 2 and idx[1] == idx[0] + 1 and a[idx[0]] == b[idx[1]] and a[idx[1]] == b[idx[0]]
    if len(a) > len(b):
        a, b = b, a
    i = j = 0
    skipped = False
    while i < len(a) and j < len(b):
        if a[i] != b[j]:
            if skipped:
                return False
            skipped = True
            j += 1
        else:
            i += 1
            j += 1
    return True


def _signature_status(paths: list) -> dict:
    """Check code signatures for a short list of flagged executables."""
    out = {}
    paths = [p for p in paths if p and os.path.isfile(p)][:25]
    if not paths:
        return out
    if IS_WINDOWS:
        quoted = ",".join("'" + p.replace("'", "''") + "'" for p in paths)
        res = powershell(
            f"@({quoted}) | ForEach-Object {{ $s = Get-AuthenticodeSignature -LiteralPath $_; "
            f"\"$($_)|$($s.Status)|$($s.SignerCertificate.Subject)\" }}", timeout=60)
        for line in (res or "").splitlines():
            parts = line.split("|")
            if len(parts) >= 2:
                out[norm(parts[0])] = (parts[1], parts[2] if len(parts) > 2 else "")
    elif IS_MAC:
        for p in paths:
            r = run_cmd(["codesign", "-dv", "--verbose=2", p], timeout=10)
            out[norm(p)] = ("Valid" if r is not None else "NotSigned", "")
    return out


def run(ctx) -> CheckResult:
    res = CheckResult(NAME)
    if not HAS_PSUTIL:
        res.ran = False
        res.error = "The 'psutil' package is not installed, so running programs could not be examined."
        return res
    if ctx.proc_denied:
        res.limited.append(
            f"{ctx.proc_denied} program(s) belong to other users or the system and could only be partly "
            + ("examined (protected processes)." if ctx.admin else "examined without administrator rights."))

    temps = temp_dirs()
    drops = user_drop_dirs()
    flagged_paths = []
    procs = ctx.processes
    res.stats["processes"] = len(procs)

    for p in procs:
        name, exe, cmd = p["name"], p["exe"], p["cmdline"]
        lname, base = name.lower(), _base(name)
        parent = (p.get("parent_name") or "").lower()
        common = dict(check=NAME, pid=p["pid"], first_seen=p["create_time"],
                      paths=[exe] if exe else [])
        ev = {"Process": name, "PID": p["pid"], "Path": exe or "(hidden)",
              "Started by": p.get("parent_name") or "?", "User": p["username"],
              "Command line": cmd[:400]}

        # 1. Fake system process (right name, wrong folder)
        if IS_WINDOWS and lname in ioc.WINDOWS_SYSTEM_BINARIES and exe:
            if not any(d in norm(exe) for d in ioc.WINDOWS_SYSTEM_BINARIES[lname]):
                res.findings.append(Finding(
                    title=f"Fake Windows system process: {name}",
                    severity=Severity.CRITICAL, category="malware",
                    description=(f"'{name}' is a core Windows process name, but this copy runs from "
                                 f"an unusual folder. Malware commonly disguises itself this way."),
                    evidence=ev, **common))
                flagged_paths.append(exe)
                continue
        if IS_LINUX and base.split("/")[0] in ioc.LINUX_MASQUERADE_NAMES and exe:
            res.findings.append(Finding(
                title=f"Program pretending to be a kernel thread: {name}",
                severity=Severity.CRITICAL, category="malware",
                description=("Real kernel threads have no program file on disk. This process uses a "
                             "kernel-thread name but runs a file, a known trick of Linux malware "
                             "and crypto-miners."),
                evidence=ev, **common))
            flagged_paths.append(exe)
            continue

        # 2. Typo-squatted system names (svch0st.exe, lsasss.exe ...)
        if (IS_WINDOWS or lname.endswith(".exe")) and lname not in _LEGIT_LOOKALIKES:
            for real in ioc.WINDOWS_SYSTEM_BINARIES:
                if _lev1(lname, real):
                    res.findings.append(Finding(
                        title=f"Look-alike of a system program: {name} (mimics {real})",
                        severity=Severity.HIGH, category="malware",
                        description="The name is one character away from a real Windows process, "
                                    "a common disguise.",
                        evidence=ev, **common))
                    flagged_paths.append(exe)
                    break

        # 3. Known hacking / mining / tunnelling tools
        if base in ioc.HACKTOOLS:
            sev = Severity.HIGH if base in {"nc", "plink", "psexec", "procdump", "ncat", "socat", "beacon"} \
                else Severity.CRITICAL
            res.findings.append(Finding(
                title=f"Hacking/abuse tool running: {name}",
                severity=sev, category="malware",
                description=ioc.HACKTOOLS[base] + ". If you did not start this yourself, treat the "
                            "device as compromised.",
                evidence=ev, **common))
            flagged_paths.append(exe)

        # 4. Remote-control software
        if base in ioc.REMOTE_ACCESS or any(base.startswith(r) for r in ("teamviewer", "anydesk", "screenconnect")):
            res.findings.append(Finding(
                title=f"Remote-control software running: {name}",
                severity=Severity.MEDIUM, category="remote_access",
                description=("This program lets someone control the computer remotely. It is "
                             "legitimate when you or your IT team use it, but scammers install it "
                             "to watch screens and steal data."),
                evidence=ev, **common))

        # 5. Running from temp / download folders, or deleted from disk
        if p["exe_deleted"]:
            res.findings.append(Finding(
                title=f"Program running after its file was deleted: {name}",
                severity=Severity.HIGH, category="malware",
                description="The program's file was removed from disk while it kept running. "
                            "Malware does this to hide.",
                evidence=ev, **common))
            flagged_paths.append(exe)
        elif exe and path_in(exe, temps):
            res.findings.append(Finding(
                title=f"Program running from a temporary folder: {name}",
                severity=Severity.HIGH, category="malware",
                description="Legitimate software is rarely run from temp folders; droppers and "
                            "malware frequently are.",
                evidence=ev, **common))
            flagged_paths.append(exe)
        elif exe and IS_LINUX and exe.startswith("/dev/shm"):
            res.findings.append(Finding(
                title=f"Program running from memory-backed folder /dev/shm: {name}",
                severity=Severity.HIGH, category="malware",
                description="/dev/shm is used by Linux malware to avoid leaving files on disk.",
                evidence=ev, **common))
            flagged_paths.append(exe)
        elif exe and path_in(exe, [d for d in drops if d.name in ("Downloads", "Desktop", "Shared", "Public")]):
            res.findings.append(Finding(
                title=f"Program running directly from Downloads/Desktop: {name}",
                severity=Severity.LOW, category="malware",
                description="Often harmless (installers, portable apps), but worth confirming you "
                            "recognise it.",
                evidence=ev, **common))
            flagged_paths.append(exe)

        # 6. Suspicious command lines
        why = ioc.match_cmdline(cmd)
        if why:
            sev = Severity.CRITICAL if "ransomware" in why else Severity.HIGH
            res.findings.append(Finding(
                title=f"Suspicious command: {why}",
                severity=sev, category="malware",
                description=f"'{name}' was started with a command line matching a known attack "
                            f"technique: {why.lower()}.",
                evidence=ev, **common))
            flagged_paths.append(exe)

        # 7. Documents / browsers spawning script hosts
        if lname in ioc.SCRIPT_HOSTS or base in ioc.SCRIPT_HOSTS:
            if parent in ioc.OFFICE_APPS:
                res.findings.append(Finding(
                    title=f"Document opened a script/command shell: {p.get('parent_name')} → {name}",
                    severity=Severity.HIGH, category="malware",
                    description="Office documents and PDFs should not launch command shells. This is "
                                "the classic sign of a malicious attachment (macro malware).",
                    evidence=ev, origin_hints=["Malicious document or email attachment"], **common))
            elif parent in ioc.BROWSERS and lname not in {"bash", "sh", "zsh"}:
                res.findings.append(Finding(
                    title=f"Web browser launched a script host: {p.get('parent_name')} → {name}",
                    severity=Severity.MEDIUM, category="malware",
                    description="Browsers rarely start command shells or script hosts directly; "
                                "this can indicate a malicious download or browser exploit.",
                    evidence=ev, origin_hints=["Web browser / malicious website"], **common))

        # 8. Unknown program using lots of CPU from a user-writable folder (miner)
        if p["cpu"] >= 70 and exe and path_in(exe, temps + drops):
            res.findings.append(Finding(
                title=f"High CPU use by program in a user folder: {name} ({p['cpu']:.0f}%)",
                severity=Severity.MEDIUM, category="malware",
                description="Sustained high CPU from an unrecognised program can indicate a hidden "
                            "cryptocurrency miner.",
                evidence=ev, **common))

    # Signature check on flagged binaries
    sigs = _signature_status(list(dict.fromkeys(p for p in flagged_paths if p)))
    for f in res.findings:
        for path in f.paths:
            s = sigs.get(norm(path))
            if s:
                f.evidence["Digital signature"] = s[0] + (f" ({s[1]})" if s[1] else "")
                if s[0] not in ("Valid",) and f.severity < Severity.HIGH and f.category == "malware":
                    f.severity = Severity(int(f.severity) + 1)
    return res
