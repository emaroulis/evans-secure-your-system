"""Auto-start (persistence) locations: how malware survives a reboot."""
from __future__ import annotations

import glob
import json
import os
import plistlib
import re
from pathlib import Path

from .. import ioc_data as ioc
from ..models import CheckResult, Finding, Severity
from ..platform_utils import (HOME, IS_LINUX, IS_MAC, IS_WINDOWS, file_times, powershell,
                              run_cmd)

NAME = "Auto-start & persistence"

_USERDIR_RE = re.compile(
    r"(\\appdata\\local\\temp\\|\\windows\\temp\\|/tmp/|/var/tmp/|/dev/shm/|\\users\\public\\|"
    r"/users/shared/|\\downloads\\|/downloads/|\\programdata\\[^\\]+\.(exe|dll|bat|ps1|vbs|js)\b|"
    r"\\appdata\\roaming\\[^\\]+\.(exe|dll|bat|ps1|vbs|js)\b)", re.I)
_LOLBIN_RE = re.compile(r"\b(mshta|wscript|cscript|regsvr32|certutil|bitsadmin|msbuild|"
                        r"installutil|rundll32)(\.exe)?\b", re.I)
_HIDDEN_DIR_RE = re.compile(r"[\\/]\.[^\\/\s]+[\\/]")


def assess(cmd: str, hidden_rule: bool = True):
    """Return (severity, reason) for an auto-start command, or None if unremarkable."""
    if not cmd:
        return None
    low = cmd.lower()
    why = ioc.match_cmdline(cmd)
    if why:
        return Severity.HIGH, why
    if _USERDIR_RE.search(low):
        return Severity.HIGH, "starts a program from a temporary or user-writable folder"
    if _LOLBIN_RE.search(low) and not re.search(r"rundll32(\.exe)?\s+\"?c:\\windows\\system32\\", low):
        return Severity.MEDIUM, "uses a Windows script/utility host often abused by malware"
    if hidden_rule and not IS_WINDOWS and _HIDDEN_DIR_RE.search(cmd) and "/.local/" not in cmd and "/.nvm/" not in cmd:
        return Severity.MEDIUM, "starts a program from a hidden folder"
    return None


class _Collector:
    def __init__(self, ctx, res):
        self.ctx, self.res, self.total = ctx, res, 0

    def entry(self, where: str, name: str, cmd: str, path: str = "", mtime=None):
        self.total += 1
        verdict = assess(cmd)
        recent = self.ctx.in_window(mtime)
        if not verdict and not recent:
            return
        sev, why = verdict if verdict else (Severity.LOW, "was added or changed recently")
        if verdict and recent:
            sev = Severity(min(int(sev) + 1, int(Severity.CRITICAL)))
            why += " and was added/changed during the scan window"
        self.res.findings.append(Finding(
            check=NAME, category="persistence", severity=sev,
            title=f"Auto-start entry {('needs review' if not verdict else 'looks suspicious')}: {name}",
            description=(f"This item runs automatically ({where}) and {why}. Malware uses auto-start "
                         "locations to come back after every restart."),
            evidence={"Location": where, "Name": name, "Runs": cmd[:500],
                      "Last changed": _fmt(mtime)},
            paths=[p for p in (path, _exe_from(cmd)) if p], first_seen=mtime))


def _fmt(ts):
    from ..models import fmt_time
    return fmt_time(ts) or "unknown"


def _exe_from(cmd: str) -> str:
    if not cmd:
        return ""
    m = re.match(r'\s*"([^"]+)"', cmd) or re.match(r"\s*(\S+)", cmd)
    p = m.group(1) if m else ""
    return p if os.path.isabs(os.path.expandvars(p)) else ""


# ---------------------------------------------------------------- Windows ----
def _windows(col: _Collector):
    import winreg  # type: ignore
    keys = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]
    for hive, sub in keys:
        hive_name = "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"
        try:
            with winreg.OpenKey(hive, sub) as k:
                i = 0
                while True:
                    try:
                        n, v, _ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    col.entry(f"Registry {hive_name}\\{sub}", n, str(v))
                    i += 1
        except OSError:
            continue

    # Winlogon hijack
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon") as k:
            for val, expected in (("Shell", "explorer.exe"), ("Userinit", "userinit.exe")):
                try:
                    v = str(winreg.QueryValueEx(k, val)[0])
                except OSError:
                    continue
                parts = [x.strip().lower() for x in v.split(",") if x.strip()]
                if any(not x.endswith(expected) for x in parts):
                    col.res.findings.append(Finding(
                        check=NAME, category="persistence", severity=Severity.CRITICAL,
                        title=f"Windows logon '{val}' setting has been changed",
                        description=f"The Winlogon {val} value should only run {expected}. Extra "
                                    "programs here launch at every logon, a known malware technique.",
                        evidence={"Value": v}))
    except OSError:
        pass

    # Startup folders
    for folder in (Path(os.environ.get("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup",
                   Path(os.environ.get("PROGRAMDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\StartUp"):
        for f in glob.glob(str(folder / "*")):
            if f.lower().endswith("desktop.ini"):
                continue
            target = f
            if f.lower().endswith(".lnk"):
                t = powershell(f"(New-Object -ComObject WScript.Shell).CreateShortcut('{f}')."
                               f"TargetPath + ' ' + (New-Object -ComObject WScript.Shell)."
                               f"CreateShortcut('{f}').Arguments", timeout=10)
                target = (t or f).strip()
            col.entry("Startup folder", os.path.basename(f), target, f, file_times(f)[0])

    # Scheduled tasks
    out = powershell(
        "Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | ForEach-Object { "
        "foreach($a in $_.Actions){ [pscustomobject]@{N=$_.TaskPath+$_.TaskName;"
        "E=$a.Execute;A=$a.Arguments;D=$_.Date} } } | ConvertTo-Json -Compress", timeout=60)
    if out:
        try:
            tasks = json.loads(out)
            tasks = tasks if isinstance(tasks, list) else [tasks]
            for t in tasks:
                if not t.get("E"):
                    continue
                name = t.get("N", "")
                cmd = f"{t.get('E') or ''} {t.get('A') or ''}".strip()
                if name.lower().startswith("\\microsoft\\") and not assess(cmd):
                    col.total += 1
                    continue
                col.entry("Scheduled task", name, os.path.expandvars(cmd))
        except ValueError:
            pass
    else:
        col.res.limited.append("Scheduled tasks could not be listed.")

    # Services that run from user folders
    out = powershell("Get-CimInstance Win32_Service | Select-Object Name,DisplayName,PathName,"
                     "StartMode | ConvertTo-Json -Compress", timeout=60)
    if out:
        try:
            svcs = json.loads(out)
            svcs = svcs if isinstance(svcs, list) else [svcs]
            for s in svcs:
                path = s.get("PathName") or ""
                v = assess(path)
                col.total += 1
                if v:
                    col.res.findings.append(Finding(
                        check=NAME, category="persistence", severity=Severity(max(int(v[0]), 3)),
                        title=f"Windows service looks suspicious: {s.get('DisplayName') or s.get('Name')}",
                        description=f"This background service {v[1]}. Malware installs services to "
                                    "run with high privileges at every boot.",
                        evidence={"Service": s.get("Name"), "Runs": path, "Start mode": s.get("StartMode")},
                        paths=[p for p in [_exe_from(path)] if p]))
        except ValueError:
            pass

    # WMI event subscriptions (fileless persistence) - needs admin
    out = powershell("Get-CimInstance -Namespace root\\subscription -ClassName __EventConsumer "
                     "-ErrorAction Stop | Select-Object Name,CommandLineTemplate,ScriptText,"
                     "__CLASS | ConvertTo-Json -Compress", timeout=30)
    if out and out.strip():
        try:
            items = json.loads(out)
            items = items if isinstance(items, list) else [items]
            for it in items:
                if it.get("Name") in ("SCM Event Log Consumer", "BVTConsumer"):
                    continue
                col.res.findings.append(Finding(
                    check=NAME, category="persistence", severity=Severity.HIGH,
                    title=f"WMI event subscription found: {it.get('Name')}",
                    description="WMI subscriptions can run code invisibly with no file on disk. They "
                                "are rare on home computers and favoured by advanced malware.",
                    evidence={"Type": it.get("__CLASS"),
                              "Runs": it.get("CommandLineTemplate") or (it.get("ScriptText") or "")[:400]}))
        except ValueError:
            pass
    elif not col.ctx.admin:
        col.res.limited.append("WMI event subscriptions (hidden fileless persistence) require "
                               "administrator rights to inspect.")


# ------------------------------------------------------------ Linux/macOS ----
def _shell_rc(col: _Collector):
    rcs = [".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".zshenv", ".bash_login",
           ".bash_logout", ".config/fish/config.fish"]
    files = [HOME / r for r in rcs] + [Path("/etc/profile"), Path("/etc/bash.bashrc"),
                                       Path("/etc/zshrc"), Path("/etc/rc.local")]
    files += [Path(p) for p in glob.glob("/etc/profile.d/*.sh")]
    for f in files:
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        mtime = file_times(f)[0]
        hooks, bad, worst = [], [], None
        for ln in text.splitlines():
            s = ln.strip()
            if not s or s.startswith("#"):
                continue
            col.total += 1
            if re.match(r"alias\s+sudo\s*=", s) or re.search(r"\bLD_PRELOAD\s*=", s):
                hooks.append(s[:300])
                continue
            v = assess(s, hidden_rule=False)
            if v:
                bad.append(f"{s[:300]}  ← {v[1]}")
                worst = max(worst or v[0], v[0])
        if hooks:
            col.res.findings.append(Finding(
                check=NAME, category="persistence", severity=Severity.HIGH,
                title=f"Shell start-up file intercepts commands: {f.name}",
                description="Redefining 'sudo' or setting LD_PRELOAD in a start-up file can be "
                            "used to capture your password or inject code into every program.",
                evidence={"File": str(f), "Lines": hooks[:10]}, paths=[str(f)], first_seen=mtime))
        if bad:
            col.res.findings.append(Finding(
                check=NAME, category="persistence", severity=worst,
                title=f"Suspicious command(s) in shell start-up file: {f.name}",
                description="These commands run every time a terminal opens and match attack patterns.",
                evidence={"File": str(f), "Lines": bad[:10]}, paths=[str(f)], first_seen=mtime))


def _cron(col: _Collector):
    user_cron = run_cmd(["crontab", "-l"]) or ""
    for ln in user_cron.splitlines():
        if ln.strip() and not ln.strip().startswith("#"):
            col.entry("Your crontab", ln.strip()[:60], ln)
    files = ["/etc/crontab"] + glob.glob("/etc/cron.d/*") + glob.glob("/var/spool/cron/*") + \
        glob.glob("/var/spool/cron/crontabs/*") + glob.glob("/usr/lib/cron/tabs/*")
    for f in files:
        try:
            text = open(f, errors="replace").read()
        except PermissionError:
            if not col.ctx.admin:
                col.res.limited.append(f"Could not read {f} without root.")
            continue
        except OSError:
            continue
        mt = file_times(f)[0]
        for ln in text.splitlines():
            s = ln.strip()
            if s and not s.startswith("#") and not re.match(r"^\w+=", s):
                col.entry(f"Cron file {f}", s[:60], s, f, mt)


def _linux(col: _Collector):
    _cron(col)
    _shell_rc(col)
    for f in glob.glob(str(HOME / ".config/autostart/*.desktop")) + glob.glob("/etc/xdg/autostart/*.desktop"):
        try:
            m = re.search(r"^Exec=(.*)$", open(f, errors="replace").read(), re.M)
        except OSError:
            continue
        col.entry("Desktop autostart", os.path.basename(f), m.group(1) if m else "", f, file_times(f)[0])
    units = glob.glob(str(HOME / ".config/systemd/user/*.service")) + \
        glob.glob("/etc/systemd/system/*.service") + glob.glob("/etc/systemd/system/*/*.service")
    for f in units:
        if os.path.islink(f):
            continue
        try:
            m = re.search(r"^ExecStart=(.*)$", open(f, errors="replace").read(), re.M)
        except OSError:
            continue
        col.entry("systemd service", os.path.basename(f), m.group(1) if m else "", f, file_times(f)[0])
    pre = Path("/etc/ld.so.preload")
    if pre.exists():
        try:
            content = pre.read_text().strip()
        except OSError:
            content = "(unreadable)"
        if content:
            col.res.findings.append(Finding(
                check=NAME, category="malware", severity=Severity.CRITICAL,
                title="/etc/ld.so.preload is in use (common rootkit technique)",
                description="This file forces a library into every program on the system. It is almost "
                            "never used legitimately and is a hallmark of Linux rootkits that hide files "
                            "and processes.",
                evidence={"Contents": content[:300]}, paths=[str(pre)] + content.split()[:5]))


def _mac(col: _Collector):
    _cron(col)
    _shell_rc(col)
    dirs = [(HOME / "Library/LaunchAgents", "Your LaunchAgents"),
            (Path("/Library/LaunchAgents"), "System LaunchAgents"),
            (Path("/Library/LaunchDaemons"), "System LaunchDaemons")]
    for d, label in dirs:
        for f in glob.glob(str(d / "*.plist")):
            try:
                with open(f, "rb") as fh:
                    pl = plistlib.load(fh)
            except Exception:
                continue
            args = pl.get("ProgramArguments") or ([pl["Program"]] if pl.get("Program") else [])
            cmd = " ".join(str(a) for a in args)
            lbl = str(pl.get("Label", os.path.basename(f)))
            mtime = file_times(f)[0]
            if lbl.startswith("com.apple.") and not cmd.startswith(("/System/", "/usr/libexec/", "/usr/bin/", "/usr/sbin/")):
                col.res.findings.append(Finding(
                    check=NAME, category="persistence", severity=Severity.HIGH,
                    title=f"Item pretends to be from Apple: {lbl}",
                    description="Its name claims to be an Apple component, but it runs a program "
                                "outside Apple's system folders.",
                    evidence={"Plist": f, "Runs": cmd},
                    paths=[p for p in (f, _exe_from(cmd)) if p], first_seen=mtime))
                continue
            col.entry(label, lbl, cmd, f, mtime)


def run(ctx) -> CheckResult:
    res = CheckResult(NAME)
    col = _Collector(ctx, res)
    if IS_WINDOWS:
        _windows(col)
    elif IS_MAC:
        _mac(col)
    elif IS_LINUX:
        _linux(col)
    # authorized SSH keys (all POSIX)
    ak = HOME / ".ssh" / "authorized_keys"
    if ak.exists():
        mt = file_times(ak)[0]
        try:
            n = sum(1 for ln in ak.read_text(errors="replace").splitlines() if ln.strip() and not ln.startswith("#"))
        except OSError:
            n = "?"
        res.stats["authorized_ssh_keys"] = n
        if ctx.in_window(mt):
            res.findings.append(Finding(
                check=NAME, category="persistence", severity=Severity.MEDIUM,
                title="SSH login keys were changed recently",
                description="~/.ssh/authorized_keys controls who can log in to this account without a "
                            "password. Attackers add their own key here for permanent access.",
                evidence={"File": str(ak), "Keys listed": n, "Last changed": _fmt(mt)},
                paths=[str(ak)], first_seen=mt))
    res.stats["autostart_entries_reviewed"] = col.total
    return res
