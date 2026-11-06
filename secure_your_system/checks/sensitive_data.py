"""Inventory of sensitive data stores and who has them open."""
from __future__ import annotations

import glob
import os
import stat
from pathlib import Path

from .. import ioc_data as ioc
from ..models import CheckResult, Finding, SensitiveItem, Severity
from ..platform_utils import HAS_PSUTIL, HOME, IS_MAC, IS_WINDOWS, file_times, norm

NAME = "Sensitive data exposure"

# (kind, label, glob pattern relative to a base, reader group or None)
_CHROMIUM = {
    "Google Chrome": "Google/Chrome/User Data" if IS_WINDOWS else (
        "Library/Application Support/Google/Chrome" if IS_MAC else ".config/google-chrome"),
    "Microsoft Edge": "Microsoft/Edge/User Data" if IS_WINDOWS else (
        "Library/Application Support/Microsoft Edge" if IS_MAC else ".config/microsoft-edge"),
    "Brave": "BraveSoftware/Brave-Browser/User Data" if IS_WINDOWS else (
        "Library/Application Support/BraveSoftware/Brave-Browser" if IS_MAC else ".config/BraveSoftware/Brave-Browser"),
    "Chromium": "Chromium/User Data" if IS_WINDOWS else (
        "Library/Application Support/Chromium" if IS_MAC else ".config/chromium"),
}
_METAMASK = "nkbihfbeogaeaoehlefnkodbefgpgknn"


def _targets() -> list:
    t = []
    local = Path(os.environ.get("LOCALAPPDATA", HOME)) if IS_WINDOWS else HOME
    roam = Path(os.environ.get("APPDATA", HOME)) if IS_WINDOWS else HOME
    support = HOME / "Library/Application Support"

    for browser, rel in _CHROMIUM.items():
        base = local / rel
        t += [("Saved browser passwords", f"{browser} passwords", str(base / "*" / "Login Data"), "browser"),
              ("Browser cookies / logged-in sessions", f"{browser} cookies", str(base / "*" / "Network" / "Cookies"), "browser"),
              ("Browser cookies / logged-in sessions", f"{browser} cookies", str(base / "*" / "Cookies"), "browser"),
              ("Saved cards & autofill", f"{browser} autofill/cards", str(base / "*" / "Web Data"), "browser"),
              ("Crypto wallet", f"MetaMask ({browser})", str(base / "*" / "Local Extension Settings" / _METAMASK), "browser")]
    ff = roam / "Mozilla/Firefox/Profiles" if IS_WINDOWS else (
        support / "Firefox/Profiles" if IS_MAC else HOME / ".mozilla/firefox")
    t += [("Saved browser passwords", "Firefox passwords", str(ff / "*" / "logins.json"), "browser"),
          ("Saved browser passwords", "Firefox key database", str(ff / "*" / "key4.db"), "browser"),
          ("Browser cookies / logged-in sessions", "Firefox cookies", str(ff / "*" / "cookies.sqlite"), "browser")]

    if IS_WINDOWS:
        t += [("Saved browser passwords", "Opera passwords", str(roam / "Opera Software/Opera Stable/Login Data"), "browser"),
              ("Windows saved credentials", "Credential Manager", str(roam / "Microsoft/Credentials/*"), None),
              ("Windows saved credentials", "Credential Manager (local)", str(local / "Microsoft/Credentials/*"), None),
              ("Chat app session", "Discord login token", str(roam / "discord/Local Storage/leveldb"), None),
              ("Chat app session", "Telegram session", str(roam / "Telegram Desktop/tdata"), None),
              ("Crypto wallet", "Exodus wallet", str(roam / "Exodus/exodus.wallet"), None),
              ("Crypto wallet", "Electrum wallets", str(roam / "Electrum/wallets/*"), None),
              ("FTP/server logins", "FileZilla saved servers", str(roam / "FileZilla/*.xml"), None),
              ("Email data", "Outlook mailbox files", str(local / "Microsoft/Outlook/*.[op]st"), None)]
    elif IS_MAC:
        t += [("System keychain / passwords", "macOS login keychain", str(HOME / "Library/Keychains/login.keychain-db"), None),
              ("Browser cookies / logged-in sessions", "Safari cookies", str(HOME / "Library/Cookies/Cookies.binarycookies"), "browser"),
              ("Chat app session", "Discord login token", str(support / "discord/Local Storage/leveldb"), None),
              ("Chat app session", "Telegram session", str(support / "Telegram Desktop/tdata"), None),
              ("Crypto wallet", "Exodus wallet", str(support / "Exodus/exodus.wallet"), None),
              ("FTP/server logins", "FileZilla saved servers", str(HOME / ".config/filezilla/*.xml"), None)]
    else:
        t += [("System keychain / passwords", "GNOME keyring", str(HOME / ".local/share/keyrings/*"), None),
              ("Chat app session", "Discord login token", str(HOME / ".config/discord/Local Storage/leveldb"), None),
              ("Chat app session", "Telegram session", str(HOME / ".local/share/TelegramDesktop/tdata"), None),
              ("FTP/server logins", "FileZilla saved servers", str(HOME / ".config/filezilla/*.xml"), None)]

    t += [("SSH private key", "SSH key", str(HOME / ".ssh" / "id_*"), "ssh"),
          ("Crypto wallet", "Electrum wallets", str(HOME / ".electrum/wallets/*"), None),
          ("Cloud credentials", "AWS access keys", str(HOME / ".aws/credentials"), None),
          ("Cloud credentials", "Azure CLI tokens", str(HOME / ".azure/msal_token_cache.*"), None),
          ("Cloud credentials", "Google Cloud credentials", str(HOME / ".config/gcloud/credentials.db"), None),
          ("Cloud credentials", "Kubernetes config", str(HOME / ".kube/config"), None),
          ("Developer tokens", "Docker registry logins", str(HOME / ".docker/config.json"), None),
          ("Developer tokens", "Git saved credentials", str(HOME / ".git-credentials"), None),
          ("Developer tokens", ".netrc logins", str(HOME / ".netrc"), None),
          ("Developer tokens", "npm token", str(HOME / ".npmrc"), None),
          ("Developer tokens", "PyPI token", str(HOME / ".pypirc"), None),
          ("PGP private keys", "GnuPG private keys", str(HOME / ".gnupg/private-keys-v1.d"), None),
          ("Command history", "Shell history (may contain typed passwords)", str(HOME / ".*_history"), None)]
    for folder in ("Documents", "Desktop", "Downloads", "OneDrive", "Dropbox"):
        d = HOME / folder
        t += [("Password manager vault", "KeePass database", str(d / "**" / "*.kdbx"), None),
              ("VPN configuration", "VPN profile", str(d / "**" / "*.ovpn"), None),
              ("Personal documents", "File that looks like a password list", str(d / "*passw*"), None),
              ("Personal documents", "Tax / identity document", str(d / "*[Tt]ax*.pdf"), None),
              ("Secrets file", ".env secrets file", str(d / "**" / ".env"), None)]
    return t


def _open_handles(ctx, res) -> dict:
    """Map normalised path -> set of process names that have it open."""
    out = {}
    if not HAS_PSUTIL:
        return out
    denied = 0
    for p in ctx.processes:
        try:
            for f in p["_p"].open_files():
                out.setdefault(norm(f.path), set()).add(p["name"])
        except Exception:
            denied += 1
    if denied and not ctx.admin:
        res.limited.append(f"Could not see which files {denied} programs have open (needs administrator rights).")
    return out


def run(ctx) -> CheckResult:
    res = CheckResult(NAME)
    handles = _open_handles(ctx, res)
    items, seen = [], set()
    for kind, label, pattern, group in _targets():
        for path in glob.glob(pattern, recursive="**" in pattern)[:50]:
            if path.endswith(".pub") or norm(path) in seen:
                continue
            seen.add(norm(path))
            m, a, _ = file_times(path)
            item = SensitiveItem(label=label, kind=kind, path=path, modified=m, accessed=a,
                                 in_window=ctx.in_window(m) or ctx.in_window(a))
            readers = set()
            np = norm(path)
            for hp, names in handles.items():
                if hp == np or hp.startswith(np + os.sep):
                    readers |= names
            item.opened_by = sorted(readers)
            items.append(item)

            if group and readers:
                allowed = ioc.EXPECTED_READERS.get(group, set())
                odd = [r for r in readers if r.lower() not in allowed and r.lower().removesuffix(".exe") not in allowed]
                if odd:
                    res.findings.append(Finding(
                        check=NAME, category="exposure", severity=Severity.HIGH,
                        title=f"Unexpected program is reading your {kind.lower()}: {', '.join(odd)}",
                        description=(f"{', '.join(odd)} has '{label}' open. Only the matching app should touch "
                                     "this file. Password-stealing malware (infostealers) reads exactly these files."),
                        evidence={"File": path, "Opened by": odd}, paths=[path]))

            if kind == "SSH private key" and not IS_WINDOWS:
                try:
                    mode = os.stat(path).st_mode
                    if mode & (stat.S_IRGRP | stat.S_IROTH):
                        res.findings.append(Finding(
                            check=NAME, category="config", severity=Severity.MEDIUM,
                            title=f"SSH private key readable by other users: {os.path.basename(path)}",
                            description="Other accounts on this machine can read this key. Restrict it "
                                        "with: chmod 600 " + path,
                            evidence={"File": path, "Permissions": oct(mode & 0o777)}, paths=[path]))
                except OSError:
                    pass

    ctx.sensitive = items
    touched = [i for i in items if i.in_window]
    res.stats.update({"sensitive_items": len(items), "touched_in_window": len(touched),
                      "kinds": sorted({i.kind for i in items})})
    if items:
        res.findings.append(Finding(
            check=NAME, category="exposure", severity=Severity.INFO,
            title=f"{len(items)} sensitive data store(s) found on this device",
            description=("These hold passwords, logged-in sessions, keys or wallets. They are what attackers "
                         "try to steal, and they are listed in 'Origin & Exposure' so you know what to "
                         "protect if an infection is confirmed. Access times can be inaccurate because "
                         "some systems don't update them."),
            evidence={"Types": sorted({i.kind for i in items}),
                      f"Used in last {ctx.window_days} day(s)": len(touched)}))
    return res
