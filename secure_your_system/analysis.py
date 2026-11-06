"""Turns raw findings into answers: where did it come from, what may have been
taken or sniffed, what to do right now, and what to check next."""
from __future__ import annotations

import os
import re
from collections import Counter, OrderedDict

from .models import CATEGORIES, Severity, fmt_time
from .platform_utils import IS_LINUX, IS_MAC, IS_WINDOWS, os_name, run_cmd

VERDICTS = {
    0: ("No signs of compromise", "Nothing suspicious was found by the checks this program can run."),
    1: ("Minor items to review", "Only low-risk items were found. Review them, but there are no strong signs of an attack."),
    2: ("Suspicious activity found", "Some findings could indicate an attack. Review each one and follow the steps below."),
    3: ("Likely compromised", "Strong signs of malicious activity were found. Follow the 'Do This Now' steps immediately."),
    4: ("Compromise detected", "Clear evidence of malware or an active attack was found. Act now — start with the first step."),
}


# ----------------------------------------------------------- provenance ------
def provenance(path: str) -> list:
    """Where did this file come from? Uses the 'downloaded from' tags OSes attach."""
    hints = []
    if not path:
        return hints
    low = path.lower().replace("\\", "/")
    try:
        if IS_WINDOWS and os.path.isfile(path):
            with open(path + ":Zone.Identifier", "r", errors="replace") as fh:
                z = fh.read()
            zone = re.search(r"ZoneId=(\d)", z)
            host = re.search(r"HostUrl=(.+)", z)
            ref = re.search(r"ReferrerUrl=(.+)", z)
            if zone and zone.group(1) in ("3", "4"):
                hints.append("Downloaded from the internet" + (f": {host.group(1).strip()}" if host else ""))
            if ref:
                hints.append(f"Download link was on page: {ref.group(1).strip()}")
    except OSError:
        pass
    if IS_MAC and os.path.exists(path):
        q = run_cmd(["xattr", "-p", "com.apple.quarantine", path], timeout=5)
        if q:
            parts = q.strip().split(";")
            agent = parts[2] if len(parts) > 2 else ""
            hints.append("Downloaded from the internet" + (f" using {agent}" if agent else ""))
        w = run_cmd(["mdls", "-raw", "-name", "kMDItemWhereFroms", path], timeout=5)
        if w and "(null)" not in w:
            urls = re.findall(r'"([^"]+)"', w)
            if urls:
                hints.append("Source URL: " + urls[0])
    if IS_LINUX and os.path.exists(path):
        for attr in ("user.xdg.origin.url", "user.xdg.referrer.url"):
            try:
                hints.append("Source URL: " + os.getxattr(path, attr).decode(errors="replace"))
            except (OSError, AttributeError):
                pass
    if "content.outlook" in low or "/olk/" in low or "outlook temp" in low:
        hints.append("Opened from an Outlook email attachment")
    elif "/downloads/" in low:
        hints.append("Saved in the Downloads folder (web or email download)")
    if re.search(r"/temp/(rar\$|7z|wz|temp\d_)", low):
        hints.append("Run directly from inside a ZIP/RAR archive")
    if any(k in low for k in ("telegram desktop", "/whatsapp", "/discord/", "/teams/")):
        hints.append("Received through a messaging app")
    if IS_WINDOWS and re.match(r"^[d-z]:/", low):
        try:
            import psutil  # type: ignore
            for part in psutil.disk_partitions():
                if "removable" in part.opts and low.startswith(part.mountpoint.lower().replace("\\", "/")):
                    hints.append("Came from a removable drive (USB)")
        except Exception:
            pass
    if (IS_MAC and low.startswith("/volumes/")) or (IS_LINUX and low.startswith(("/media/", "/run/media/"))):
        hints.append("Came from an external/removable drive")
    return hints


# --------------------------------------------------------------- engine ------
def analyse(result, ctx) -> dict:
    findings = result.findings
    real = [f for f in findings if f.severity >= Severity.LOW]
    serious = [f for f in findings if f.severity >= Severity.MEDIUM]
    cats = Counter(f.category for f in serious)
    level = max((int(f.severity) for f in findings if f.severity > Severity.INFO), default=0)
    # Only the EICAR test file found: say so clearly.
    test_only = serious and all("EICAR" in str(f.evidence.get("Indicator", "")) for f in serious)

    counts = OrderedDict((s.label, sum(1 for f in findings if f.severity == s))
                         for s in sorted(Severity, reverse=True))
    first = min((f.first_seen for f in serious if f.first_seen and f.category != "remote_access"),
                default=None)

    has = lambda cat, sev=Severity.MEDIUM: any(f.category == cat and f.severity >= sev for f in findings)
    malware = has("malware", Severity.HIGH) or has("exfiltration", Severity.HIGH)
    maybe_malware = has("malware") or has("persistence") or has("exfiltration")
    sniffing = has("sniffer")
    remote = has("remote_access")
    stealer = any(f.category == "exposure" and f.severity >= Severity.HIGH for f in findings)
    ransomware = any("ransomware" in f.title.lower() and f.severity >= Severity.CRITICAL for f in findings)

    title, summary = VERDICTS[level]
    if test_only:
        title, summary = ("Test file detected (scanner working)",
                          "Only the harmless EICAR test file was found. Delete it; no real threat was detected.")

    a = {
        "risk_level": level,
        "headline": title,
        "summary": summary,
        "counts": counts,
        "first_activity": fmt_time(first),
        "attack_types": [{"type": CATEGORIES.get(c, c), "count": n} for c, n in cats.most_common()],
        "nothing_found": level <= 1,
        "test_only": bool(test_only),
    }
    a["origin"] = _origin(serious, sniffing, remote)
    a["possibly_taken"] = _possibly_taken(result, serious, first, malware, maybe_malware, remote,
                                          stealer, ransomware, ctx)
    a["sniffed"] = _sniffed(findings, result, sniffing)
    a["destinations"] = _destinations(serious)
    a["affected_locations"] = _locations(real, result, first, malware or remote or stealer, ctx)
    a["actions_now"] = _actions(level, malware, maybe_malware, sniffing, remote, stealer, ransomware,
                                findings, result, test_only)
    a["further_checks"] = _further_checks(result, level)
    a["limitations"] = _limitations(result, ctx)
    a["narrative"] = _narrative(a, first, malware, sniffing, remote, ransomware)
    return a


def _origin(serious, sniffing, remote) -> list:
    sources = OrderedDict()

    def add(src, conf, ev):
        s = sources.setdefault(src, {"source": src, "confidence": conf, "evidence": []})
        if ["Low", "Medium", "High"].index(conf) > ["Low", "Medium", "High"].index(s["confidence"]):
            s["confidence"] = conf
        if ev and ev not in s["evidence"]:
            s["evidence"].append(ev)

    for f in serious:
        for h in f.origin_hints:
            add(h, "High" if "document" in h.lower() or "defender" in h.lower() else "Medium", f.title)
        if f.category in ("malware", "persistence", "exfiltration"):
            for p in f.paths[:3]:
                for h in provenance(p):
                    if h.startswith(("Downloaded", "Source URL", "Download link")):
                        add("Downloaded from the internet", "High", f"{os.path.basename(p)} — {h}")
                    elif h.startswith("Opened from an Outlook"):
                        add("Email attachment", "High", f"{os.path.basename(p)} — {h}")
                    elif "archive" in h.lower():
                        add("File opened from a ZIP/RAR archive (often an email or download)", "Medium",
                            os.path.basename(p))
                    elif "removable" in h.lower() or "external" in h.lower():
                        add("USB / removable drive", "High", os.path.basename(p))
                    elif "messaging" in h.lower():
                        add("Messaging app download (Telegram, Discord, WhatsApp…)", "Medium", os.path.basename(p))
                    else:
                        add("Downloaded file (Downloads folder)", "Medium", os.path.basename(p))
        if f.category == "persistence":
            add("Set to restart automatically (persistence was installed)", "Medium", f.title)
    if remote:
        add("Remote access to this device (remote-control software or a backdoor accepting connections)",
            "Medium", next(f.title for f in serious if f.category == "remote_access"))
    if sniffing:
        for f in serious:
            if f.category != "sniffer":
                continue
            if "arp" in f.title.lower() or "router" in f.title.lower():
                add("Another device on your local network / Wi-Fi (man-in-the-middle)", "High", f.title)
            elif "proxy" in f.title.lower() or "certificate" in f.title.lower():
                add("Changed network settings on this device (proxy / trusted certificate)", "Medium", f.title)
            else:
                add("Capture software running on this device", "High", f.title)
    if serious and not sources:
        add("Undetermined — no download tag, parent program or network clue pointed to an entry point",
            "Low", "See 'Further checks' for logs that can reveal the entry point")
    rank = {"High": 0, "Medium": 1, "Low": 2}
    return sorted(sources.values(), key=lambda s: (rank[s["confidence"]], s["source"].startswith("Set to restart")))


def _possibly_taken(result, serious, first, malware, maybe_malware, remote, stealer, ransomware, ctx) -> list:
    items = []
    since = first or ctx.window_start
    if malware or remote or stealer:
        by_kind = OrderedDict()
        for s in result.sensitive:
            by_kind.setdefault(s.kind, []).append(s)
        for kind, lst in by_kind.items():
            touched = [s for s in lst if (s.accessed and s.accessed >= since) or (s.modified and s.modified >= since)]
            items.append({
                "what": kind,
                "risk": "High" if touched or stealer else "Medium",
                "why": ("Used or changed after the suspicious activity began, so it was available to the "
                        "attacker." if touched else "Present on the device while it was compromised."),
                "paths": [s.path for s in (touched or lst)][:10],
            })
        if remote:
            items.append({"what": "Anything on screen or in your files during remote sessions",
                          "risk": "Medium",
                          "why": "Remote-control software can view the screen, copy files and type.",
                          "paths": []})
    elif maybe_malware:
        items.append({"what": "Nothing confirmed taken",
                      "risk": "Low",
                      "why": "Findings are suspicious but not conclusive. If they are confirmed malicious, treat "
                             "the sensitive data listed below as exposed.",
                      "paths": []})
    if ransomware:
        items.insert(0, {"what": "Your documents (encrypted, and possibly copied out first)",
                         "risk": "High",
                         "why": "Modern ransomware usually steals copies of files before encrypting them.",
                         "paths": []})
    for f in serious:
        if f.category == "exposure" and f.severity >= Severity.HIGH:
            items.insert(0, {"what": f.title, "risk": "High", "why": f.description, "paths": f.paths})
    return items


def _sniffed(findings, result, sniffing) -> list:
    out = []
    clear = [f for f in findings if f.category == "exposure" and "unencrypted" in f.title.lower()]
    if sniffing:
        titles = " ".join(f.title.lower() for f in findings if f.category == "sniffer")
        out += [
            {"what": "Websites and services you used", "why": "Domain lookups (DNS) and server addresses are "
                                                               "visible even when the connection is encrypted."},
            {"what": "Anything sent without encryption", "why": "Plain HTTP pages and forms, FTP, Telnet, "
                                                                "POP3/IMAP email logins can be read in full."},
            {"what": "Connection metadata", "why": "When you were online, which servers you contacted and how "
                                                   "much data was exchanged."},
        ]
        if "proxy" in titles or "certificate" in titles:
            out.append({"what": "Encrypted (HTTPS) traffic — passwords, cookies, messages",
                        "why": "Traffic passes through a proxy or a newly trusted certificate, which can decrypt it."})
        if "responder" in titles or "inveigh" in titles or "attack tool" in titles:
            out.append({"what": "Windows/network login password hashes",
                        "why": "Tools like Responder capture login hashes that can be cracked offline."})
        if "router" in titles or "arp" in titles:
            out.append({"what": "Traffic from other devices on the same network",
                        "why": "ARP spoofing intercepts traffic for every device that trusts the fake router."})
        if any(t in titles for t in ("airodump", "aircrack", "aireplay")):
            out.append({"what": "Wi-Fi password", "why": "Captured Wi-Fi handshakes can be cracked offline."})
    for f in clear:
        out.append({"what": f"Unencrypted traffic from {f.evidence.get('Process', 'a program')}",
                    "why": f.description})
    return out


def _destinations(serious) -> list:
    seen = OrderedDict()
    for f in serious:
        for r in f.remotes:
            seen.setdefault(r, f.evidence.get("Process", ""))
    return [{"endpoint": r, "process": p} for r, p in list(seen.items())[:40]]


def _locations(real, result, first, compromised, ctx) -> list:
    locs = OrderedDict()
    for f in real:
        for p in f.paths:
            if p and p not in locs:
                locs[p] = {"path": p, "reason": f.title, "severity": f.severity.label}
    if compromised:
        since = first or ctx.window_start
        for s in result.sensitive:
            if (s.accessed and s.accessed >= since) or (s.modified and s.modified >= since):
                locs.setdefault(s.path, {"path": s.path, "reason": f"{s.kind} used during the suspicious period",
                                         "severity": "High"})
    return list(locs.values())[:200]


def _actions(level, malware, maybe_malware, sniffing, remote, stealer, ransomware, findings, result,
             test_only) -> list:
    A = []

    def add(priority, step, detail):
        A.append({"priority": priority, "step": step, "detail": detail})

    if test_only:
        add("Now", "Delete the EICAR test file", "It is harmless; it only proves detection works.")
        return A + _hygiene()
    if level == 0:
        add("Soon", "No urgent action needed",
            "If you still suspect a problem (odd pop-ups, slowness, account alerts), work through the "
            "Further Checks tab, starting with re-running as administrator.")
        return A + _hygiene()
    if level == 1:
        add("Soon", "Review the low-risk items in the Findings tab",
            "Confirm you recognise each one. Nothing requires urgent action.")
        return A + _hygiene()

    if ransomware:
        add("Now", "Disconnect from all networks and unplug external/backup drives",
            "Stops encryption spreading to other devices and to your backups. Do NOT pay the ransom yet.")
        add("Now", "Do not restart or wipe the device; photograph the ransom note",
            "Free decryptors exist for some families (nomoreransom.org). Report to the FBI at ic3.gov "
            "(US) or your national cyber agency.")
    if malware or stealer or remote:
        add("Now", "Disconnect this device from the internet (turn off Wi-Fi / unplug the cable)",
            "Cuts off any remote attacker and stops more data leaving. Leave the computer ON so evidence in "
            "memory is preserved if you plan to get professional help.")
        add("Now", "If this is a work or school device, contact your IT/security team before doing anything else",
            "They may need the device untouched for investigation, and company accounts may also be at risk.")
        add("Now", "From a DIFFERENT, clean device, change your most important passwords",
            "Order: email accounts → password manager → banking/payment → work accounts → social media. "
            "Changing them on the infected device could let the attacker capture the new ones.")
        add("Now", "Sign out of all sessions and turn on two-factor authentication",
            "Stolen browser cookies let attackers stay logged in even after a password change. Use 'sign out "
            "of all devices' in Google, Microsoft, Apple, Facebook, banking apps, etc.")
    if remote:
        add("Now", "Uninstall remote-control software you did not install yourself",
            "If you allowed someone in (e.g. a 'support' caller), assume they saw everything and copied files. "
            "Contact your bank if they saw banking pages.")
    if any(s.kind == "Crypto wallet" for s in result.sensitive) and (malware or stealer or remote):
        add("Now", "Move crypto funds to a NEW wallet created on a clean device",
            "Wallet files and seed phrases on this device must be treated as stolen.")
    if any(s.kind in ("Saved cards & autofill",) for s in result.sensitive) and (malware or stealer):
        add("Today", "Alert your bank/card issuer and watch statements",
            "Cards saved in the browser may have been copied. Ask for replacement cards if unsure.")
    if any(s.kind == "SSH private key" for s in result.sensitive) and (malware or stealer):
        add("Today", "Replace SSH keys and remove the old ones from servers",
            "Generate new keys on a clean machine; delete old keys from ~/.ssh/authorized_keys on every server "
            "and GitHub/GitLab; review server login logs.")
    if any(s.kind == "Cloud credentials" for s in result.sensitive) and (malware or stealer):
        add("Today", "Rotate cloud access keys and review cloud activity logs",
            "AWS: IAM → deactivate keys, check CloudTrail. Azure/GCP: revoke tokens, check activity logs.")
    if sniffing:
        add("Now", "Stop using this network for anything sensitive",
            "Use mobile data or a trusted VPN until the sniffing source is found.")
        add("Today", "Secure your router",
            "Log in to the router: check connected devices for unknown ones, change the Wi-Fi and admin "
            "passwords, turn off WPS and remote management, update firmware, check its DNS settings.")
        add("Today", "Change passwords used over this network",
            "Especially any typed into sites without the padlock (HTTP), FTP or email apps.")
        if any("proxy" in f.title.lower() for f in findings if f.category == "sniffer"):
            add("Now", "Remove the proxy setting if you did not add it",
                _proxy_howto())
        if any("certificate" in f.title.lower() for f in findings):
            add("Today", "Remove unrecognised trusted root certificates", _cert_howto())
    if any(f.category == "config" and "hosts" in f.title.lower() for f in findings):
        add("Today", "Restore the hosts file", "Remove the redirect lines listed in Findings (needs admin).")
    if maybe_malware or malware:
        add("Today", "Run a full offline antivirus scan", _av_howto())
        add("Today", "Remove the auto-start entries and files listed under Affected Locations",
            "Write down or export this report first so you keep the evidence. Quarantine via antivirus rather "
            "than deleting by hand where possible.")
    if any(f.category == "posture" and f.severity >= Severity.MEDIUM for f in findings):
        add("Today", "Turn your security protections back on", "See the 'protection is off' findings.")
    if malware or ransomware:
        add("This week", "Consider a full reinstall of the operating system",
            "After a confirmed infection, a clean reinstall from official media is the only way to be sure. "
            "Restore files only from backups made before the first suspicious activity.")
        add("This week", "Watch for identity misuse",
            "Check haveibeenpwned.com, review bank/credit reports, and consider a credit freeze if identity "
            "documents were on the device.")
    order = {"Now": 0, "Today": 1, "This week": 2, "Soon": 3, "Ongoing": 4}
    A.sort(key=lambda x: order.get(x["priority"], 5))
    return A + _hygiene() if level < 3 else A


def _hygiene() -> list:
    return [{"priority": "Ongoing", "step": "Keep the operating system, browser and apps updated",
             "detail": "Most infections use known, already-patched flaws."},
            {"priority": "Ongoing", "step": "Use a password manager and two-factor authentication",
             "detail": "Limits the damage if any one password is stolen."},
            {"priority": "Ongoing", "step": "Keep an offline/versioned backup",
             "detail": "Your best protection against ransomware and data loss."}]


def _proxy_howto():
    if IS_WINDOWS:
        return "Settings → Network & Internet → Proxy: turn off 'Use a proxy server' and remove any setup script."
    if IS_MAC:
        return "System Settings → Network → (your network) → Details → Proxies: turn all off."
    return "Remove proxy lines from /etc/environment and your shell files; check desktop network settings."


def _cert_howto():
    if IS_WINDOWS:
        return "Press Win+R, run certmgr.msc → Trusted Root Certification Authorities → Certificates."
    if IS_MAC:
        return "Open Keychain Access → System and login keychains → Certificates; remove ones you don't recognise."
    return "Remove the file from /usr/local/share/ca-certificates and run: sudo update-ca-certificates --fresh"


def _av_howto():
    if IS_WINDOWS:
        return ("Windows Security → Virus & threat protection → Scan options → 'Microsoft Defender Offline scan' "
                "(reboots and scans before malware can hide). A second opinion: Malwarebytes or ESET Online Scanner.")
    if IS_MAC:
        return "Use Malwarebytes for Mac or another reputable scanner; macOS XProtect runs automatically."
    return "Run ClamAV (sudo freshclam && sudo clamscan -r /home) and rkhunter/chkrootkit as root."


def _further_checks(result, level) -> list:
    """Checks this program cannot do itself (needs admin, other tools, or other devices)."""
    G = []
    limited = [l for c in result.checks for l in c.limited]
    intro = ("Nothing was found by this scan. These deeper checks can catch what a normal-user scan "
             "cannot see:" if level <= 1 else "To confirm and scope the findings, also do these:")
    if not result.host.get("admin"):
        G.append({"group": "Re-run this scanner with administrator rights",
                  "why": "Some checks were limited without admin rights.",
                  "items": [{"check": l.rstrip("."), "how": _elevate_howto()} for l in dict.fromkeys(limited)][:12]
                  or [{"check": "Full process, connection and file visibility", "how": _elevate_howto()}]})
    if IS_WINDOWS:
        G.append({"group": "Windows deep checks (admin)", "why": intro, "items": [
            {"check": "Microsoft Defender Offline scan",
             "how": "Windows Security → Virus & threat protection → Scan options → Microsoft Defender Offline scan."},
            {"check": "Review every auto-start location with Sysinternals Autoruns",
             "how": "Download from learn.microsoft.com/sysinternals, run as admin, Options → Scan Options → "
                    "'Check VirusTotal.com', look for red/pink rows."},
            {"check": "Check running programs' signatures with Process Explorer",
             "how": "Sysinternals Process Explorer → Options → Verify Image Signatures and VirusTotal."},
            {"check": "Look for unknown logons and new accounts in Event Viewer",
             "how": "Event Viewer → Windows Logs → Security: event IDs 4624/4625 (logons), 4720 (user created), "
                    "4732 (added to Administrators), 1102 (log cleared). System log 7045 (new service)."},
            {"check": "Check PowerShell history for hidden scripts",
             "how": "Event Viewer → Applications and Services → Microsoft → Windows → PowerShell → Operational, "
                    "event 4104."},
            {"check": "List local user accounts", "how": "Run 'net user' and 'net localgroup administrators' "
                                                         "in an admin Command Prompt; remove unknown accounts."},
            {"check": "Check firewall rules for unknown 'Allow' entries",
             "how": "wf.msc → Inbound Rules, sort by Action/Program."},
        ]})
    elif IS_MAC:
        G.append({"group": "macOS deep checks", "why": intro, "items": [
            {"check": "Review all persistence with KnockKnock / BlockBlock (Objective-See, free)",
             "how": "objective-see.org → KnockKnock → scan, enable VirusTotal checking."},
            {"check": "Check configuration profiles", "how": "System Settings → Privacy & Security → Profiles. "
                                                            "Remove any you did not install (adware uses them)."},
            {"check": "Review Login Items and background items",
             "how": "System Settings → General → Login Items & Extensions."},
            {"check": "Check privacy permissions", "how": "System Settings → Privacy & Security → Screen "
                                                         "Recording, Accessibility, Full Disk Access: remove unknown apps."},
            {"check": "Review the unified log for installs", "how": "sudo log show --last 7d --predicate "
                                                                   "'process == \"installd\"' | less"},
        ]})
    else:
        G.append({"group": "Linux deep checks (root)", "why": intro, "items": [
            {"check": "Rootkit scan", "how": "sudo apt install rkhunter chkrootkit && sudo rkhunter --check && "
                                             "sudo chkrootkit"},
            {"check": "Verify system packages haven't been modified",
             "how": "Debian/Ubuntu: sudo debsums -s  ·  Fedora/RHEL: sudo rpm -Va"},
            {"check": "Review login history", "how": "last -a; sudo lastb; sudo journalctl -u ssh --since -7d; "
                                                     "/var/log/auth.log"},
            {"check": "See every connection with its owner", "how": "sudo ss -tunap"},
            {"check": "Find unexpected SUID programs", "how": "sudo find / -perm -4000 -type f 2>/dev/null"},
            {"check": "Check all users' cron jobs and authorized_keys",
             "how": "sudo ls /var/spool/cron/crontabs; sudo cat /root/.ssh/authorized_keys"},
        ]})
    G.append({"group": "Network checks (router & other devices)", "why":
              "Sniffing and man-in-the-middle attacks often happen outside this computer.", "items": [
        {"check": "Router: connected devices", "how": "Log in to your router (often 192.168.0.1 or 192.168.1.1) "
                                                     "and look for devices you don't recognise."},
        {"check": "Router: DNS, port forwarding, UPnP and remote admin",
         "how": "DNS should be your ISP or a known provider; remove unknown port forwards; disable UPnP and "
                "remote management unless needed; update firmware."},
        {"check": "Capture traffic from outside the device",
         "how": "Run Wireshark on another computer (or the router's capture feature) to spot regular 'beacon' "
                "connections that malware hides from the infected machine."},
        {"check": "Scan your network for unknown devices",
         "how": "Use a network scanner app (e.g. Fing) or 'nmap -sn 192.168.1.0/24' from a trusted device."},
    ]})
    G.append({"group": "Account checks (online)", "why":
              "Stolen data is used against your accounts, which this program cannot see.", "items": [
        {"check": "Breach check", "how": "haveibeenpwned.com — check every email address you use."},
        {"check": "Recent sign-ins and devices",
         "how": "Google: myaccount.google.com/security · Microsoft: account.microsoft.com/security · "
                "Apple: appleid.apple.com → Devices · Facebook/Instagram: Security → Where you're logged in."},
        {"check": "Email forwarding rules and connected apps",
         "how": "Attackers add hidden forwarding rules and OAuth app grants to keep reading your email."},
        {"check": "Bank and card statements", "how": "Look for small test charges; set up transaction alerts."},
    ]})
    G.append({"group": "Advanced / professional", "why": "For confirmed or high-value incidents.", "items": [
        {"check": "Memory forensics", "how": "Capture RAM (WinPmem / AVML / osxpmem) and analyse with Volatility 3 "
                                              "to find malware that hides from normal tools."},
        {"check": "Firmware / boot integrity", "how": "Check Secure Boot is on, update BIOS/UEFI from the vendor."},
        {"check": "Professional incident response",
         "how": "For business devices, ransomware or financial loss, contact an incident-response firm, your "
                "insurer, and law enforcement (US: ic3.gov)."},
    ]})
    return G


def _elevate_howto():
    if IS_WINDOWS:
        return "Click 'Run as Administrator' in the app, or right-click the program → Run as administrator."
    if IS_MAC:
        return "Run from Terminal: sudo ./run_mac_linux.sh  (or sudo python3 -m secure_your_system)"
    return "Run from a terminal: sudo ./run_mac_linux.sh"


def _limitations(result, ctx) -> list:
    lim = [
        "This program checks for signs of compromise; it is not a replacement for antivirus software.",
        "It cannot prove exactly what was taken or which packets were sniffed in the past — that needs logs "
        "or captures recorded at the time. Exposure is estimated from the evidence available now.",
        "Kernel-level rootkits can hide from any program running on the infected system.",
        "File access times are not always updated by the operating system, so 'used recently' may be incomplete.",
    ]
    if not result.host.get("psutil"):
        lim.insert(0, "psutil is not installed — process and network checks were skipped. See the README install guide.")
    if not result.host.get("admin"):
        lim.insert(0, "Scan ran WITHOUT administrator rights; some areas were only partly visible.")
    return lim


def _narrative(a, first, malware, sniffing, remote, ransomware) -> str:
    if a.get("test_only"):
        return a["summary"]
    if a["nothing_found"]:
        return (a["summary"] + " That is a good sign, but a normal-user scan cannot see everything. "
                "The 'Further Checks' tab lists deeper checks to rule out hidden threats.")
    parts = [a["summary"]]
    if first:
        parts.append(f"The earliest suspicious activity found dates to {fmt_time(first)}; treat anything "
                     "used on this device since then as potentially exposed.")
    if a["origin"]:
        top = a["origin"][0]
        parts.append(f"Most likely entry point: {top['source']} ({top['confidence'].lower()} confidence).")
    if malware:
        parts.append("Signs of malicious software were found.")
    if sniffing:
        parts.append("There are signs your network traffic may be intercepted.")
    if remote:
        parts.append("Something on this device allows remote access.")
    if ransomware:
        parts.append("Ransomware indicators were found.")
    return " ".join(parts)
