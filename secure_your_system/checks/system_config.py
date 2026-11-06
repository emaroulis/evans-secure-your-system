"""System settings attackers tamper with (hosts, proxy, DNS, certificates) and protection status."""
from __future__ import annotations

import glob
import json
import os
import re
import time
from pathlib import Path

from .. import ioc_data as ioc
from ..models import CheckResult, Finding, Severity
from ..platform_utils import IS_LINUX, IS_MAC, IS_WINDOWS, file_times, is_public_ip, powershell, run_cmd

NAME = "System settings & protection"


def _hosts(ctx, res):
    path = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32/drivers/etc/hosts" if IS_WINDOWS \
        else Path("/etc/hosts")
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return
    custom, hijacks = [], []
    for ln in lines:
        s = ln.split("#")[0].strip()
        if not s:
            continue
        parts = s.split()
        if len(parts) < 2:
            continue
        ip, names = parts[0], parts[1:]
        if all(n in ("localhost", "localhost.localdomain", "broadcasthost", "ip6-localhost",
                     "ip6-loopback", "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes",
                     "ip6-allrouters") or n.startswith("ip6-") for n in names):
            continue
        custom.append(s)
        if ip not in ("0.0.0.0", "127.0.0.1", "::1") and any(
                k in n.lower() for n in names for k in ioc.HOSTS_PROTECTED_KEYWORDS):
            hijacks.append(s)
    mtime = file_times(path)[0]
    res.stats["hosts_custom_entries"] = len(custom)
    if hijacks:
        res.findings.append(Finding(
            check=NAME, category="config", severity=Severity.HIGH, paths=[str(path)],
            title="Hosts file redirects important websites",
            description="Entries send well-known sites (banks, Microsoft, security vendors…) to a different "
                        "server. Malware does this to show fake login pages or block security updates.",
            evidence={"Entries": hijacks[:20], "Last changed": time.ctime(mtime) if mtime else "?"},
            first_seen=mtime))
    elif custom and ctx.in_window(mtime):
        res.findings.append(Finding(
            check=NAME, category="config", severity=Severity.LOW, paths=[str(path)],
            title="Hosts file was changed recently",
            description="Custom entries were added recently. Usually from ad-blockers or developer tools.",
            evidence={"Entries": custom[:20]}, first_seen=mtime))


def _proxy(ctx, res):
    settings = {}
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy"):
        if os.environ.get(var):
            settings[var] = os.environ[var]
    if IS_WINDOWS:
        try:
            import winreg  # type: ignore
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as k:
                for v in ("ProxyEnable", "ProxyServer", "AutoConfigURL"):
                    try:
                        settings[v] = winreg.QueryValueEx(k, v)[0]
                    except OSError:
                        pass
            if not settings.get("ProxyEnable"):
                settings.pop("ProxyServer", None)
            settings.pop("ProxyEnable", None)
        except OSError:
            pass
    elif IS_MAC:
        out = run_cmd(["scutil", "--proxy"]) or ""
        for key in ("HTTPProxy", "HTTPSProxy", "SOCKSProxy", "ProxyAutoConfigURLString"):
            m = re.search(rf"{key}\s*:\s*(\S+)", out)
            en = re.search(rf"{key.replace('Proxy', 'Enable').replace('URLString', 'Enable')}\s*:\s*1", out)
            if m and (en or key == "ProxyAutoConfigURLString"):
                settings[key] = m.group(1)
    if settings:
        local = all(re.search(r"(127\.0\.0\.1|localhost|::1)", str(v)) for v in settings.values())
        res.findings.append(Finding(
            check=NAME, category="sniffer", severity=Severity.LOW if local else Severity.MEDIUM,
            title="Web traffic is being sent through a proxy",
            description=("A proxy setting routes your web traffic through another program or server. "
                         "Companies, VPNs and debugging tools use proxies, but malware sets one to read "
                         "and change your traffic. If you did not set this, it may be intercepting you."),
            evidence={k: str(v) for k, v in settings.items()}))


def _dns(ctx, res):
    servers = []
    if IS_WINDOWS:
        out = powershell("Get-DnsClientServerAddress -AddressFamily IPv4 | "
                         "Select-Object -ExpandProperty ServerAddresses")
        servers = [s.strip() for s in (out or "").splitlines() if s.strip()]
    elif IS_MAC:
        out = run_cmd(["scutil", "--dns"]) or ""
        servers = re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", out)
    else:
        try:
            servers = re.findall(r"^nameserver\s+(\S+)", Path("/etc/resolv.conf").read_text(), re.M)
        except OSError:
            pass
    servers = list(dict.fromkeys(servers))
    res.stats["dns_servers"] = servers
    odd = [s for s in servers if is_public_ip(s) and s not in ioc.KNOWN_DNS]
    if odd:
        res.findings.append(Finding(
            check=NAME, category="config", severity=Severity.MEDIUM,
            title="Unrecognised DNS server in use",
            description=("DNS turns website names into addresses. A rogue DNS server can silently send "
                         "you to fake sites and sees every site you visit. These may simply be your "
                         "internet provider's servers — check with your provider or router settings."),
            evidence={"DNS servers": servers, "Unrecognised": odd}))


def _certs(ctx, res):
    recent = []
    if IS_WINDOWS:
        out = powershell("Get-ChildItem Cert:\\CurrentUser\\Root, Cert:\\LocalMachine\\Root | "
                         "Select-Object Subject,NotBefore,Thumbprint | ConvertTo-Json -Compress", timeout=40)
        try:
            data = json.loads(out) if out else []
            data = data if isinstance(data, list) else [data]
            for c in data:
                nb = c.get("NotBefore", "")
                m = re.search(r"/Date\((\d+)\)/", str(nb))
                ts = int(m.group(1)) / 1000 if m else None
                if ts and ctx.in_window(ts):
                    recent.append(f"{c.get('Subject')} (issued {time.ctime(ts)})")
        except ValueError:
            pass
    elif IS_LINUX:
        for f in glob.glob("/usr/local/share/ca-certificates/**/*", recursive=True):
            if os.path.isfile(f) and ctx.in_window(file_times(f)[0]):
                recent.append(f)
    if recent:
        res.findings.append(Finding(
            check=NAME, category="sniffer", severity=Severity.MEDIUM,
            title="New trusted root certificate(s) added recently",
            description=("A newly trusted root certificate lets whoever holds its key read and alter your "
                         "encrypted (HTTPS) traffic without warnings. Antivirus web shields, corporate "
                         "tools and debugging proxies add these legitimately — if you do not recognise "
                         "it, treat encrypted traffic as possibly intercepted."),
            evidence={"Certificates": recent[:15]}))


def _posture(ctx, res):
    if IS_WINDOWS:
        out = powershell("Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,"
                         "AntivirusSignatureLastUpdated,QuickScanEndTime | ConvertTo-Json -Compress")
        if out:
            try:
                st = json.loads(out)
                res.stats["defender"] = st
                if st.get("AntivirusEnabled") is False or st.get("RealTimeProtectionEnabled") is False:
                    res.findings.append(Finding(
                        check=NAME, category="posture", severity=Severity.HIGH,
                        title="Microsoft Defender real-time protection is OFF",
                        description="Malware often switches off antivirus. If you did not turn it off and "
                                    "have no other antivirus, turn it back on now.",
                        evidence=st))
            except ValueError:
                pass
        det = powershell("Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | "
                         "Select-Object -First 20 ThreatID,InitialDetectionTime,Resources,"
                         "ActionSuccess | ConvertTo-Json -Compress -Depth 3", timeout=40)
        if det and det.strip():
            try:
                items = json.loads(det)
                items = items if isinstance(items, list) else [items]
                names = {}
                tn = powershell("Get-MpThreat | Select-Object ThreatID,ThreatName | ConvertTo-Json -Compress")
                threats = json.loads(tn) if tn and tn.strip() else []
                for t in threats if isinstance(threats, list) else [threats]:
                    names[t.get("ThreatID")] = t.get("ThreatName")
                paths = []
                for it in items:
                    for r in it.get("Resources") or []:
                        paths.append(re.sub(r"^\w+:_", "", str(r)))
                res.findings.append(Finding(
                    check=NAME, category="malware", severity=Severity.HIGH,
                    title=f"Microsoft Defender has detected {len(items)} threat(s) on this device",
                    description="Defender's history shows past detections. Even if they were removed, they "
                                "tell you what got in, when, and where it was.",
                    evidence={"Threats": [names.get(i.get("ThreatID"), i.get("ThreatID")) for i in items],
                              "Detected": [str(i.get("InitialDetectionTime")) for i in items][:10],
                              "Removed successfully": [i.get("ActionSuccess") for i in items][:10]},
                    paths=paths[:30], origin_hints=["Previously detected by Microsoft Defender"]))
            except (ValueError, TypeError, AttributeError):
                pass
        elif not ctx.admin:
            res.limited.append("Microsoft Defender detection history may need administrator rights to read.")
        fw = run_cmd(["netsh", "advfirewall", "show", "allprofiles", "state"]) or ""
        if re.search(r"State\s+OFF", fw, re.I):
            res.findings.append(Finding(
                check=NAME, category="posture", severity=Severity.MEDIUM,
                title="Windows Firewall is off for at least one network profile",
                description="The firewall blocks unwanted incoming connections. Malware sometimes disables it.",
                evidence={"Status": fw.strip()[:400]}))
    elif IS_MAC:
        gk = (run_cmd(["spctl", "--status"]) or "").strip()
        sip = (run_cmd(["csrutil", "status"]) or "").strip()
        fw = (run_cmd(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"]) or "").strip()
        res.stats.update({"gatekeeper": gk, "sip": sip, "firewall": fw})
        if "disabled" in gk.lower():
            res.findings.append(Finding(
                check=NAME, category="posture", severity=Severity.HIGH, title="Gatekeeper is disabled",
                description="Gatekeeper blocks unsigned/unknown apps. Turning it off is a common step in "
                            "macOS malware installers.", evidence={"Status": gk}))
        if "disabled" in sip.lower():
            res.findings.append(Finding(
                check=NAME, category="posture", severity=Severity.HIGH,
                title="System Integrity Protection (SIP) is disabled",
                description="SIP protects core macOS files. With it off, malware can modify the system.",
                evidence={"Status": sip}))
        if "disabled" in fw.lower():
            res.findings.append(Finding(
                check=NAME, category="posture", severity=Severity.LOW, title="macOS firewall is off",
                description="Consider turning on the firewall in System Settings → Network → Firewall.",
                evidence={"Status": fw}))
    elif IS_LINUX:
        ufw = run_cmd(["ufw", "status"])
        if ufw and "inactive" in ufw.lower():
            res.findings.append(Finding(
                check=NAME, category="posture", severity=Severity.LOW, title="Firewall (ufw) is inactive",
                description="Consider enabling it: sudo ufw enable", evidence={"Status": ufw.strip()}))
        elif ufw is None and not ctx.admin:
            res.limited.append("Firewall status needs root to read on Linux.")


def run(ctx) -> CheckResult:
    res = CheckResult(NAME)
    for fn in (_hosts, _proxy, _dns, _certs, _posture):
        if ctx.cancelled:
            break
        try:
            fn(ctx, res)
        except Exception as e:  # keep going if one sub-check fails
            res.limited.append(f"{fn.__name__.strip('_')} check failed: {e}")
    return res
