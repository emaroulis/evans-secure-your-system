"""Network connections: command-and-control, exfiltration and cleartext traffic."""
from __future__ import annotations

from collections import Counter, defaultdict

from .. import ioc_data as ioc
from ..models import CheckResult, Finding, Severity
from ..platform_utils import HAS_PSUTIL, is_public_ip, path_in, psutil, temp_dirs, user_drop_dirs

NAME = "Network connections"


def run(ctx) -> CheckResult:
    res = CheckResult(NAME)
    if not HAS_PSUTIL:
        res.ran = False
        res.error = "The 'psutil' package is not installed, so network connections could not be listed."
        return res
    if ctx.conn_limited:
        res.limited.append(ctx.conn_limited)

    conns = ctx.connections
    temps, drops = temp_dirs(), user_drop_dirs()
    established = [c for c in conns if c["remote_ip"] and c["status"] in ("ESTABLISHED", "SYN_SENT", "NONE")]
    public = [c for c in established if is_public_ip(c["remote_ip"])]
    listening = [c for c in conns if c["status"] == "LISTEN"]
    res.stats.update({
        "connections": len(conns),
        "active_external": len(public),
        "unique_remote_ips": len({c["remote_ip"] for c in public}),
        "listening_ports": len(listening),
    })

    by_proc = defaultdict(list)
    for c in public:
        by_proc[(c["pid"], c["process"], c["exe"])].append(c)

    for (pid, pname, exe), cs in by_proc.items():
        remotes = sorted({f"{c['remote_ip']}:{c['remote_port']}" for c in cs})
        proc = ctx.proc_by_pid(pid) if pid else None
        ev = {"Process": pname or "(unknown)", "PID": pid, "Path": exe or "(hidden)",
              "Remote endpoints": remotes[:20]}
        base = dict(check=NAME, pid=pid, remotes=remotes, paths=[exe] if exe else [],
                    first_seen=proc["create_time"] if proc else None)
        lname = (pname or "").lower()

        bad_ports = {c["remote_port"]: ioc.SUSPICIOUS_PORTS[c["remote_port"]]
                     for c in cs if c["remote_port"] in ioc.SUSPICIOUS_PORTS}
        if bad_ports:
            desc = "; ".join(f"port {p}: {d}" for p, d in bad_ports.items())
            tor = any(p in (9001, 9030, 9050, 9150) for p in bad_ports)
            res.findings.append(Finding(
                title=f"{pname or 'A program'} is connected to a high-risk port",
                severity=Severity.HIGH, category="exfiltration",
                description=(f"Connections on ports associated with attacker tools were found ({desc}). "
                             + ("Tor hides where data is sent. " if tor else "")
                             + "This can be a remote-control channel or data being sent out."),
                evidence=ev, **base))

        if lname in ioc.LOLBIN_NETWORK:
            res.findings.append(Finding(
                title=f"Windows system utility talking to the internet: {pname}",
                severity=Severity.HIGH, category="exfiltration",
                description=(f"{pname} is a built-in Windows tool that attackers abuse to download "
                             "malware or send data out. It normally has no reason to connect to the internet."),
                evidence=ev, **base))
        elif lname in ("powershell.exe", "pwsh.exe", "cmd.exe", "bash", "sh", "nc", "ncat", "socat"):
            res.findings.append(Finding(
                title=f"Command shell with an internet connection: {pname}",
                severity=Severity.MEDIUM, category="exfiltration",
                description="A command shell talking directly to an internet address can be a "
                            "remote attacker's session (reverse shell) or a script downloading files.",
                evidence=ev, **base))

        if exe and path_in(exe, temps):
            res.findings.append(Finding(
                title=f"Program from a temp folder is sending/receiving internet traffic: {pname}",
                severity=Severity.HIGH, category="exfiltration",
                description="Malware dropped into a temp folder that talks to the internet is a "
                            "strong sign of command-and-control or data theft.",
                evidence=ev, **base))
        elif exe and path_in(exe, [d for d in drops if d.name in ("Downloads", "Desktop", "Shared")]):
            res.findings.append(Finding(
                title=f"Program from Downloads/Desktop has internet connections: {pname}",
                severity=Severity.LOW, category="exfiltration",
                description="Confirm you recognise this program and expect it to use the internet.",
                evidence=ev, **base))

        cleartext = sorted({c["remote_port"] for c in cs if c["remote_port"] in ioc.CLEARTEXT_PORTS})
        if cleartext:
            res.findings.append(Finding(
                title=f"{pname or 'A program'} is using unencrypted connections",
                severity=Severity.LOW, category="exposure",
                description=("These connections are not encrypted, so anyone sniffing the network "
                             "could read them: " + "; ".join(ioc.CLEARTEXT_PORTS[p] for p in cleartext)),
                evidence=ev, **base))

    # Programs listening on all interfaces from user folders (backdoor servers)
    for c in listening:
        if c["local"].startswith(("0.0.0.0:", ":::", "[::]:")) and c["exe"] and path_in(c["exe"], temps + drops):
            res.findings.append(Finding(
                title=f"Program from a user folder is accepting outside connections: {c['process']}",
                severity=Severity.HIGH, category="remote_access",
                description="A program in a temp/download folder is listening for incoming network "
                            "connections on all interfaces, which is how backdoors let attackers in.",
                evidence={"Process": c["process"], "Listening on": c["local"], "Path": c["exe"]},
                paths=[c["exe"]], pid=c["pid"], check=NAME))

    # Upload volume since boot (whole device)
    try:
        io = psutil.net_io_counters()
        res.stats["sent_mb_since_boot"] = round(io.bytes_sent / 1e6, 1)
        res.stats["recv_mb_since_boot"] = round(io.bytes_recv / 1e6, 1)
        if io.bytes_sent > 2e9 and io.bytes_sent > io.bytes_recv * 1.5:
            res.findings.append(Finding(
                check=NAME, title="This device has uploaded far more data than it downloaded",
                severity=Severity.LOW, category="exfiltration",
                description=(f"Since startup, {io.bytes_sent/1e9:.1f} GB were sent versus "
                             f"{io.bytes_recv/1e9:.1f} GB received. Backups, cloud sync and video calls "
                             "can explain this; otherwise it may indicate data being copied out."),
                evidence={"Sent (GB)": round(io.bytes_sent / 1e9, 2),
                          "Received (GB)": round(io.bytes_recv / 1e9, 2)}))
    except Exception:
        pass

    top = Counter(c["process"] or "(unknown)" for c in public).most_common(8)
    res.stats["top_talkers"] = [f"{n} ({k})" for n, k in top]
    return res
