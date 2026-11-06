"""Packet-sniffing and man-in-the-middle detection."""
from __future__ import annotations

import glob
import json
import os
import re
from collections import defaultdict

from .. import ioc_data as ioc
from ..models import CheckResult, Finding, Severity
from ..platform_utils import IS_LINUX, IS_MAC, IS_WINDOWS, powershell, run_cmd

NAME = "Packet sniffing & interception"
IFF_PROMISC = 0x100
_BENIGN_PACKET_USERS = {"dhclient", "dhcpcd", "networkmanager", "systemd-network",
                        "systemd-networkd", "wpa_supplicant", "lldpd", "avahi-daemon",
                        "udhcpc", "dnsmasq", "keepalived", "hostapd"}


def _promisc_interfaces(res) -> list:
    found = []
    if IS_LINUX:
        for flags in glob.glob("/sys/class/net/*/flags"):
            try:
                v = int(open(flags).read().strip(), 16)
                if v & IFF_PROMISC:
                    found.append(flags.split("/")[4])
            except (OSError, ValueError):
                pass
    elif IS_MAC:
        out = run_cmd(["ifconfig"]) or ""
        for m in re.finditer(r"^(\S+): flags=\w+<([^>]*)>", out, re.M):
            if "PROMISC" in m.group(2):
                found.append(m.group(1))
    elif IS_WINDOWS:
        out = powershell("Get-NetAdapter | Select-Object Name,PromiscuousMode | ConvertTo-Json")
        if out:
            try:
                data = json.loads(out)
                data = data if isinstance(data, list) else [data]
                found = [d["Name"] for d in data if d.get("PromiscuousMode")]
            except (ValueError, KeyError, TypeError):
                pass
        else:
            res.limited.append("Could not read network adapter capture mode on Windows.")
    return found


def _linux_packet_socket_owners(ctx, res) -> list:
    """Find processes holding raw packet-capture sockets (AF_PACKET)."""
    try:
        lines = open("/proc/net/packet").read().splitlines()[1:]
    except OSError:
        return []
    inodes = set()
    for ln in lines:
        parts = ln.split()
        if parts:
            inodes.add(parts[-1])
    if not inodes:
        return []
    owners, denied = [], 0
    for pid_dir in glob.glob("/proc/[0-9]*"):
        try:
            for fd in os.listdir(pid_dir + "/fd"):
                try:
                    link = os.readlink(f"{pid_dir}/fd/{fd}")
                except OSError:
                    continue
                m = re.match(r"socket:\[(\d+)\]", link)
                if m and m.group(1) in inodes:
                    pid = int(pid_dir.split("/")[-1])
                    owners.append(pid)
                    break
        except PermissionError:
            denied += 1
        except OSError:
            pass
    if denied and not ctx.admin:
        res.limited.append(f"{len(inodes)} raw packet socket(s) exist; owners of some could not be "
                           "identified without root (run with sudo to see them).")
    return owners


def _mac_bpf_users(ctx, res) -> list:
    devices = glob.glob("/dev/bpf*")
    if not devices:
        return []
    out = run_cmd(["lsof", "-n", "-Fpc"] + devices, timeout=20)
    if out is None and not ctx.admin:
        res.limited.append("Could not see which programs have packet-capture devices (/dev/bpf) "
                           "open without sudo.")
    pids = []
    for ln in (out or "").splitlines():
        if ln.startswith("p"):
            try:
                pids.append(int(ln[1:]))
            except ValueError:
                pass
    return pids


def _arp_table() -> list:
    entries = []
    if IS_LINUX and os.path.exists("/proc/net/arp"):
        for ln in open("/proc/net/arp").read().splitlines()[1:]:
            p = ln.split()
            if len(p) >= 6 and p[3] != "00:00:00:00:00:00":
                entries.append((p[0], p[3].lower(), p[5]))
        return entries
    out = run_cmd(["arp", "-a"]) or ""
    for ln in out.splitlines():
        ip = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", ln)
        mac = re.search(r"((?:[0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2})", ln)
        if ip and mac:
            m = mac.group(1).lower().replace("-", ":")
            m = ":".join(x.zfill(2) for x in m.split(":"))
            entries.append((ip.group(1), m, ""))
    return entries


def _default_gateway() -> str:
    if IS_LINUX:
        try:
            for ln in open("/proc/net/route").read().splitlines()[1:]:
                p = ln.split()
                if p[1] == "00000000":
                    g = int(p[2], 16)
                    return ".".join(str((g >> (8 * i)) & 0xFF) for i in range(4))
        except (OSError, ValueError, IndexError):
            return ""
    elif IS_MAC:
        m = re.search(r"gateway:\s*(\S+)", run_cmd(["route", "-n", "get", "default"]) or "")
        return m.group(1) if m else ""
    elif IS_WINDOWS:
        out = powershell("(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | "
                         "Select-Object -First 1).NextHop")
        return (out or "").strip()
    return ""


def _is_special_mac(mac: str) -> bool:
    return mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") or mac.startswith(("01:00:5e", "33:33"))


def run(ctx) -> CheckResult:
    res = CheckResult(NAME)

    # 1. Network cards in capture ("promiscuous") mode
    prom = _promisc_interfaces(res)
    res.stats["promiscuous_interfaces"] = prom
    if prom:
        res.findings.append(Finding(
            check=NAME, title="Network adapter is in packet-capture (promiscuous) mode",
            severity=Severity.HIGH, category="sniffer",
            description=("The adapter(s) " + ", ".join(prom) + " are set to capture ALL network traffic, "
                         "not just traffic meant for this device. This is what packet sniffers do. "
                         "Virtual machine software and network tools can also cause it."),
            evidence={"Interfaces": prom}))

    # 2. Sniffing tools running
    for p in ctx.processes:
        b = p["name"].lower().removesuffix(".exe")
        if b in ioc.SNIFFER_OFFENSIVE or b in ioc.SNIFFER_DIAGNOSTIC:
            offensive = b in ioc.SNIFFER_OFFENSIVE
            res.findings.append(Finding(
                check=NAME, pid=p["pid"], first_seen=p["create_time"],
                paths=[p["exe"]] if p["exe"] else [],
                title=f"{'Attack' if offensive else 'Packet capture'} tool running: {p['name']}",
                severity=Severity.CRITICAL if offensive else Severity.MEDIUM, category="sniffer",
                description=("This is a network-attack tool used to intercept other people's traffic "
                             "and steal credentials." if offensive else
                             "This tool records network traffic. Fine if you are using it on purpose; "
                             "if not, someone may be capturing your traffic."),
                evidence={"Process": p["name"], "PID": p["pid"], "Path": p["exe"],
                          "Command line": p["cmdline"][:300], "User": p["username"]}))

    # 3. Raw packet-socket / BPF owners
    owners = []
    if IS_LINUX:
        owners = _linux_packet_socket_owners(ctx, res)
    elif IS_MAC:
        owners = _mac_bpf_users(ctx, res)
    for pid in set(owners):
        pr = ctx.proc_by_pid(pid)
        name = pr["name"] if pr else str(pid)
        if name.lower() in _BENIGN_PACKET_USERS or name.lower().removesuffix(".exe") in (
                ioc.SNIFFER_DIAGNOSTIC | ioc.SNIFFER_OFFENSIVE):
            continue
        if IS_MAC and name.lower() in {"airportd", "configd", "mdnsresponder", "symptomsd",
                                        "networkserviceproxy", "bootpd"}:
            continue
        res.findings.append(Finding(
            check=NAME, pid=pid, paths=[pr["exe"]] if pr and pr["exe"] else [],
            first_seen=pr["create_time"] if pr else None,
            title=f"Unrecognised program holding a raw packet-capture handle: {name}",
            severity=Severity.HIGH, category="sniffer",
            description="This program has opened a low-level capture interface that can read raw "
                        "network packets. Unknown programs doing this may be sniffers.",
            evidence={"Process": name, "PID": pid, "Path": pr["exe"] if pr else ""}))

    # 4. Capture drivers installed (Windows)
    if IS_WINDOWS:
        windir = os.environ.get("WINDIR", r"C:\Windows")
        drivers = [d for d in (os.path.join(windir, "System32", "drivers", "npcap.sys"),
                               os.path.join(windir, "System32", "drivers", "npf.sys"))
                   if os.path.exists(d)]
        if drivers:
            res.findings.append(Finding(
                check=NAME, title="Packet-capture driver installed (Npcap/WinPcap)",
                severity=Severity.INFO, category="sniffer", paths=drivers,
                description="A driver that allows traffic capture is installed. Normal if you use "
                            "Wireshark or Nmap; otherwise ask who installed it.",
                evidence={"Drivers": drivers}))

    # 5. ARP spoofing (man-in-the-middle on the local network)
    arp = [e for e in _arp_table() if not _is_special_mac(e[1])]
    gw = _default_gateway()
    res.stats["arp_entries"] = len(arp)
    res.stats["gateway"] = gw
    macs = defaultdict(set)
    for ip, mac, _ in arp:
        macs[mac].add(ip)
    for mac, ips in macs.items():
        if len(ips) > 1:
            gw_hit = gw in ips
            res.findings.append(Finding(
                check=NAME,
                title=("Router's address is shared with another device (possible ARP spoofing)"
                       if gw_hit else "Several network addresses share one hardware address"),
                severity=Severity.HIGH if gw_hit else Severity.LOW, category="sniffer",
                description=("Another device on your network is answering for your router. That is how "
                             "man-in-the-middle attacks redirect your traffic through the attacker so it "
                             "can be read or altered." if gw_hit else
                             "Usually caused by a repeater/mesh system or VM, but can indicate ARP spoofing."),
                evidence={"Hardware (MAC) address": mac, "IP addresses": sorted(ips),
                          "Default gateway": gw or "unknown"}))
    return res
