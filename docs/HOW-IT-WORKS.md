# How Evan's Secure Your System Works

This document explains what the scanner does, what data it touches, how it runs offline, and the published research and documentation each check is based on. Sources are listed in the [References](#references) section at the end.

## Contents

- [Overview](#overview)
- [Stage 1: Snapshot](#stage-1-snapshot)
- [Stage 2: The seven checks](#stage-2-the-seven-checks)
- [Stage 3: Analysis](#stage-3-analysis)
- [Stage 4: Results and reports](#stage-4-results-and-reports)
- [Is any data saved?](#is-any-data-saved)
- [Can it run without Wi-Fi?](#can-it-run-without-wi-fi)
- [Where the detection logic comes from](#where-the-detection-logic-comes-from)
- [References](#references)

---

## Overview

Every scan runs in four stages. The program **only reads** the system and never changes, deletes or moves anything.

```
Snapshot  →  7 checks  →  Analysis  →  Results (6 tabs + optional saved report)
```

Each check produces **findings**. A finding has:
- a severity: Info, Low, Medium, High or Critical
- a plain-English explanation
- the evidence behind it, such as file paths, process names and network addresses

The analysis stage then answers five questions:
1. How serious is this?
2. Where did it come from?
3. What may have been taken?
4. What may have been sniffed?
5. What should I do now?

The approach follows the structure NIST recommends for incident response: detect, analyse, then respond and recover [[N1]](#nist). The "Further Checks" tab covers the parts of that process a single on-device scan can't do.

---

## Stage 1: Snapshot

When a scan starts, the program captures the system's current state once, using the cross-platform `psutil` library [[L1]](#libraries):

- **Running programs:** name, file location, full command line, parent program, user account, start time, and CPU use measured over one second.
- **Network connections:** every open TCP/UDP connection, the program that owns it, and the remote address and port.

Every later check reuses this snapshot, so the results stay consistent and the scan stays fast.

---

## Stage 2: The seven checks

### 1. Running programs
| What it looks for | Why it matters |
|---|---|
| Core Windows processes (e.g. `svchost.exe`, `lsass.exe`) running from the wrong folder | Malware uses trusted names to hide. MITRE's guidance is that these binaries should only run from `System32`/`SysWOW64` [[A1]](#attack) |
| Look-alike names one character away from a system process (e.g. `svch0st.exe`) | Same disguise technique [[A1]](#attack) |
| Linux processes pretending to be kernel threads but running a file | Common in Linux malware and crypto-miners [[A1]](#attack) |
| Known credential-theft, hacking, tunnelling and mining tools | e.g. Mimikatz-style credential dumping [[A9]](#attack), miners [[A10]](#attack) |
| Programs running from temp folders, or whose file was deleted | Typical of dropper malware |
| Command lines matching attack techniques | Hidden/encoded PowerShell [[A11]](#attack), downloaders [[A12]](#attack), obfuscated commands [[A13]](#attack), abuse of `mshta`, `regsvr32`, `rundll32` [[A14]](#attack), deleting backups/shadow copies [[A15]](#attack) |
| A Word/Excel/PDF reader launching a command shell | The classic sign of a malicious email attachment [[A16]](#attack) |
| High CPU from an unknown program in a user folder | Possible hidden crypto-miner [[A10]](#attack) |
| Code signatures of flagged programs (Windows/macOS) | Unsigned binaries in odd locations are more suspicious |

### 2. Network connections
| What it looks for | Why it matters |
|---|---|
| Connections to ports used by attack tools, Tor, IRC botnets or mining pools | Command-and-control or data theft over non-standard ports [[A17]](#attack) |
| Built-in Windows utilities (`mshta`, `certutil`, `regsvr32`…) connecting to the internet | These binaries are abused to download payloads [[A14]](#attack) |
| Temp-folder programs talking to the internet; backdoors listening for incoming connections | Strong indicators of command-and-control |
| Unencrypted protocols (HTTP, FTP, Telnet, POP3/IMAP…) | Anything sent over them can be read by a sniffer [[A2]](#attack) |
| Unusually high upload volume | Possible bulk data exfiltration |

### 3. Packet sniffing and interception
| What it looks for | Why it matters |
|---|---|
| Network adapters in **promiscuous mode** | Sniffers put adapters in this mode to read all traffic [[A2]](#attack). It's checked through Linux interface flags [[L3]](#libraries), macOS `ifconfig`, and the Windows `PromiscuousMode` adapter property [[M3]](#microsoft) |
| Sniffing and attack tools (Wireshark, tcpdump, Ettercap, Bettercap, Responder…) | Named in MITRE's Network Sniffing technique and detection guidance [[A2]](#attack) |
| Programs holding raw packet-capture sockets (Linux `AF_PACKET`) or `/dev/bpf` (macOS) | These interfaces let a program read raw network frames [[L3]](#libraries) |
| Npcap/WinPcap capture drivers (Windows) | Show that the system can capture packets |
| Two network addresses sharing the router's hardware (MAC) address | The signature of **ARP spoofing** man-in-the-middle attacks [[A3]](#attack) |
| LLMNR/NBT-NS poisoning tools (Responder, Inveigh) | Capture Windows login hashes [[A4]](#attack) |

### 4. Auto-start and persistence
| What it looks for | Source |
|---|---|
| Registry Run/RunOnce keys and Startup folders | [[A18]](#attack) |
| Changes to the Winlogon `Shell`/`Userinit` settings | [[A18]](#attack) |
| Scheduled tasks | [[A19]](#attack) |
| Windows services running from user-writable folders | [[A20]](#attack) |
| WMI event subscriptions (fileless persistence) | [[A21]](#attack) |
| macOS LaunchAgents/LaunchDaemons, including fake `com.apple.*` items | [[A20]](#attack), [[A1]](#attack) |
| Linux cron jobs and systemd services | [[A19]](#attack), [[A20]](#attack) |
| Shell start-up files (`.bashrc`, `.zshrc`, `/etc/profile`…) | [[A22]](#attack) |
| `/etc/ld.so.preload` and `LD_PRELOAD` hooks (rootkit technique) | [[A23]](#attack) |
| Recently changed `~/.ssh/authorized_keys` | [[A24]](#attack) |

The same areas are covered by Microsoft's Sysinternals Autoruns tool, which the Further Checks tab recommends for a deeper review [[M2]](#microsoft).

### 5. System settings and protection
| What it looks for | Source |
|---|---|
| Hosts-file entries redirecting banks, Microsoft or security vendors; proxy settings; unrecognised DNS servers | Interception through configuration changes [[A5]](#attack) |
| Newly trusted root certificates | Lets an attacker read encrypted (HTTPS) traffic without warnings [[A6]](#attack) |
| Antivirus, firewall, Gatekeeper or SIP turned off | Malware often disables defences [[A25]](#attack), [[A26]](#attack) |
| Microsoft Defender's past detections | Read with `Get-MpThreatDetection`, which returns active and past threats Defender found [[M1]](#microsoft) |

### 6. Files and downloads
| What it looks for | Source |
|---|---|
| SHA-256 fingerprints matched against known-bad hashes (built-in plus your own in `custom_iocs/`) | Standard indicator-of-compromise matching. Optional YARA rules [[L2]](#libraries) |
| The EICAR test file | Industry-standard harmless test file for checking that detection works [[T1]](#testing) |
| Double extensions such as `invoice.pdf.exe` | [[A7]](#attack) |
| Filenames using the hidden right-to-left override character | [[A8]](#attack) |
| Hidden or packed programs and scripts in temp folders | Droppers often look like this. Packing is estimated with an entropy measure |
| Ransomware-style file extensions and ransom notes | [[A27]](#attack) |
| Programs downloaded recently | Likely entry points if an infection is found |

### 7. Sensitive data exposure
The program lists stores that attackers target:
- browser saved passwords, cookies and cards
- keychains and credential managers
- SSH keys and cloud credentials
- crypto wallets, Discord and Telegram sessions
- password-manager vaults and VPN profiles

It then checks whether any unexpected program has them open, which is exactly what information-stealing malware does [[A28]](#attack), [[A29]](#attack).

---

## Stage 3: Analysis

| Question | How it's answered |
|---|---|
| **Verdict** | The highest severity found sets the result, from "No signs of compromise" to "Compromise detected" |
| **Where it came from** | See the list below |
| **Timeline** | The earliest suspicious activity marks the start of the exposure window |
| **What may have been taken** | Sensitive stores used or changed since that point are ranked highest risk. Any unexpected reader is flagged |
| **What may have been sniffed** | Based on how interception happened. A local sniffer exposes unencrypted traffic [[A2]](#attack). ARP spoofing affects every device on the network [[A3]](#attack). A proxy or rogue certificate can expose encrypted traffic too [[A6]](#attack). Responder-style tools capture login hashes [[A4]](#attack) |
| **Do This Now** | Steps chosen to match the findings, ordered Now → Today → This week |
| **Further Checks** | Always produced. Includes everything limited by permissions, plus network, account and forensic checks the program can't do itself |

To trace where a suspicious file came from, the analysis uses several clues:
- **Windows download tag:** browsers attach a hidden `Zone.Identifier` stream to downloads, recording the security zone and often the exact download URL (`HostUrl`) and the page it was linked from (`ReferrerUrl`) [[M4]](#microsoft).
- **macOS download tag:** the `com.apple.quarantine` attribute records which app downloaded a file, and Spotlight's "where from" data records the URL [[P1]](#apple).
- **Linux download tag:** some browsers save the source URL in the `user.xdg.origin.url` attribute.
- **Location:** for example an Outlook attachment folder, inside a ZIP or RAR file, a USB drive, or a messaging app's download folder.
- **Parent program:** for example Word launching PowerShell, a common phishing pattern [[A16]](#attack).
- **Context:** whether remote-control software [[A30]](#attack) or network interception is also present.

---

## Stage 4: Results and reports

Results appear in six tabs:
- Overview
- Findings
- Origin & Exposure
- Do This Now
- Further Checks
- Scan Details

**Save Report** exports a self-contained HTML report, plain text, or JSON for analysts.

---

## Is any data saved?

**The scan itself saves nothing.** Results are held in memory and are gone when the program closes. The program has no account, no cloud service and no tracking, and it never sends data anywhere.

It writes to disk only in these cases:
- **Reports:** only when you click **Save Report** (or pass `--html`/`--json` in terminal mode), to a location you choose. Reports contain your computer name, username, file paths, program names and IP addresses, so keep them private. The repository's `.gitignore` excludes them.
- **`.venv` folder:** created on first launch inside the program's own folder. It holds the program's private copy of its one helper library (`psutil`).

What it reads:
- **Sensitive stores** (passwords, cookies, wallets): only whether the file exists, its timestamps, and which programs have it open. **It never opens or reads their contents.**
- **Programs and scripts** in scanned folders, plus very small files of any type: read to compute a fingerprint (hash), the same way antivirus works. A fingerprint only appears in a report if it matches a known threat.

---

## Can it run without Wi-Fi?

**Yes.** Every check runs locally. The scan makes no internet requests: no online lookups, no reverse DNS, no threat-intelligence downloads.

The internet is only needed once:
- to install Python and let the first launch download `psutil`, or
- to build the standalone app.

After that, the program (or a built `.exe` on a USB stick) works fully offline. That's useful for checking a machine you've already disconnected.

Offline limitations:
- **Network check:** it only sees connections open at that moment. If the device is offline, a live command-and-control connection can't be observed, but processes, persistence, files and settings are still checked. For the fullest picture, scan once before disconnecting, save the report, then disconnect.
- **Threat knowledge:** detection relies on the built-in behaviour checks and indicators, plus any hashes or YARA rules you add. It doesn't fetch updates.
- **Online checks:** account checks (breach lookups, sign-in history) are listed in Further Checks for you to do from another device.

---

## Where the detection logic comes from

- **Techniques:** the checks are mapped to **MITRE ATT&CK®**, a public knowledge base of adversary techniques based on real-world observations. Technique IDs below refer to the ATT&CK Enterprise matrix as of late 2026. MITRE occasionally renames techniques and tactics, so the IDs are the stable reference.
- **Operating-system interfaces:** the official documentation from Microsoft, Apple and the Linux man-pages project.
- **Incident response steps:** the NIST incident response guidance (SP 800-61 Rev. 3).
- **Built-in indicator lists:** tool names, port numbers and command-line patterns. These are behaviour- and name-based heuristics drawn from the technique pages above. They aren't a full antivirus signature database. Add your own hashes and YARA rules for broader coverage.

---

## References

<a id="attack"></a>
### MITRE ATT&CK techniques
| Ref | Technique | Link |
|---|---|---|
| A1 | T1036 Masquerading (incl. T1036.005 Match Legitimate Resource Name or Location) | https://attack.mitre.org/techniques/T1036/ |
| A2 | T1040 Network Sniffing | https://attack.mitre.org/techniques/T1040/ |
| A3 | T1557.002 Adversary-in-the-Middle: ARP Cache Poisoning | https://attack.mitre.org/techniques/T1557/002/ |
| A4 | T1557.001 Adversary-in-the-Middle: Name Resolution Poisoning and SMB Relay | https://attack.mitre.org/techniques/T1557/ |
| A5 | T1557 Adversary-in-the-Middle (hosts, DNS and proxy tampering) | https://attack.mitre.org/techniques/T1557/ |
| A6 | T1553.004 Subvert Trust Controls: Install Root Certificate | https://attack.mitre.org/techniques/T1553/004/ |
| A7 | T1036.007 Masquerading: Double File Extension | https://attack.mitre.org/techniques/T1036/007/ |
| A8 | T1036.002 Masquerading: Right-to-Left Override | https://attack.mitre.org/techniques/T1036/002/ |
| A9 | T1003.001 OS Credential Dumping: LSASS Memory | https://attack.mitre.org/techniques/T1003/001/ |
| A10 | T1496 Resource Hijacking (crypto-mining) | https://attack.mitre.org/techniques/T1496/ |
| A11 | T1059.001 Command and Scripting Interpreter: PowerShell | https://attack.mitre.org/techniques/T1059/001/ |
| A12 | T1105 Ingress Tool Transfer | https://attack.mitre.org/techniques/T1105/ |
| A13 | T1027.010 Obfuscated Files or Information: Command Obfuscation | https://attack.mitre.org/techniques/T1027/010/ |
| A14 | T1218 System Binary Proxy Execution (.005 Mshta, .010 Regsvr32, .011 Rundll32) | https://attack.mitre.org/techniques/T1218/ |
| A15 | T1490 Inhibit System Recovery | https://attack.mitre.org/techniques/T1490/ |
| A16 | T1566.001 Phishing: Spearphishing Attachment / T1204.002 User Execution: Malicious File | https://attack.mitre.org/techniques/T1566/001/ |
| A17 | T1571 Non-Standard Port | https://attack.mitre.org/techniques/T1571/ |
| A18 | T1547.001 Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | https://attack.mitre.org/techniques/T1547/001/ |
| A19 | T1053 Scheduled Task/Job (.003 Cron, .005 Scheduled Task) | https://attack.mitre.org/techniques/T1053/ |
| A20 | T1543 Create or Modify System Process (.001 Launch Agent, .002 Systemd Service, .003 Windows Service, .004 Launch Daemon) | https://attack.mitre.org/techniques/T1543/ |
| A21 | T1546.003 Event Triggered Execution: WMI Event Subscription | https://attack.mitre.org/techniques/T1546/003/ |
| A22 | T1546.004 Event Triggered Execution: Unix Shell Configuration Modification | https://attack.mitre.org/techniques/T1546/004/ |
| A23 | T1574.006 Hijack Execution Flow: Dynamic Linker Hijacking | https://attack.mitre.org/techniques/T1574/006/ |
| A24 | T1098.004 Account Manipulation: SSH Authorized Keys | https://attack.mitre.org/techniques/T1098/004/ |
| A25 | T1685 Disable or Modify Tools | https://attack.mitre.org/techniques/T1685/ |
| A26 | T1686 Disable or Modify System Firewall | https://attack.mitre.org/techniques/T1686/ |
| A27 | T1486 Data Encrypted for Impact (ransomware) | https://attack.mitre.org/techniques/T1486/ |
| A28 | T1555.003 Credentials from Password Stores: Credentials from Web Browsers | https://attack.mitre.org/techniques/T1555/003/ |
| A29 | T1539 Steal Web Session Cookie | https://attack.mitre.org/techniques/T1539/ |
| A30 | T1219 Remote Access Tools | https://attack.mitre.org/techniques/T1219/ |

<a id="microsoft"></a>
### Microsoft documentation
| Ref | Topic | Link |
|---|---|---|
| M1 | `Get-MpThreatDetection`: Defender's active and past detections | https://learn.microsoft.com/en-us/powershell/module/defender/get-mpthreatdetection |
| M2 | Sysinternals Autoruns: auto-start locations | https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns |
| M3 | `MSFT_NetAdapter` class (`PromiscuousMode` property) | https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/hh968170(v=vs.85) |
| M4 | Mark of the Web / `Zone.Identifier` stream (`ZoneId`, `HostUrl`, `ReferrerUrl`) | https://textslashplain.com/2016/04/04/downloads-and-the-mark-of-the-web/ · https://en.wikipedia.org/wiki/Mark_of_the_Web |

<a id="apple"></a>
### Apple / macOS
| Ref | Topic | Link |
|---|---|---|
| P1 | File Quarantine (`com.apple.quarantine`) and Gatekeeper | https://redcanary.com/blog/gatekeeper |

<a id="libraries"></a>
### Libraries and Linux interfaces
| Ref | Topic | Link |
|---|---|---|
| L1 | psutil: cross-platform process and network information | https://psutil.readthedocs.io/ |
| L2 | YARA: pattern-matching rules for malware | https://virustotal.github.io/yara/ |
| L3 | Linux `packet(7)`: raw packet sockets and promiscuous mode | https://www.man7.org/linux/man-pages/man7/packet.7.html |

<a id="testing"></a>
### Testing
| Ref | Topic | Link |
|---|---|---|
| T1 | EICAR anti-malware test file | https://www.eicar.org/download-anti-malware-testfile/ |

<a id="nist"></a>
### Incident response guidance
| Ref | Topic | Link |
|---|---|---|
| N1 | NIST SP 800-61 Rev. 3: *Incident Response Recommendations and Considerations for Cybersecurity Risk Management* (April 2025) | https://csrc.nist.gov/pubs/sp/800/61/r3/final |

*MITRE ATT&CK® is a registered trademark of The MITRE Corporation. This project isn't affiliated with or endorsed by MITRE, Microsoft, Apple, NIST or EICAR.*
