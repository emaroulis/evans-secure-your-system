# Evan's Secure Your System (developer notes)

Cross-platform Python desktop app for host compromise assessment. For setup and usage, see **README.md**.

## Architecture

```
secure_your_system/
├── __main__.py        entry point (GUI by default, --cli for terminal)
├── gui.py             tkinter interface: 6 tabs, threaded scan, report export
├── cli.py             terminal mode + exit codes
├── scanner.py         runs every check, builds ScanResult, calls analysis
├── analysis.py        origin / exposure / sniffed / actions / further-checks engine
├── report.py          HTML, JSON, text exports
├── models.py          Finding, CheckResult, ScanResult, SensitiveItem, Severity
├── platform_utils.py  OS detection, admin check, safe subprocess, paths
├── ioc_data.py        indicator lists (tools, ports, cmdline patterns, extensions)
└── checks/
    ├── base.py            ScanContext: shared process/connection snapshot, custom IOCs
    ├── processes.py       masquerading, typosquats, hacktools, temp-folder execution,
    │                      deleted binaries, malicious cmdlines, Office→shell, miners, signatures
    ├── network.py         C2 ports, LOLBins online, temp-binaries online, backdoor listeners,
    │                      cleartext protocols, upload volume
    ├── sniffer.py         promiscuous NICs, sniffer tools, AF_PACKET/BPF owners,
    │                      Npcap drivers, ARP spoofing of the gateway
    ├── persistence.py     Run keys, Winlogon, startup folders, scheduled tasks, services, WMI,
    │                      cron, systemd, autostart, shell rc hooks, ld.so.preload, LaunchAgents
    ├── system_config.py   hosts hijack, proxy, DNS, new root CAs, Defender/Firewall/Gatekeeper/SIP,
    │                      Defender detection history
    ├── files.py           hash + EICAR + YARA matching, double extensions, RLO trick,
    │                      temp droppers (entropy), ransomware traces, recent downloads
    └── sensitive_data.py  browser passwords/cookies/cards, keychains, SSH, cloud creds, wallets,
                           chat sessions, vaults; unexpected readers; key permissions
```

Each check exposes `NAME` and `run(ctx) -> CheckResult`. To add one, create a module in `checks/` and append it to `ALL_CHECKS` in `checks/__init__.py`.

`analysis.py` maps findings to the five questions the product answers:

1. **Verdict.** The highest severity sets the risk level, from 0 (clean) to 4 (compromise).
2. **Origin.** Comes from download tags (Windows Zone.Identifier, macOS quarantine/WhereFroms, Linux xdg.origin xattrs), file location (Outlook temp, archives, USB, messaging apps), parent process (Office/browser → shell), remote-access tools and sniffer type.
3. **Possibly taken.** Lists sensitive stores, prioritised by whether they were used after the earliest suspicious activity, plus any unexpected readers.
4. **Possibly sniffed.** Depends on how traffic was intercepted (local tool, ARP MITM, proxy/rogue CA, Responder, Wi-Fi capture), plus any cleartext connections seen.
5. **Actions and further checks.** Steps are tailored to what was found. Further checks always include admin-only, network, account and forensic checks the program cannot run itself.

## Design principles

- Read-only: the program never modifies the system.
- Degrades gracefully: missing psutil, no admin rights and access-denied errors are recorded as `limited` and turned into further-check recommendations instead of crashes.
- Uses only the standard library plus `psutil`. `yara-python` is optional.
