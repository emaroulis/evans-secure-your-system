"""Indicator lists used by the checks.

These are behaviour- and name-based indicators, not a full antivirus
signature database. Users can add their own SHA-256 hashes in
custom_iocs/hashes.txt and YARA rules in custom_iocs/rules/ (see README install guide).
"""
import re

# --- Network sniffing / interception tools --------------------------------
# Legitimate diagnostic tools: fine if YOU installed them, a red flag if not.
SNIFFER_DIAGNOSTIC = {
    "wireshark", "tshark", "dumpcap", "tcpdump", "windump", "rawcap",
    "networkminer", "fiddler", "charles", "mitmproxy", "mitmdump", "mitmweb",
    "burpsuite", "ngrep", "kismet", "pktmon", "netmon", "microsoft message analyzer",
}
# Tools built for attacking other people's traffic.
SNIFFER_OFFENSIVE = {
    "ettercap", "bettercap", "dsniff", "arpspoof", "urlsnarf", "mailsnarf",
    "msgsnarf", "cain", "responder", "inveigh", "airodump-ng", "aireplay-ng",
    "aircrack-ng", "sslstrip", "mitm6", "driftnet", "intercepter-ng",
}

# --- Hacking / credential theft / mining tools ------------------------------
HACKTOOLS = {
    "mimikatz": "Credential dumping tool (steals Windows passwords)",
    "lazagne": "Password recovery/stealing tool",
    "rubeus": "Kerberos ticket abuse tool",
    "sharphound": "Active Directory reconnaissance",
    "pwdump": "Password hash dumper",
    "gsecdump": "Credential dumper",
    "wce": "Windows Credential Editor",
    "procdump": "Memory dumper (often used on lsass to steal passwords)",
    "psexec": "Remote command execution",
    "paexec": "Remote command execution",
    "xmrig": "Cryptocurrency miner",
    "xmr-stak": "Cryptocurrency miner",
    "cpuminer": "Cryptocurrency miner",
    "minerd": "Cryptocurrency miner",
    "nheqminer": "Cryptocurrency miner",
    "t-rex": "Cryptocurrency miner",
    "nbminer": "Cryptocurrency miner",
    "ngrok": "Tunnel that exposes the device to the internet",
    "chisel": "Network tunnelling tool",
    "frpc": "Reverse-proxy tunnel client",
    "gost": "Tunnelling proxy",
    "plink": "SSH tunnelling client (often abused)",
    "ncat": "Netcat (remote shell / data transfer)",
    "netcat": "Netcat (remote shell / data transfer)",
    "nc": "Netcat (remote shell / data transfer)",
    "socat": "Socket relay (remote shell / data transfer)",
    "meterpreter": "Metasploit payload",
    "beacon": "Possible Cobalt Strike beacon",
}

# --- Remote access tools (common in tech-support scams) ---------------------
REMOTE_ACCESS = {
    "anydesk", "teamviewer", "teamviewer_service", "screenconnect.clientservice",
    "screenconnect.windowsclient", "connectwisecontrol", "ammyy_admin", "aa_v3",
    "rustdesk", "ultraviewer", "ultraviewer_service", "splashtop",
    "srservice", "atera_agent", "ateraagent", "client32", "rserver3", "radmin",
    "logmein", "lmiguardiansvc", "gotoassist", "bomgar-scc", "supremo",
    "remoteutilities", "rutserv", "rfusclient", "zohoassist", "tightvnc",
    "tvnserver", "winvnc", "vncserver", "x11vnc", "uvnc_service", "dwagent",
}

# --- Windows system process names & where they must live --------------------
WINDOWS_SYSTEM_BINARIES = {
    "svchost.exe": ["\\windows\\system32\\", "\\windows\\syswow64\\"],
    "lsass.exe": ["\\windows\\system32\\"],
    "csrss.exe": ["\\windows\\system32\\"],
    "winlogon.exe": ["\\windows\\system32\\"],
    "services.exe": ["\\windows\\system32\\"],
    "smss.exe": ["\\windows\\system32\\"],
    "wininit.exe": ["\\windows\\system32\\"],
    "spoolsv.exe": ["\\windows\\system32\\"],
    "taskhostw.exe": ["\\windows\\system32\\"],
    "dllhost.exe": ["\\windows\\system32\\", "\\windows\\syswow64\\"],
    "conhost.exe": ["\\windows\\system32\\"],
    "rundll32.exe": ["\\windows\\system32\\", "\\windows\\syswow64\\"],
    "explorer.exe": ["\\windows\\"],
    "lsm.exe": ["\\windows\\system32\\"],
    "dwm.exe": ["\\windows\\system32\\"],
    "sihost.exe": ["\\windows\\system32\\"],
    "ctfmon.exe": ["\\windows\\system32\\", "\\windows\\syswow64\\"],
}
# Linux kernel-thread / daemon names commonly faked by malware.
LINUX_MASQUERADE_NAMES = {"kworker", "kthreadd", "ksoftirqd", "migration",
                          "rcu_sched", "kswapd0", "watchdog", "kdevtmpfs"}

# --- Script hosts / "living off the land" binaries --------------------------
SCRIPT_HOSTS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe",
                "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
                "certutil.exe", "bitsadmin.exe", "msbuild.exe", "installutil.exe",
                "powershell", "pwsh", "bash", "sh", "zsh", "dash", "python",
                "python3", "perl", "osascript", "curl", "wget"}
# These should almost never make internet connections on their own.
LOLBIN_NETWORK = {"mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
                  "bitsadmin.exe", "msbuild.exe", "installutil.exe",
                  "wscript.exe", "cscript.exe", "cmstp.exe", "odbcconf.exe"}
OFFICE_APPS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
               "msaccess.exe", "mspub.exe", "onenote.exe", "acrord32.exe",
               "acrobat.exe", "foxitreader.exe", "microsoft word",
               "microsoft excel", "microsoft powerpoint", "microsoft outlook"}
BROWSERS = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
            "iexplore.exe", "chrome", "firefox", "brave", "safari", "msedge",
            "google chrome", "microsoft edge", "opera"}
EMAIL_CLIENTS = {"outlook.exe", "thunderbird.exe", "thunderbird", "mail",
                 "hxoutlook.exe", "olk.exe"}

# Command-line patterns (regex on the lower-cased command line) seen in attacks.
# Patterns marked PS only apply when PowerShell is involved, to avoid false alarms.
PS_ONLY = {0, 1, 2}
SUSPICIOUS_CMDLINE = [
    (r"-e(nc|ncodedcommand)?\s+[a-z0-9+/=]{40,}", "Encoded (hidden) PowerShell command"),
    (r"-w(indowstyle)?\s+hid", "PowerShell launched with a hidden window"),
    (r"\biex\b|invoke-expression", "PowerShell running code it built at runtime"),
    (r"downloadstring|downloadfile|invoke-webrequest|net\.webclient|start-bitstransfer",
     "Script downloading content from the internet"),
    (r"frombase64string", "Script decoding hidden (Base64) content"),
    (r"certutil.*-urlcache", "certutil abused to download a file"),
    (r"bitsadmin.*/transfer", "bitsadmin abused to download a file"),
    (r"mshta\s+.*(http|javascript|vbscript)", "mshta running remote/inline script"),
    (r"rundll32.*javascript:", "rundll32 running inline JavaScript"),
    (r"regsvr32.*/i:\s*http", "regsvr32 loading a remote script (Squiblydoo)"),
    (r"(curl|wget)[^|;]*\|\s*(ba|z|da)?sh", "Download piped straight into a shell"),
    (r"base64\s+(-d|--decode)[^|]*\|\s*(ba|z)?sh", "Decoded content piped into a shell"),
    (r"/dev/tcp/\d", "Reverse shell over /dev/tcp"),
    (r"\bnc(at)?\b.*\s-e\s", "Netcat executing a shell (reverse shell)"),
    (r"python[0-9.]*\s+-c\s+.*socket", "Python one-liner opening a network socket"),
    (r"vssadmin.*delete\s+shadows|wbadmin.*delete|bcdedit.*recoveryenabled\s+no",
     "Backups/shadow copies being deleted (ransomware behaviour)"),
    (r"stratum\+tcp://", "Connecting to a cryptocurrency mining pool"),
]

# --- Ports -------------------------------------------------------------------
SUSPICIOUS_PORTS = {
    4444: "Metasploit default handler",
    4445: "Common reverse-shell port",
    1337: "Common backdoor port",
    31337: "Classic backdoor port (Back Orifice)",
    6666: "IRC (used by botnets)", 6667: "IRC (used by botnets)",
    6668: "IRC (used by botnets)", 6669: "IRC (used by botnets)",
    3333: "Crypto-mining pool (stratum)", 14444: "Crypto-mining pool (Monero)",
    45700: "Crypto-mining pool", 5555: "Mining pool / Android debug / RAT",
    9001: "Tor relay", 9030: "Tor directory", 9050: "Tor SOCKS proxy",
    9150: "Tor Browser SOCKS proxy", 1604: "DarkComet RAT", 5552: "njRAT",
    8848: "Common RAT port", 2222: "Alternate SSH (often backdoors)",
}
# Protocols whose contents a sniffer can read in plain text.
CLEARTEXT_PORTS = {
    21: "FTP (logins and files in plain text)",
    23: "Telnet (everything typed is visible)",
    25: "SMTP email (may be unencrypted)",
    80: "HTTP web traffic (pages, forms, cookies visible)",
    110: "POP3 email (password visible)",
    143: "IMAP email (password visible)",
    389: "LDAP directory (credentials may be visible)",
    445: "SMB file sharing (hashes can be captured)",
    1433: "SQL Server", 3306: "MySQL", 5432: "PostgreSQL",
    5900: "VNC remote desktop", 8080: "HTTP alternate port",
    161: "SNMP", 69: "TFTP",
}

# Well-known public DNS resolvers (anything else public is worth a look).
KNOWN_DNS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220", "4.2.2.1", "4.2.2.2", "64.6.64.6",
    "64.6.65.6", "94.140.14.14", "94.140.15.15", "76.76.2.0", "76.76.10.0",
    "185.228.168.9", "2001:4860:4860::8888", "2001:4860:4860::8844",
    "2606:4700:4700::1111", "2606:4700:4700::1001", "2620:fe::fe",
}

# Domains attackers commonly redirect via the hosts file.
HOSTS_PROTECTED_KEYWORDS = [
    "microsoft", "windowsupdate", "google", "apple", "icloud", "bank", "paypal",
    "chase", "wellsfargo", "bankofamerica", "amazon", "facebook", "instagram",
    "norton", "mcafee", "kaspersky", "avast", "avg", "bitdefender", "eset",
    "malwarebytes", "sophos", "virustotal", "office", "live.com", "outlook",
]

# --- Files --------------------------------------------------------------------
EXECUTABLE_EXT = {".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".sys", ".msi",
                  ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse",
                  ".wsf", ".wsh", ".hta", ".jar", ".lnk", ".iso", ".img", ".app",
                  ".sh", ".command", ".py", ".pl", ".elf", ".bin", ".run",
                  ".dylib", ".so", ".pkg", ".dmg", ".xll", ".docm", ".xlsm",
                  ".pptm", ".one"}
DECOY_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png",
             ".txt", ".zip", ".rar", ".mp4", ".mp3", ".invoice", ".ppt", ".pptx"}
RANSOM_NOTE_HINTS = ["readme", "decrypt", "restore", "recover", "how_to", "ransom",
                     "your_files", "!!!"]
RANSOM_EXT = {".locked", ".encrypted", ".crypt", ".crypted", ".enc", ".locky",
              ".cerber", ".wncry", ".wcry", ".ryk", ".conti", ".lockbit", ".akira",
              ".blackcat", ".royal", ".basta"}

# EICAR is the industry-standard harmless antivirus test file. Including it lets
# you safely confirm the scanner works (see README install guide, "Testing").
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
EICAR_MARKER = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
BUILTIN_BAD_HASHES = {EICAR_SHA256: "EICAR antivirus test file (harmless test)"}

# Processes allowed to read particular sensitive stores (lower-case names).
EXPECTED_READERS = {
    "browser": BROWSERS | {"chromium", "chromium-browser", "vivaldi", "opera_gx",
                           "msedgewebview2.exe", "google chrome helper"},
    "ssh": {"ssh", "ssh.exe", "ssh-agent", "ssh-agent.exe", "git", "git.exe",
            "scp", "sftp", "code", "code.exe", "putty.exe", "pageant.exe",
            "gnome-keyring-daemon", "sshd", "1password", "keychain"},
}


_PS_RE = re.compile(r"powershell|pwsh")


def match_cmdline(cmd: str):
    """Return the reason a command line looks malicious, or None."""
    low = (cmd or "").lower()
    if not low:
        return None
    is_ps = bool(_PS_RE.search(low))
    for i, (pattern, why) in enumerate(SUSPICIOUS_CMDLINE):
        if i in PS_ONLY and not is_ps:
            continue
        if re.search(pattern, low):
            return why
    return None
