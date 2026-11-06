# Credits, Sources & Acknowledgements

This file records where Evan's Secure Your System came from: who built it, how it was built, what software and documentation it relies on, and which existing tools it's similar to.

For the security research behind each individual check (MITRE ATT&CK techniques, NIST guidance and so on), see **[docs/HOW-IT-WORKS.md → References](docs/HOW-IT-WORKS.md#references)**.

---

## 1. Authorship and how the software was made

| Role | Credit |
|---|---|
| Project owner, concept and requirements | **Evan Alexander Maroulis** |
| Product direction (features, "what was taken / sniffed" analysis, recommendations when nothing is found, user-friendly interface, naming, visual theme) | Evan Maroulis |
| Code, documentation and packaging scripts | Written with **Claude** (Anthropic), working from Evan's specifications |
| Review, testing on real hardware, publishing | Evan Maroulis |

### AI assistance disclosure

This project was built with the help of **Claude**, an AI model made by Anthropic, using the Claude app on November 6, 2026.

Claude's part:
- **Built the program:** designed the architecture and wrote the Python source code, the graphical interface, the HTML report generator, the install guide (README), this credits file and the How It Works guide.
- **Tested the scan:** tested the scanning engine in a Linux test environment against simulated threats, including:
  - the harmless EICAR test file
  - a fake "kworker" process running from a hidden temp folder
  - a fake auto-start entry
  - a backdoor-style listener that had an SSH key open
  - a disguised `invoice.pdf.exe`

  The tests checked that each one was detected, then the test artefacts were removed.
- **Checked the sources:** researched and checked the references cited in the documentation using web search.

Evan defined what the software must do, chose the name and visual direction, ran it on his own computer, and approved each change.

Code written with AI assistance can contain mistakes. Like any security tool, its results should be confirmed with the further checks it recommends.

**How to cite the AI assistance:**

> Anthropic. (2026). *Claude* (Claude Opus 5.5) [Large language model]. https://claude.ai

Commits in this repository that Claude helped write carry a `Co-Authored-By: Claude` line, so the git history shows the same thing.

### How the code was written
Claude wrote the code from its general knowledge of Python and of the documented interfaces of Windows, macOS and Linux. No code was copied from the tools listed in section 4. The official documentation in sections 2 and 3 is the authoritative reference for each interface the program uses, and the right place to check its behaviour.

### Visual design
The dark violet theme with magenta highlights and a lime action button was inspired by a reference screenshot Evan supplied. It was used **only** as a reference for colour and style. No images, logos, text or other assets from it are included in this project.

---

## 2. Software this project uses

| Component | What it's used for | Licence | Documentation |
|---|---|---|---|
| **Python 3** | Programming language and standard library | PSF License | https://docs.python.org/3/ |
| **tkinter / ttk** (part of Python) | The desktop window and all on-screen controls | PSF License | https://docs.python.org/3/library/tkinter.html |
| **psutil** | Listing running programs, network connections and open files on every OS | BSD 3-Clause | https://psutil.readthedocs.io/ |
| **yara-python** *(optional)* | Matching files against YARA malware rules you add | Apache 2.0 | https://virustotal.github.io/yara/ |
| **PyInstaller** *(build only)* | Packaging the program into a standalone `.exe` / app | GPL 2.0 with bootloader exception (your built app isn't affected) | https://pyinstaller.org/ |

Python standard-library modules used, with documentation:
- `hashlib` (SHA-256 file fingerprints): https://docs.python.org/3/library/hashlib.html
- `subprocess` (running built-in OS commands safely): https://docs.python.org/3/library/subprocess.html
- `winreg` (reading Windows auto-start registry keys): https://docs.python.org/3/library/winreg.html
- `plistlib` (reading macOS LaunchAgent files): https://docs.python.org/3/library/plistlib.html
- `ctypes` (Windows administrator check and "Run as Administrator"): https://docs.python.org/3/library/ctypes.html
- `ipaddress` (separating private and internet addresses): https://docs.python.org/3/library/ipaddress.html
- `threading` and `queue` (keeping the window responsive during a scan): https://docs.python.org/3/library/threading.html
- `argparse` (terminal mode): https://docs.python.org/3/library/argparse.html

---

## 3. Operating-system documentation (Windows, macOS, Linux)

The program reads the system through each OS's own built-in interfaces. These are the official or best available references for them.

### Windows
| Interface | Used for | Reference |
|---|---|---|
| `Get-MpThreatDetection` (Microsoft Defender) | Past and current Defender detections | https://learn.microsoft.com/en-us/powershell/module/defender/get-mpthreatdetection |
| `MSFT_NetAdapter` / `Get-NetAdapter` (`PromiscuousMode`) | Spotting network adapters in packet-capture mode | https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/hh968170(v=vs.85) |
| Sysinternals Autoruns (recommended in Further Checks) | Reference list of Windows auto-start locations | https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns |
| Mark of the Web (`Zone.Identifier` stream) | Finding where a downloaded file came from | https://textslashplain.com/2016/04/04/downloads-and-the-mark-of-the-web/ (Eric Lawrence, Microsoft) |

### macOS
| Interface | Used for | Reference |
|---|---|---|
| File Quarantine (`com.apple.quarantine`) and Gatekeeper | Finding which app downloaded a file; checking Gatekeeper status | https://redcanary.com/blog/gatekeeper |
| LaunchAgents / LaunchDaemons | Auto-start items | See MITRE T1543 in [HOW-IT-WORKS](docs/HOW-IT-WORKS.md#references) |
| KnockKnock (recommended in Further Checks) | Reference list of macOS persistence locations | https://objective-see.org/products/knockknock.html |

### Linux
| Interface | Used for | Reference |
|---|---|---|
| `packet(7)` (AF_PACKET sockets, promiscuous mode) | Finding programs that capture raw network traffic | https://www.man7.org/linux/man-pages/man7/packet.7.html |
| `/proc` filesystem | Process, socket and ARP information | https://man7.org/linux/man-pages/man5/proc.5.html |
| `ld.so(8)` (`/etc/ld.so.preload`) | Rootkit-style library injection | https://man7.org/linux/man-pages/man8/ld.so.8.html |

---

## 4. Similar tools (for comparison and further reading)

These established tools cover similar ground. They were used as a **conceptual benchmark** for what a compromise check should cover, and several are recommended in the app's Further Checks tab. **None of their code is included in this project.**

| Tool | Platform | What it does | Link |
|---|---|---|---|
| Sysinternals Autoruns | Windows | Lists every auto-start location, with signature and VirusTotal checks | https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns |
| KnockKnock (Objective-See) | macOS | Uncovers persistently installed software to reveal malware | https://objective-see.org/products/knockknock.html |
| LOKI (Florian Roth / Nextron) | Win/Mac/Linux | Open-source Python IOC and YARA scanner (filenames, hashes, YARA, C2) | https://github.com/Neo23x0/Loki |
| Velociraptor | Win/Mac/Linux | Endpoint visibility and forensic collection | https://docs.velociraptor.app/ |
| osquery | Win/Mac/Linux | Query system state like a database | https://osquery.io/ |
| rkhunter / chkrootkit | Linux/Unix | Rootkit and backdoor scanners | https://rkhunter.sourceforge.net/ |
| ClamAV | Win/Mac/Linux | Open-source antivirus engine | https://www.clamav.net/ |
| Volatility 3 | Win/Mac/Linux | Memory forensics (recommended for advanced cases) | https://volatility3.readthedocs.io/ |
| EICAR test file | All | Industry-standard harmless file for testing detection | https://www.eicar.org/download-anti-malware-testfile/ |

How this project differs: it combines malware, sniffing and persistence checks in one plain-language desktop app. It also adds an analysis layer that estimates the origin of a problem, what may have been taken or sniffed, and what to do next, aimed at non-experts.

---

## 5. Security knowledge base

The detection logic is based on public security research. The full, linked reference list is in **[docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md#references)**. In summary:
- **MITRE ATT&CK®**, about 30 technique pages: masquerading, network sniffing, ARP cache poisoning, persistence mechanisms, credential theft, ransomware and more.
- **NIST SP 800-61 Rev. 3** (2025), incident response recommendations, which structure the "Do This Now" steps.
- **Microsoft, Apple and Linux** documentation, listed above.

---

*MITRE ATT&CK® is a registered trademark of The MITRE Corporation. Windows, Microsoft Defender and Sysinternals are trademarks of Microsoft. macOS and Gatekeeper are trademarks of Apple Inc. Claude is a product of Anthropic. All trademarks belong to their owners. This project isn't affiliated with or endorsed by any of them.*
