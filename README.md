# Evan's Secure Your System

**Version 1.0 · Download & install guide**

Evan's Secure Your System checks your computer for signs of malware, network sniffing and data theft. Then it tells you, in plain language:

- **What it found** and how serious each finding is
- **Where the problem likely came from** (download, email attachment, USB drive, remote session, your network)
- **What may have been taken or sniffed**, and which files on your computer are affected
- **What to do right now**, step by step
- **Which further checks to run** when it finds nothing, or when it can't see everything

Secure Your System only reads your system. It never deletes, moves or changes anything.

Works on **Windows 10/11**, **macOS 12+** and **Linux** (Ubuntu, Debian, Fedora, etc.).

## Quick start

1. Install **Python 3.9+** from <https://www.python.org/downloads/> (Windows: tick **Add python.exe to PATH**).
2. Unzip **Evans-Secure-Your-System.zip**.
3. Start it:
   - **Windows:** double-click `run_windows.bat`
   - **macOS/Linux:** run `./run_mac_linux.sh` in a terminal
4. Press **Start Scan**.

The full instructions follow.

## What's in the download

| File / folder | Purpose |
|---|---|
| `run_windows.bat` | Starts Secure Your System on Windows (sets itself up on first run) |
| `run_mac_linux.sh` | Starts Secure Your System on macOS and Linux |
| `build_windows.bat` / `build_mac_linux.sh` | Optional: builds a standalone app that doesn't need Python |
| `secure_your_system/` | The program's source code |
| `custom_iocs/` | Optional: your own malware hashes and YARA rules |
| `requirements.txt` | The helper packages that get installed automatically |
| `README.md` | This guide |
| `DEVELOPER.md` | How the code is organised, for programmers |

---

## Option A: Easiest (run with Python)

### Step 1: Install Python (one time only)

| System | What to do |
|---|---|
| **Windows** | Go to <https://www.python.org/downloads/>, click **Download Python 3.x**, and run the installer. **On the first screen, tick "Add python.exe to PATH"**, then click *Install Now*. |
| **macOS** | Go to <https://www.python.org/downloads/>, download the macOS installer and run it. (The python.org version includes the window toolkit Secure Your System uses.) |
| **Linux** | Open a terminal and run: `sudo apt install python3 python3-venv python3-tk` (Ubuntu/Debian) or `sudo dnf install python3 python3-tkinter` (Fedora). |

You need Python 3.9 or newer.

### Step 2: Get Secure Your System

1. Download **Evans-Secure-Your-System.zip**.
2. Right-click it and choose **Extract All…** (Windows) or double-click it (macOS/Linux).
3. Put the extracted **Evans-Secure-Your-System** folder somewhere convenient, like your Desktop.

### Step 3: Start it

| System | What to do |
|---|---|
| **Windows** | Open the Evans-Secure-Your-System folder and double-click **`run_windows.bat`**. If Windows shows "Windows protected your PC", click **More info → Run anyway** (this happens with any new script). |
| **macOS** | Open **Terminal**, type `cd ` (with a space), drag the Evans-Secure-Your-System folder into the Terminal window, press **Enter**, then run: `./run_mac_linux.sh` |
| **Linux** | Open a terminal in the Evans-Secure-Your-System folder and run: `./run_mac_linux.sh` |

The **first start takes about a minute** because it sets itself up (it installs one helper package, `psutil`, into its own private folder). Later starts are instant.

---

## Option B: Build a standalone app (no Python needed afterwards)

Use this to make a single program file you can copy to other computers.

- **Windows:** double-click `build_windows.bat`. When it finishes, your program is at `dist\Evans-Secure-Your-System.exe`.
- **macOS / Linux:** run `./build_mac_linux.sh`. Your program is in the `dist` folder.

Copy the whole `dist` folder (it includes `custom_iocs`) to wherever you want. Build on the same kind of system you'll run it on: Windows builds Windows apps, Mac builds Mac apps.

---

## Using Secure Your System

1. **Choose a scan type.**
   - **Quick** (recommended first): checks running programs, network, auto-start items, settings, and the key folders where malware usually lands (Temp, Downloads, Desktop). Takes about 1–3 minutes.
   - **Deep:** also scans your entire home folder. It can take 10+ minutes.
2. **Choose "When might it have happened?"** Activity in this period is treated as suspect. If you're unsure, keep **Last 7 days**.
3. Press **Start Scan**. You can keep using the computer.
4. Read the results in each tab:

| Tab | What it shows |
|---|---|
| **Overview** | A colour-coded verdict (green = clean, red = compromised), key numbers, and the most important findings |
| **Findings** | Every finding with its evidence. Click one for details; **Open file location** shows the file in your file manager |
| **Origin & Exposure** | Where it came from, what may have been taken, what may have been sniffed, where data may have gone, and the list of affected file locations |
| **Do This Now** | Numbered steps in order of urgency (Now → Today → This week) |
| **Further Checks** | Checks this program can't do itself: admin-only checks, router, online accounts and professional tools. **Use this tab if nothing was found** |
| **Scan Details** | What was checked, what was limited, and the program's limitations |

5. Click **Save Report ▾ → HTML** to keep a copy or send it to IT or a technician.

### Running with administrator rights (recommended)

Without admin rights, Secure Your System can't fully see programs and files that belong to the system or to other users. It still works, and the report lists exactly what was limited.

- **Windows:** click **Run as Administrator** in the app, or right-click `run_windows.bat` (or `Evans-Secure-Your-System.exe`) → **Run as administrator**.
- **macOS / Linux:** start it with `sudo ./run_mac_linux.sh`

### Terminal mode (no window)

```
python -m secure_your_system --cli                     # quick scan, prints results
python -m secure_your_system --cli --deep --days 30    # deep scan, 30-day window
python -m secure_your_system --cli --html report.html --json report.json
```

Exit codes: `0` = clean or minor, `1` = suspicious, `2` = likely or confirmed compromise.

---

## Testing that detection works (safe)

The **EICAR test file** is a harmless, industry-standard file that every antivirus product detects on purpose.

1. Create a text file in your Downloads folder named `eicar_test.txt` containing exactly this line:
   `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`
2. Run a Quick scan. Secure Your System should report **"Test file detected (scanner working)"**.
3. Delete the file. (Your antivirus may delete it first, which also proves the antivirus works.)

---

## Optional: adding your own threat indicators

- **Known-bad file hashes:** add SHA-256 hashes, one per line, to `custom_iocs/hashes.txt`.
- **YARA rules:** install `pip install yara-python` (inside `.venv`), then put `.yar` files in `custom_iocs/rules/`.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| "Python was not found" | Reinstall Python and tick **Add python.exe to PATH** (Windows). |
| Window doesn't open on Linux ("No module named tkinter") | `sudo apt install python3-tk`, or use terminal mode with `--cli`. |
| "psutil is not installed" message | Delete the `.venv` folder and start again, or run `pip install psutil`. |
| macOS says the script "cannot be opened" | Run `chmod +x run_mac_linux.sh` in Terminal, then try again. |
| Antivirus flags Secure Your System | Security tools sometimes flag scanners that inspect processes. The source code is included for you to review. |
| Scan seems slow | Deep scans of large home folders take time. Press **Stop**; the results found so far are kept. |

---

## Important limitations

- Secure Your System looks for **signs of compromise**. It does **not replace antivirus software**.
- It **cannot prove after the fact exactly what was stolen or which packets were sniffed**. That requires logs or packet captures recorded at the time. It estimates exposure from the evidence it can see now.
- Advanced kernel-level rootkits can hide from any program running on an infected system. If you suspect one, follow the **Further Checks → Advanced** steps.
- For a **work or school device**, contact your IT/security team before acting on the results.
