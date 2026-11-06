"""File-system scan: known-bad hashes, disguised files, droppers, ransomware traces."""
from __future__ import annotations

import hashlib
import math
import os
import stat
from collections import Counter
from pathlib import Path

from .. import ioc_data as ioc
from ..models import CheckResult, Finding, Severity
from ..platform_utils import HOME, IS_WINDOWS, env_path, file_times, path_in, temp_dirs, user_drop_dirs

NAME = "Files & downloads"
SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".cache", "site-packages", ".npm", ".cargo",
             ".rustup", ".gradle", ".m2", "venv", ".venv", "caches", "cache", "code cache",
             "gpucache", "service worker", "indexeddb", ".trash", "$recycle.bin", "winsxs",
             "library/containers", "photos library.photoslibrary", "music"}
MAX_HASH_BYTES = 60 * 1024 * 1024
RLO = "‮"


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def entropy(path: str) -> float:
    try:
        with open(path, "rb") as fh:
            data = fh.read(1024 * 1024)
    except OSError:
        return 0.0
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _is_executable(path: str, name: str, st) -> bool:
    ext = os.path.splitext(name)[1].lower()
    if ext in ioc.EXECUTABLE_EXT:
        return True
    if not IS_WINDOWS and st.st_mode & stat.S_IXUSR and stat.S_ISREG(st.st_mode):
        return True
    return False


def _hidden(path: str, name: str, st) -> bool:
    if name.startswith("."):
        return True
    if IS_WINDOWS:
        return bool(getattr(st, "st_file_attributes", 0) & 0x2)
    return False


def _roots(ctx):
    roots = list(temp_dirs()) + [d for d in user_drop_dirs() if d.name in ("Downloads", "Desktop", "Shared", "Public")]
    if IS_WINDOWS:
        appdata = env_path("APPDATA")
        if appdata:
            roots.append(appdata / r"Microsoft\Windows\Start Menu\Programs\Startup")
    if ctx.deep:
        roots.append(HOME)
        if IS_WINDOWS and env_path("PROGRAMDATA"):
            roots.append(env_path("PROGRAMDATA"))
    seen, out = set(), []
    for r in roots:
        if r.exists() and str(r) not in seen:
            seen.add(str(r))
            out.append(r)
    return out


def run(ctx) -> CheckResult:
    res = CheckResult(NAME)
    temps = temp_dirs()
    downloads = [d for d in user_drop_dirs() if d.name == "Downloads"]
    limit = 400_000 if ctx.deep else 40_000
    max_depth = 12 if ctx.deep else 4
    scanned = hashed = denied = 0
    ransom_files, ransom_notes, recent_downloads = [], [], []
    temp_exec_findings = 0
    visited = set()

    for root in _roots(ctx):
        root_depth = str(root).count(os.sep)
        for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
            if ctx.cancelled or scanned >= limit:
                break
            if dirpath in visited:
                dirnames[:] = []
                continue
            visited.add(dirpath)
            low = dirpath.lower().replace("\\", "/")
            dirnames[:] = [d for d in dirnames
                           if d.lower() not in SKIP_DIRS and not any(s in low + "/" + d.lower() for s in SKIP_DIRS if "/" in s)]
            if dirpath.count(os.sep) - root_depth >= max_depth:
                dirnames[:] = []
            if scanned % 2000 == 0:
                ctx.progress(f"Scanning files… {scanned:,} checked ({dirpath[:70]})")
            for name in filenames:
                scanned += 1
                path = os.path.join(dirpath, name)
                try:
                    st = os.lstat(path)
                except PermissionError:
                    denied += 1
                    continue
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                lname = name.lower()
                ext = os.path.splitext(lname)[1]

                # Ransomware traces
                if ext in ioc.RANSOM_EXT:
                    ransom_files.append(path)
                if ext in (".txt", ".html", ".hta") and any(h in lname for h in ioc.RANSOM_NOTE_HINTS) \
                        and any(k in lname for k in ("decrypt", "ransom", "restore", "recover", "files")):
                    ransom_notes.append(path)

                # Right-to-left override filename trick
                if RLO in name:
                    res.findings.append(Finding(
                        check=NAME, category="malware", severity=Severity.CRITICAL, paths=[path],
                        title="File name uses a hidden character to fake its extension",
                        description="This file name contains an invisible 'right-to-left' character that "
                                    "makes, for example, 'invoice_fdp.exe' display as 'invoice_exe.pdf'. "
                                    "It is only used to trick people into running malware.",
                        evidence={"File": path}, first_seen=st.st_mtime))

                executable = _is_executable(path, name, st)
                parts = lname.split(".")
                if executable and len(parts) >= 3 and "." + parts[-2] in ioc.DECOY_EXT \
                        and "." + parts[-1] in ioc.EXECUTABLE_EXT:
                    res.findings.append(Finding(
                        check=NAME, category="malware", severity=Severity.HIGH, paths=[path],
                        title=f"File disguised with a double extension: {name}",
                        description="The name looks like a document or picture, but the real extension "
                                    "makes it a program. This is a common email-attachment trick.",
                        evidence={"File": path, "Size (KB)": round(st.st_size / 1024, 1)},
                        first_seen=st.st_mtime))

                # Hash / signature / YARA matching
                small_any = st.st_size <= 4096
                if (executable or small_any) and st.st_size <= MAX_HASH_BYTES:
                    try:
                        digest = sha256(path)
                        hashed += 1
                        hit = ctx.bad_hashes.get(digest)
                        if not hit and small_any:
                            with open(path, "rb") as fh:
                                if ioc.EICAR_MARKER in fh.read():
                                    hit = "EICAR antivirus test file (harmless test)"
                        if hit:
                            test = "EICAR" in hit
                            res.findings.append(Finding(
                                check=NAME, category="malware",
                                severity=Severity.MEDIUM if test else Severity.CRITICAL,
                                title=f"Known malicious file detected: {name}",
                                description=(f"This file matches a known indicator: {hit}. "
                                             + ("It is the standard harmless test file, which confirms "
                                                "detection is working." if test else
                                                "Do not open it. Quarantine it with your antivirus.")),
                                evidence={"File": path, "SHA-256": digest, "Indicator": hit},
                                paths=[path], first_seen=st.st_mtime))
                            continue
                        if ctx.yara_rules and executable and st.st_size < 20 * 1024 * 1024:
                            matches = ctx.yara_rules.match(path, timeout=10)
                            if matches:
                                res.findings.append(Finding(
                                    check=NAME, category="malware", severity=Severity.HIGH,
                                    title=f"YARA rule matched: {name}",
                                    description="This file matches one of your YARA malware rules.",
                                    evidence={"File": path, "Rules": [m.rule for m in matches],
                                              "SHA-256": digest},
                                    paths=[path], first_seen=st.st_mtime))
                    except (OSError, Exception):
                        pass

                if not executable:
                    continue

                # Programs/scripts sitting in temp folders
                if path_in(path, temps) and temp_exec_findings < 40:
                    recent = ctx.in_window(st.st_mtime)
                    hidden = _hidden(path, name, st) or any(
                        part.startswith(".") for part in os.path.relpath(dirpath, str(next(
                            (t for t in temps if path_in(path, [t])), dirpath))).split(os.sep) if part != ".")
                    if recent or hidden:
                        ent = entropy(path) if ext in (".exe", ".dll", ".scr", "") else 0.0
                        sev = Severity.MEDIUM
                        if hidden and recent:
                            sev = Severity.HIGH
                        temp_exec_findings += 1
                        res.findings.append(Finding(
                            check=NAME, category="malware", severity=sev, paths=[path],
                            title=f"{'Hidden program/script' if hidden else 'Program/script'} in a temp folder: {name}",
                            description=("Programs and scripts placed in temp folders are how many attacks "
                                         "start (droppers). Many are leftovers from installers; check any "
                                         "you do not recognise."
                                         + (" The file appears packed/encrypted, which malware uses to "
                                            "avoid detection." if ent > 7.2 else "")),
                            evidence={"File": path, "Size (KB)": round(st.st_size / 1024, 1),
                                      "Hidden": hidden, "Packed-looking (entropy)": round(ent, 2) if ent else "n/a"},
                            first_seen=st.st_mtime))

                if downloads and path_in(path, downloads) and ctx.in_window(st.st_mtime):
                    recent_downloads.append((path, st.st_mtime))

    if ransom_files or len(ransom_notes) >= 2:
        heavy = len(ransom_files) >= 20 or len(ransom_notes) >= 3
        res.findings.append(Finding(
            check=NAME, category="malware",
            severity=Severity.CRITICAL if heavy else Severity.MEDIUM,
            title="Possible ransomware traces" if heavy else "File names resembling ransomware",
            description=(f"{len(ransom_files)} file(s) have extensions used by ransomware and "
                         f"{len(ransom_notes)} file(s) look like ransom notes. "
                         + ("This strongly suggests files have been encrypted by ransomware."
                            if heavy else "Could be coincidental; check whether these files still open.")),
            evidence={"Encrypted-looking files": ransom_files[:15], "Possible ransom notes": ransom_notes[:10]},
            paths=(ransom_notes + ransom_files)[:40]))

    if recent_downloads:
        recent_downloads.sort(key=lambda x: -x[1])
        res.findings.append(Finding(
            check=NAME, category="malware", severity=Severity.INFO,
            title=f"{len(recent_downloads)} program(s)/script(s) downloaded in the last {ctx.window_days} day(s)",
            description="Not a problem on its own. These are the most likely entry points if an infection "
                        "is found, so confirm you recognise each one.",
            evidence={"Files": [p for p, _ in recent_downloads[:25]]},
            paths=[p for p, _ in recent_downloads[:25]]))

    res.stats.update({"files_checked": scanned, "files_hashed": hashed,
                      "known_bad_indicators": len(ctx.bad_hashes),
                      "yara": bool(ctx.yara_rules), "scan_scope": "deep" if ctx.deep else "quick"})
    if denied:
        res.limited.append(f"{denied} file(s) could not be opened due to permissions.")
    if scanned >= limit:
        res.limited.append(f"Stopped after {limit:,} files (scan limit).")
    res.limited.extend(ctx.notes)
    return res
