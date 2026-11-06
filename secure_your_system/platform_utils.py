"""Operating-system helpers: privilege detection, paths, safe command runner."""
from __future__ import annotations

import getpass
import ipaddress
import os
import platform
import socket
import subprocess
import sys
from pathlib import Path
from typing import Optional

OS = platform.system()            # "Windows", "Darwin", "Linux"
IS_WINDOWS = OS == "Windows"
IS_MAC = OS == "Darwin"
IS_LINUX = OS == "Linux"
HOME = Path.home()

try:
    import psutil  # type: ignore
    HAS_PSUTIL = True
except ImportError:  # the app still runs, with fewer checks
    psutil = None
    HAS_PSUTIL = False


def os_name() -> str:
    return {"Darwin": "macOS"}.get(OS, OS)


def is_admin() -> bool:
    try:
        if IS_WINDOWS:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def host_info() -> dict:
    info = {
        "hostname": socket.gethostname(),
        "user": _safe(getpass.getuser),
        "os": f"{os_name()} {platform.release()}",
        "os_version": platform.version(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "admin": is_admin(),
        "psutil": HAS_PSUTIL,
    }
    if HAS_PSUTIL:
        try:
            info["boot_time"] = psutil.boot_time()
        except Exception:
            pass
    return info


def _safe(fn, default="unknown"):
    try:
        return fn()
    except Exception:
        return default


def run_cmd(args, timeout: int = 20) -> Optional[str]:
    """Run a command and return stdout, or None if it failed / is missing."""
    kwargs = {}
    if IS_WINDOWS:
        kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
    try:
        out = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout,
            errors="replace", **kwargs,
        )
        return out.stdout if out.returncode == 0 or out.stdout else None
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def powershell(command: str, timeout: int = 30) -> Optional[str]:
    if not IS_WINDOWS:
        return None
    return run_cmd(
        ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
         "Bypass", "-Command", command],
        timeout=timeout,
    )


def env_path(var: str) -> Optional[Path]:
    v = os.environ.get(var)
    return Path(v) if v else None


def temp_dirs() -> list:
    dirs = []
    if IS_WINDOWS:
        for var in ("TEMP", "TMP"):
            p = env_path(var)
            if p:
                dirs.append(p)
        windir = env_path("WINDIR") or Path(r"C:\Windows")
        dirs.append(windir / "Temp")
    else:
        dirs += [Path("/tmp"), Path("/var/tmp")]
        if IS_LINUX:
            dirs.append(Path("/dev/shm"))
        tmp = os.environ.get("TMPDIR")
        if tmp:
            dirs.append(Path(tmp))
    return _uniq_existing(dirs)


def user_drop_dirs() -> list:
    """Folders where downloaded / dropped files usually land."""
    dirs = [HOME / "Downloads", HOME / "Desktop"]
    if IS_WINDOWS:
        for var in ("APPDATA", "LOCALAPPDATA", "PUBLIC", "PROGRAMDATA"):
            p = env_path(var)
            if p:
                dirs.append(p)
    elif IS_MAC:
        dirs += [Path("/Users/Shared"), HOME / "Library" / "Application Support"]
    else:
        dirs += [HOME / ".local" / "bin", HOME / ".cache"]
    return _uniq_existing(dirs)


def _uniq_existing(paths) -> list:
    seen, out = set(), []
    for p in paths:
        try:
            r = str(p.resolve()).lower() if IS_WINDOWS else str(p.resolve())
        except OSError:
            continue
        if r not in seen and p.exists():
            seen.add(r)
            out.append(p)
    return out


def norm(path: str) -> str:
    p = os.path.normpath(path or "")
    return p.lower() if IS_WINDOWS else p


def path_in(path: str, folders) -> bool:
    p = norm(path)
    for f in folders:
        f = norm(str(f))
        if f and (p == f or p.startswith(f.rstrip("\\/") + os.sep)):
            return True
    return False


def is_public_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local
                or a.is_multicast or a.is_reserved or a.is_unspecified)


def file_times(path) -> tuple:
    try:
        st = os.stat(path)
        created = getattr(st, "st_birthtime", None) or (st.st_ctime if IS_WINDOWS else None)
        return st.st_mtime, st.st_atime, created
    except OSError:
        return None, None, None


def open_location(path: str) -> None:
    """Open the folder containing `path` in the system file manager."""
    folder = path if os.path.isdir(path) else os.path.dirname(path)
    try:
        if IS_WINDOWS:
            subprocess.Popen(["explorer", "/select,", path])
        elif IS_MAC:
            subprocess.Popen(["open", "-R", path])
        else:
            subprocess.Popen(["xdg-open", folder])
    except OSError:
        pass


def relaunch_as_admin() -> bool:
    """Windows only: relaunch this program with a UAC prompt."""
    if not IS_WINDOWS:
        return False
    try:
        import ctypes
        if getattr(sys, "frozen", False):
            exe, params = sys.executable, " ".join(sys.argv[1:])
        else:
            exe = sys.executable
            params = " ".join(['-m', 'secure_your_system'] + sys.argv[1:])
        workdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, workdir, 1)
        return rc > 32
    except Exception:
        return False
