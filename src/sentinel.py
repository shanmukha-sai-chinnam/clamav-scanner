#!/usr/bin/env python3
"""ClamAV File Creation Sentinel Daemon.

Monitors directories in real-time using Linux kernel inotify.
When a file is created or written, it streams the file to ClamAV daemon via INSTREAM.
If infected, quarantines the file and alerts the user.
"""

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import struct
import subprocess
import sys
import time
from typing import Dict, List, Optional, Set

# Import ClamAVClient
sys.path.insert(0, str(Path(__file__).resolve().parent))
from clamav_client import ClamAVClient, ScanResult

# Linux inotify constants
IN_CLOEXEC = 0x80000
IN_NONBLOCK = 0x800
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_ISDIR = 0x40000000

# Combined mask: file creation, moved into dir, or finished write
WATCH_MASK = IN_CREATE | IN_MOVED_TO | IN_CLOSE_WRITE | IN_ISDIR

# ANSI Colors
COLOR_RESET = "\033[0m"
COLOR_GREEN = "\033[32m"
COLOR_RED = "\033[31;1m"
COLOR_YELLOW = "\033[33m"
COLOR_CYAN = "\033[36m"
COLOR_GRAY = "\033[90m"


class InotifyWatcher:
    """Zero-dependency wrapper over Linux kernel inotify."""

    def __init__(self):
        self.libc = ctypes.CDLL("libc.so.6", use_errno=True)
        self.fd = self.libc.inotify_init1(IN_CLOEXEC | IN_NONBLOCK)
        if self.fd < 0:
            errno = ctypes.get_errno()
            raise OSError(errno, f"Failed to initialize inotify: {os.strerror(errno)}")

        self.wd_to_path: Dict[int, Path] = {}
        self.path_to_wd: Dict[Path, int] = {}

    def add_watch(self, path: Path, mask: int = WATCH_MASK) -> int:
        c_path = str(path.resolve()).encode("utf-8")
        wd = self.libc.inotify_add_watch(self.fd, c_path, mask)
        if wd < 0:
            errno = ctypes.get_errno()
            raise OSError(errno, f"Failed to add watch for {path}: {os.strerror(errno)}")
        self.wd_to_path[wd] = path
        self.path_to_wd[path] = wd
        return wd

    def remove_watch(self, wd: int):
        if wd in self.wd_to_path:
            path = self.wd_to_path.pop(wd)
            self.path_to_wd.pop(path, None)
            self.libc.inotify_rm_watch(self.fd, wd)

    def read_events(self) -> List[tuple]:
        """Read pending inotify events from file descriptor."""
        events = []
        try:
            raw_data = os.read(self.fd, 65536)
        except (BlockingIOError, InterruptedError):
            return events

        offset = 0
        header_size = struct.calcsize("iIII")
        while offset + header_size <= len(raw_data):
            wd, mask, cookie, length = struct.unpack_from("iIII", raw_data, offset)
            offset += header_size
            name_bytes = raw_data[offset : offset + length]
            offset += length
            # Strip trailing null bytes
            name = name_bytes.split(b"\0", 1)[0].decode("utf-8", errors="replace")
            events.append((wd, mask, cookie, name))
        return events

    def close(self):
        if self.fd >= 0:
            self.libc.close(self.fd)
            self.fd = -1


class Sentinel:
    """File creation monitoring and ClamAV quarantine engine."""

    IGNORE_DIRS = {
        ".git",
        "result",
        ".quarantine",
        ".direnv",
        "__pycache__",
        ".cache",
        "node_modules",
        ".cargo",
    }

    def __init__(
        self,
        watch_dir: Path,
        client: ClamAVClient,
        quarantine_dir: Path,
        audit_log: Path,
        recursive: bool = True,
        auto_quarantine: bool = True,
    ):
        self.watch_dir = watch_dir.resolve()
        self.client = client
        self.quarantine_dir = quarantine_dir.resolve()
        self.audit_log = audit_log.resolve()
        self.recursive = recursive
        self.auto_quarantine = auto_quarantine
        self.watcher = InotifyWatcher()
        self.recently_scanned: Dict[str, float] = {}  # path -> timestamp

        # Ensure quarantine directory exists
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

    def should_ignore(self, path: Path) -> bool:
        """Filter out internal / build / temp directories."""
        resolved = path.resolve()
        if resolved == self.audit_log:
            return True
        if path.name.endswith(".jsonl") or path.name.endswith(".log"):
            return True
        # Check parts against ignore list
        for part in path.parts:
            if part in self.IGNORE_DIRS:
                return True
            if part.startswith(".") and part != "." and part != "..":
                # Ignore hidden directories / dotfiles
                return True
        # Ignore temp swap files
        name = path.name
        if name.endswith("~") or name.endswith(".tmp") or name.endswith(".swp"):
            return True
        return False

    def setup_watches(self):
        """Recursively register inotify watches on the target directory."""
        if not self.watch_dir.exists():
            raise FileNotFoundError(f"Watch directory does not exist: {self.watch_dir}")

        self.watcher.add_watch(self.watch_dir)
        print(f"{COLOR_CYAN}👁️  Monitoring root:{COLOR_RESET} {self.watch_dir}")

        if self.recursive:
            count = 1
            for root, dirs, _ in os.walk(self.watch_dir):
                # Filter out ignored dirs in-place
                dirs[:] = [d for d in dirs if d not in self.IGNORE_DIRS and not d.startswith(".")]
                for d in dirs:
                    sub_path = Path(root) / d
                    try:
                        self.watcher.add_watch(sub_path)
                        count += 1
                    except OSError as e:
                        print(f"{COLOR_YELLOW}⚠️  Could not watch {sub_path}: {e}{COLOR_RESET}")
            print(f"{COLOR_CYAN}📂 Subdirectories registered:{COLOR_RESET} {count}")

    def compute_sha256(self, file_path: Path) -> str:
        h = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return "unknown"

    def quarantine_file(self, file_path: Path, virus_name: str) -> Path:
        """Safely move infected file to quarantine and remove permissions."""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        dest_name = f"{timestamp}_{file_path.name}"
        dest_path = self.quarantine_dir / dest_name

        try:
            # Move file into quarantine
            shutil.move(str(file_path), str(dest_path))
            # Strip all permissions (chmod 000) so it cannot be read or executed
            os.chmod(dest_path, 0)
            return dest_path
        except Exception as e:
            print(f"{COLOR_RED}❌ Quarantine failure for {file_path}: {e}{COLOR_RESET}")
            return file_path

    def notify_user(self, title: str, message: str, urgency: str = "critical"):
        """Send desktop alert via libnotify if available."""
        if shutil.which("notify-send"):
            try:
                subprocess.run(
                    ["notify-send", "-u", urgency, "-a", "ClamAV-Sentinel", title, message],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except Exception:
                pass

    def log_event(self, event_data: dict):
        """Append structured JSON event to audit log."""
        try:
            with open(self.audit_log, "a", encoding="utf-8") as f:
                f.write(json.dumps(event_data) + "\n")
        except Exception as e:
            print(f"{COLOR_YELLOW}⚠️  Failed to write audit log: {e}{COLOR_RESET}")

    def handle_file(self, file_path: Path):
        """Perform scan on the newly created or written file."""
        if not file_path.is_file() or self.should_ignore(file_path):
            return

        # Debounce: avoid scanning same file twice within 0.5s
        path_str = str(file_path)
        now = time.time()
        if path_str in self.recently_scanned:
            if now - self.recently_scanned[path_str] < 0.5:
                return
        self.recently_scanned[path_str] = now

        # Prune old entries from recently_scanned
        if len(self.recently_scanned) > 1000:
            cutoff = now - 5.0
            self.recently_scanned = {p: t for p, t in self.recently_scanned.items() if t > cutoff}

        try:
            size_bytes = file_path.stat().st_size
        except OSError:
            return

        # Perform ClamAV scan via INSTREAM socket
        result = self.client.scan_file(file_path)
        sha256 = self.compute_sha256(file_path) if file_path.exists() else "none"

        event = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "file": str(file_path),
            "size_bytes": size_bytes,
            "sha256": sha256,
            "status": result.status,
            "virus_name": result.virus_name,
            "latency_ms": round(result.latency_ms, 2),
            "raw_response": result.raw_response,
        }

        if result.is_infected:
            print(
                f"{COLOR_RED}🚨 [INFECTED] {file_path}{COLOR_RESET}\n"
                f"   Virus: {COLOR_RED}{result.virus_name}{COLOR_RESET} | Size: {size_bytes}B | "
                f"Time: {result.latency_ms:.1f}ms"
            )
            if self.auto_quarantine:
                quarantine_target = self.quarantine_file(file_path, result.virus_name or "Malware")
                event["quarantined_to"] = str(quarantine_target)
                print(f"   {COLOR_YELLOW}📦 Quarantined to: {quarantine_target} (chmod 000){COLOR_RESET}")
                self.notify_user(
                    "Threat Quarantined!",
                    f"Virus: {result.virus_name}\nFile: {file_path.name}\nMoved to: {quarantine_target}",
                    urgency="critical",
                )
            else:
                self.notify_user(
                    "Threat Detected!",
                    f"Virus: {result.virus_name}\nFile: {file_path}",
                    urgency="critical",
                )
        elif result.is_clean:
            print(
                f"{COLOR_GREEN}✓ [CLEAN]{COLOR_RESET} {file_path} "
                f"{COLOR_GRAY}({size_bytes}B, {result.latency_ms:.1f}ms){COLOR_RESET}"
            )
        else:
            print(f"{COLOR_YELLOW}⚠️  [ERROR]{COLOR_RESET} {file_path}: {result.raw_response}")

        self.log_event(event)

    def run(self):
        """Main event polling loop."""
        self.setup_watches()
        print(f"{COLOR_GREEN}🛡️  ClamAV Sentinel running. Waiting for file creation events...{COLOR_RESET}")

        poll = select.poll()
        poll.register(self.watcher.fd, select.POLLIN)

        try:
            while True:
                # Poll with 500ms timeout
                ready = poll.poll(500)
                if not ready:
                    continue

                for wd, mask, cookie, name in self.watcher.read_events():
                    base_path = self.watcher.wd_to_path.get(wd)
                    if not base_path:
                        continue

                    full_path = base_path / name if name else base_path

                    # If a new directory was created, watch it recursively
                    if mask & IN_ISDIR and (mask & (IN_CREATE | IN_MOVED_TO)):
                        if self.recursive and not self.should_ignore(full_path):
                            for root, dirs, files in os.walk(full_path):
                                dirs[:] = [d for d in dirs if d not in self.IGNORE_DIRS and not d.startswith(".")]
                                p = Path(root)
                                try:
                                    self.watcher.add_watch(p)
                                    print(f"{COLOR_CYAN}📂 Subdirectory watch added:{COLOR_RESET} {p}")
                                except OSError:
                                    pass
                                for f in files:
                                    self.handle_file(p / f)
                        continue

                    # If a regular file creation / moved / write event
                    if mask & (IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE):
                        # Short sleep to allow quick atomic writes to flush
                        time.sleep(0.02)
                        self.handle_file(full_path)

        except KeyboardInterrupt:
            print(f"\n{COLOR_CYAN}Stopping ClamAV Sentinel...{COLOR_RESET}")
        finally:
            self.watcher.close()


def main():
    parser = argparse.ArgumentParser(description="ClamAV Real-Time File Sentinel")
    parser.add_argument(
        "--watch-dir",
        type=Path,
        default=Path("."),
        help="Directory to watch for file creations (default: current directory)",
    )
    parser.add_argument("--host", default="127.0.0.1", help="ClamAV daemon host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=3310, help="ClamAV daemon port (default: 3310)")
    parser.add_argument(
        "--quarantine-dir",
        type=Path,
        default=Path(".quarantine"),
        help="Directory to store quarantined files (default: .quarantine)",
    )
    parser.add_argument(
        "--audit-log",
        type=Path,
        default=Path("clamav-audit.jsonl"),
        help="Path to JSONL audit log file",
    )
    parser.add_argument(
        "--no-quarantine",
        action="store_true",
        help="Disable automatic quarantine (alert only)",
    )
    parser.add_argument(
        "--no-recursive",
        action="store_true",
        help="Disable recursive subdirectory monitoring",
    )

    args = parser.parse_args()

    client = ClamAVClient(host=args.host, port=args.port)
    sentinel = Sentinel(
        watch_dir=args.watch_dir,
        client=client,
        quarantine_dir=args.quarantine_dir,
        audit_log=args.audit_log,
        recursive=not args.no_recursive,
        auto_quarantine=not args.no_quarantine,
    )
    sentinel.run()


if __name__ == "__main__":
    main()
