# 🛡️ ClamAV Sentinel

> Real-time, event-driven antivirus monitoring for NixOS-WSL powered by Docker-based ClamAV daemon (`clamd`).

`clamav-sentinel` continuously monitors file creation and modification events in real-time using Linux kernel `inotify`. Newly created files are immediately streamed over TCP (`INSTREAM` protocol) to an in-memory ClamAV container. Threats are neutralized instantly through automated quarantine isolation and desktop notifications, achieving sub-10ms scan latencies without the CPU overhead of spawning fresh scanning processes.

---

## ⚡ Architecture

```text
 ┌─────────────────────────────────────────────────────────────┐
 │                      NixOS-WSL Host                         │
 │                                                             │
 │   New File Created / Written                                │
 │   (/home/damathryxx64/repositories/...)                     │
 │               │                                             │
 │               ▼                                             │
 │   ┌───────────────────────┐                                 │
 │   │ inotify Event Watcher │  (IN_CREATE, IN_CLOSE_WRITE)    │
 │   └───────────┬───────────┘                                 │
 │               │  Filters (.git, result, .quarantine)        │
 │               ▼                                             │
 │   ┌───────────────────────┐                                 │
 │   │ INSTREAM Socket Client│                                 │
 │   └───────────┬───────────┘                                 │
 └───────────────┼─────────────────────────────────────────────┘
                 │ TCP Stream (127.0.0.1:3310)
                 ▼
 ┌─────────────────────────────────────────────────────────────┐
 │               Docker Container (clamav-daemon)              │
 │                                                             │
 │   ┌─────────────────────────────────────────────────────┐   │
 │   │ clamd (In-Memory Database: 8.5M+ Virus Signatures)  │   │
 │   └──────────────────────────┬──────────────────────────┘   │
 │                              │                              │
 │   ┌──────────────────────────┴──────────────────────────┐   │
 │   │ freshclam (Automated background signature updates)  │   │
 │   └─────────────────────────────────────────────────────┘   │
 └──────────────────────────────┬──────────────────────────────┘
                                │ Verdict (OK / FOUND)
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │                   Response & Quarantine                     │
 │                                                             │
 │  • CLEAN    -> Log event (timestamp, SHA-256, scan time)    │
 │  • INFECTED -> Move to .quarantine/<ts>_<file> (chmod 000)  │
 │             -> Desktop Alert (libnotify)                    │
 │             -> Audit Log (clamav-audit.jsonl)               │
 └─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### 1. Enter Environment
```bash
cd /home/damathryxx64/repositories/clamav-scanner
nix develop
# or run commands directly using ./bin/clamav-sentinel
```

### 2. Start ClamAV Daemon
```bash
./bin/clamav-sentinel up
```
*Note: On first startup, ClamAV pulls the Docker image and initializes virus definitions.*

### 3. Check Status
```bash
./bin/clamav-sentinel status
```

### 4. Start Real-Time Watcher
```bash
# Watch current working directory
./bin/clamav-sentinel watch

# Or watch entire repositories folder
./bin/clamav-sentinel watch /home/damathryxx64/repositories
```

---

## 🛠️ CLI Reference

| Command | Description |
|---|---|
| `clamav-sentinel up` | Start ClamAV container in background and wait for daemon health |
| `clamav-sentinel down` | Stop ClamAV container |
| `clamav-sentinel restart` | Restart ClamAV container |
| `clamav-sentinel status` | Inspect container status, connectivity, and database version |
| `clamav-sentinel scan <path>` | Scan a specific file or folder on demand |
| `clamav-sentinel watch [dir]` | Launch continuous file creation sentinel on target directory |
| `clamav-sentinel logs` | Tail ClamAV daemon container logs |
| `clamav-sentinel test` | Run unit tests and live End-to-End (E2E) integration suite |

### Watcher Options
```bash
./bin/clamav-sentinel watch [directory] [options]

Options:
  --quarantine-dir <path>   Directory for isolated malware (default: .quarantine)
  --audit-log <path>        Path for JSONL audit log (default: clamav-audit.jsonl)
  --no-quarantine           Alert and log only without moving infected files
  --no-recursive            Monitor top-level directory only (disable recursion)
```

---

## 📦 Quarantine & Threat Neutralization

When a malicious file is detected:
1. **Immediate Relocation**: The file is removed from the active directory and relocated to `.quarantine/<YYYYMMDD_HHMMSS>_<original_name>`.
2. **Permission Stripping**: Permissions are set to `000` (`chmod 000`), neutralizing accidental execution or read access.
3. **Desktop Alert**: Dispatches a high-priority notification via `notify-send`.
4. **Audit Record**: Records file path, size, SHA-256 hash, virus signature name, and latency in `clamav-audit.jsonl`.

---

## 🔄 Systemd Background Service

To run ClamAV Sentinel automatically on login in your NixOS-WSL user session:

```bash
mkdir -p ~/.config/systemd/user/
cp systemd/clamav-sentinel.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now clamav-sentinel.service
```

Check service status and logs:
```bash
systemctl --user status clamav-sentinel.service
journalctl --user -u clamav-sentinel.service -f
```

---

## 🧪 Testing

Run all unit tests and live E2E integration verification:
```bash
./bin/clamav-sentinel test
```

Unit tests validate socket framing, INSTREAM protocol chunking, error handling, debouncing, and quarantine logic. E2E tests create real benign files and live EICAR virus signatures in a sandbox to verify end-to-end detection and isolation.
