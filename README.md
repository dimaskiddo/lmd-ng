# 🛡️ Linux Malware Detect Next Generation (LMD-NG)

**LMD-NG** is a ground-up rewrite of **Linux Malware Detect (LMD/MalDet)**. Built with **Golang and CGO**, LMD-NG brings security logic to **Linux**, **macOS**, and **Windows** with a client-server architecture.

A centralized **Database Signature Service (DBS)** loads signature databases into memory once, while lightweight **Real-Time Protector (RTP)** clients and CLI tools stream data for matching.

---

## ✨ Why LMD-NG?

*   **⚡ Client-Server Architecture:** Centralized signature matching via **DBS** (server) while **RTP** and **On-Demand Scan** act as lightweight clients, reducing memory overhead across multiple nodes.
*   **🕵️ Real-Time Protection:** Native file system monitoring—**FSEvents** on macOS (via CGO/Zig) and **fsnotify** on Linux/Windows.
*   **🔍 On-Demand Scanning:** Manual scans of any directory. Scan CLI acts as a DBS client for centralized, in-memory signatures.
*   **🔄 Intelligent Updates:** Automated signature updates with hot-reload—DBS stays current without restarting active scans.
*   **⬆️ Self-Upgrade:** One-command binary upgrade from GitHub releases. Downloads, stops services, replaces the binary, restarts — with automatic checksum verification.
*   **📊 Status Dashboard:** `lmd-ng status` shows DBS reachability, engine signature counts (MD5, SHA256, HEX, RFXN, ClamAV HDB/NDB/MDB), CVD database versions, quarantine count, RTP paths, and scheduler config.
*   **📦 Native ClamAV Loader:** Pure Go support for ClamAV databases (`.cvd`, `.cld`, `.ndb`, `.hdb`, `.mdb`). No `libclamav` or `os/exec` dependencies.
*   **📥 Secure Quarantine:** AES-256-GCM encryption, POSIX attribute preservation, short-ID lookup.
*   **🔒 Secure Streaming:** TLS mutual authentication over Unix domain sockets or TCP.
*   **📧 Multi-Channel Alerts:** Email (SMTP), Telegram, Discord, and Slack notifications on quarantine events.
*   **📊 Structured Logging:** Go `slog` with lumberjack rotation.
*   **🚀 Auto-Tuned System Limits:** Automatically optimizes file descriptor limits for heavy scans.
*   **🌍 Cross-Platform:** Linux, macOS, Windows. No legacy bash dependencies.
*   **🛠️ Zig CGO Toolchain:** Compiled with `CGO_ENABLED=1` using the **Zig compiler** for reproducible cross-platform builds.
---

## 🏗️ Architecture at a Glance

```mermaid
graph TD
    subgraph "DBS Server (Database Signature Service)"
        DB_S["Signature Databases"] --> Engine_S["Memory Loader"]
        Engine_S --> Matcher_S["Pattern Matcher"]
    end

    subgraph "Clients (RTP / Scan CLI)"
        Source["File System Events / Path"]
        
        subgraph "Local Engine (On-Demand Fallback)"
            DB_L["Local DB"] --> Engine_L["Memory Loader"]
            Engine_L --> Matcher_L["Pattern Matcher"]
        end

        Streamer["Data Streamer"]
        
        Source --> Streamer
        Streamer -- "Remote Matching" --> Matcher_S
        Source -- "Local Matching" --> Matcher_L
        
        Matcher_S -- "Detection Result" --> ActionHandler["Action Handler"]
        Matcher_L -- "Detection Result" --> ActionHandler
        
        ActionHandler --> Notifier["Email / Telegram / Discord / Slack"]
        ActionHandler --> Quarantine["Quarantine Manager"]
    end
```

---

## ⚠️ Upgrading

> **Quarantine encryption format changed after v0.2.0.** Files quarantined with
> encryption enabled on affected versions used a broken format and **cannot be
> successfully restored**. Before upgrading, check your quarantined files and try
> restoring them; if restoration fails, remove the affected entries:
>
> ```sh
> lmd-ng quarantine list
> lmd-ng quarantine restore <id>        # or:
> lmd-ng quarantine remove --force <id>
> ```
>
> **Unencrypted quarantine files are unaffected** and restore normally after upgrading.

---

## 🚀 Getting Started

### 📋 Prerequisites

*   **Go** (1.21+)
*   **Make** (For Builds)
*   **Zig** (Required for Cross-Compilation CGO)

---

## 🛠️ Deployment

### 🐳 **Using Container**

1.  **Install Docker** following the [official guide](https://docs.docker.com/get-docker/).
2.  **Run the combined daemon:**
    ```sh
    docker run -d \
      -v /data/to/protect:/data:rw \
      -v /path/to/config.yaml:/usr/local/lmd-ng/config.yaml \
      --name lmd-ng \
      dimaskiddo/lmd-ng:latest
    ```

### 📦 **Using Pre-Built Binaries**

1.  Download the latest release from the [Releases Page](https://github.com/dimaskiddo/lmd-ng/releases).
2.  **Installation & Startup:**

#### 🐧 **Linux / 🍎 macOS**
```sh
chmod +x lmd-ng

# Update signature databases
./lmd-ng update

# Install services (requires sudo)
sudo ./lmd-ng service install atp
sudo ./lmd-ng service install dbs
sudo ./lmd-ng service install rtp

# Start services one-by-one
sudo ./lmd-ng service start atp
sudo ./lmd-ng service start dbs
sudo ./lmd-ng service start rtp
```

#### 🪟 **Windows**
*(Run from an Administrator Command Prompt)*
```powershell
# Update signature databases
.\lmd-ng.exe update

# Install services
.\lmd-ng.exe service install atp
.\lmd-ng.exe service install dbs
.\lmd-ng.exe service install rtp

# Start services one-by-one
.\lmd-ng.exe service start atp
.\lmd-ng.exe service start dbs
.\lmd-ng.exe service start rtp
```

### 🔐 Verifying Releases

Release artifacts are published with a `checksums.txt` file. `lmd-ng upgrade`
verifies the downloaded archive against `checksums.txt` automatically before
replacing the binary. To verify a manual download:

```bash
sha256sum -c checksums.txt --ignore-missing
```

### 🏗️ **Build From Source**

```sh
git clone https://github.com/dimaskiddo/lmd-ng.git
cd lmd-ng
make vendor
make build
# Binary is located in dist/lmd-ng
```

---

## 🕹️ Usage & Commands

LMD-NG is managed via a CLI:

### 💂‍♂️ Daemon Services
*   **`lmd-ng daemon`**: Start **ATP** (Anti-Tamper Protection), **DBS** (Server), and **RTP** (Client) in one process. ATP starts first to lock files before DBS loads signatures.
*   **`lmd-ng daemon atp`**: Start only the Anti-Tamper Protection daemon (locks critical files against tampering).
*   **`lmd-ng daemon dbs`**: Start only the Database Signature Service.
*   **`lmd-ng daemon rtp`**: Start only the Real-Time Protector (monitors file system).

Each daemon component writes to its **own log file** (default `<logs_dir>/lmd-ng-<component>.log`), overridable with `--log-file`.

### 🔍 Scanning & Updates
*   **`lmd-ng scan <path>`**: Perform an on-demand scan. Streams data to the local DBS. Uses the main config log path by default; pass `--log-file` to redirect to a separate scan log.
*   **`lmd-ng update`**: Update signatures and trigger a hot-reload in the running DBS.
*   **`lmd-ng upgrade [--force]`**: Self-upgrade binary from GitHub releases. Without `--force`, exits early if already up-to-date.
*   **`lmd-ng status`**: Display DBS reachability, signature counts, CVD versions, quarantine, RTP config.
*   **`lmd-ng version`**: Display binary version and commit hash.

### 📥 Quarantine Management
*   **`lmd-ng quarantine list`**: List all quarantined files.
*   **`lmd-ng quarantine add <file>`**: Manually move a suspicious file into quarantine.
*   **`lmd-ng quarantine restore <id|path>`**: Restore a file to its original location with full attribute preservation.
*   **`lmd-ng quarantine restore <id|path> --to <path>`**: Export the file to a custom path for analysis. The file **remains in quarantine** (evidence preserved); the original path is recorded in `<path>.original-path.txt`.
*   **`lmd-ng quarantine remove <id|path>`**: Permanently delete a threat (requires `--force`).

### 📁 Log Files

Each component writes to its own file for easier debugging. All logs rotate with the same settings from the `logging` section of `config.yaml` (`max_size`, `max_backups`, `max_age`, `compress`).

| Component | Default path |
|---|---|
| Combined daemon | `<logs_dir>/lmd-ng.log` (config `logging.filepath`) |
| ATP | `<logs_dir>/lmd-ng-atp.log` |
| DBS | `<logs_dir>/lmd-ng-dbs.log` |
| RTP | `<logs_dir>/lmd-ng-rtp.log` |
| On-demand scan | config `logging.filepath` (or `--log-file`) |

---

### ⚙️ Service Management
Manage LMD-NG components as background services (Systemd, Launchd, or Windows Services). Operations require elevated privileges.

Services are installed with startup **dependencies** baked in: `dbs` requires `atp`, and `rtp` requires both `atp` and `dbs`. Starting a service whose dependency is not running fails with a clear error. `service install` also bakes in the config path and a per-component log file (override with `--log-file`).

*   **Install Services**:
    *   `lmd-ng service install`: Register **ATP**, **DBS**, and **RTP** services.
    *   `lmd-ng service install atp`: Register only the Anti-Tamper Protection daemon.
    *   `lmd-ng service install dbs`: Register only the Database Signature Service (server).
    *   `lmd-ng service install rtp`: Register only the Real-Time Protector (client).
    *   `lmd-ng service install dbs --log-file /var/log/lmd-ng/dbs.log`: Install with an explicit log path.
*   **Control Services**:
    *   `lmd-ng service start [atp|dbs|rtp]`: Start services. If no component is specified, **ATP is started first**, followed by **DBS**, then **RTP**.
    *   `lmd-ng service stop [atp|dbs|rtp]`: Stop services. If no component is specified, **RTP is stopped first**, followed by **DBS**, then **ATP** (ATP releases last).
    *   `lmd-ng service restart [atp|dbs|rtp]`: Restart services. If no component is specified, **ATP is restarted first**, followed by **DBS**, then **RTP**.
*   **Uninstall Services**:
    *   `lmd-ng service uninstall`: Stop and remove **ATP**, **DBS**, and **RTP** services. **RTP is uninstalled first**, followed by **DBS**, then **ATP**.
    *   `lmd-ng service uninstall atp`: Stop and remove the Anti-Tamper Protection daemon.
    *   `lmd-ng service uninstall dbs`: Stop and remove only the Database Signature Service (server).
    *   `lmd-ng service uninstall rtp`: Stop and remove only the Real-Time Protector (client).

---

## 🧪 Testing

```sh
go test ./...
```
*Note: Integration tests validate the compiled binary in `dist/`.*

---

## ✍️ Authors

*   **Dimas Restu Hidayanto** - *Initial Work & Architecture* - [DimasKiddo](https://github.com/dimaskiddo)

---

## 🏗️ Dependencies

*   **[Go](https://golang.org/)**
*   **[Zig](https://ziglang.org/)** - CGO cross-compilation
*   **[Cobra](https://github.com/spf13/cobra)** - CLI framework
*   **[Viper](https://github.com/spf13/viper)** - YAML configuration with hot-reload
*   **[robfig/cron](https://github.com/robfig/cron)** - Scheduling for updates and scans
*   **[fsnotify/fsnotify](https://github.com/fsnotify/fsnotify)** - File system watcher (Linux/Windows)
*   **[fsnotify/fsevents](https://github.com/fsnotify/fsevents)** - FSEvents watcher (macOS)
*   **[kardianos/service](https://github.com/kardianos/service)** - OS service management
*   **[natefinch/lumberjack](https://github.com/natefinch/lumberjack)** - Log rotation

---

## ⚠️ Disclaimer

**DO WITH YOUR OWN RISK (DWYOR)**. This software is provided "as is", without warranty of any kind, express or implied. Use of this software may involve risks, including but not limited to system instability or data loss. The authors are not responsible for any damage caused by the use of this application.

---

## ⚖️ License

Distributed under the **MIT License**. See `LICENSE` for more information.

---
**LMD-NG** — *Next Generation Security for a Modern World.* 🛡️🌐
