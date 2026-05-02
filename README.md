# 🛡️ Linux Malware Detect Next Generation (LMD-NG)

Welcome to the future of multi-platform security! **LMD-NG** is a complete, ground-up rewrite of the legendary **Linux Malware Detect (LMD/MalDet)**. While the original LMD was built specifically for Linux, **LMD-NG** brings that same battle-tested logic to **Windows** and **macOS**, supercharged with the speed, safety, and modern features of **Pure Golang**! 🐹✨

Whether you're protecting a high-traffic server, a personal workstation, or a fleet of cloud instances, LMD-NG is designed to be your lightweight, lightning-fast, and cross-platform guardian. With **real-time email alerts** and **automated quarantine**, you can rest easy knowing your systems are protected across all major operating systems! 🦾

---

## ✨ Why LMD-NG?

*   **⚡ Blazing Performance:** Rewritten in Pure Go for maximum efficiency and minimal resource footprint.
*   **📦 Zero Dependencies:** Compiled with `CGO_ENABLED=0`. It's a single static binary that just *works*.
*   **🌍 Truly Cross-Platform:** Breaking free from the Linux-only roots of the original LMD, LMD-NG runs natively on **Windows**, **macOS**, and **Linux**! 🚀
*   **🕵️ Real-Time Protection:** Native file system monitoring (using `fsnotify`) catches threats the moment they land.
*   **🔄 Modern Signature Updates:** Seamlessly pulls the latest threat definitions to keep you safe.
*   **🌐 Smart Updater:** Internet-aware signature updater that validates connectivity and dynamically manages ClamAV User-Agent versions directly from GitHub.
*   **🚀 Auto-Tuned System Limits:** Automatically optimizes file descriptor limits to ensure smooth performance during heavy scans, even on restricted environments like macOS.
*   **🦠 Native ClamAV Support:** Built-in loader for ClamAV databases with **zero** `libclamav` dependency. Access a massive signature library natively! 
*   **🛠️ Service Integration:** Easily install, uninstall, start, stop, or restart as a system service with built-in commands.
*   **🔒 Secure Quarantine:** Safely isolates threats with optional AES encryption to prevent accidental execution.
*   **📧 Email Notifications:** Get instant HTML-formatted alerts when malware is detected. Supports SMTP with SSL/TLS.
*   **📊 Structured Logging:** Clean, modern logs using Go's `slog` for better observability.

---

## 🚀 Getting Started

Getting up and running with LMD-NG is as easy as a breeze! 🌬️

### 📋 Prerequisites

*   **Go** (1.21+ recommended) - The engine under the hood.
*   **Make** - For automated building magic.
*   **GoReleaser** (Optional) - For building your own mass distributions.

---

## 🛠️ Deployment

### 🐳 **Using Container**

Ready to containerize your security? We've got you covered!

1.  **Install Docker** following the [official guide](https://docs.docker.com/get-docker/).
2.  **Fire it up!**
    ```sh
    docker run -d \
      -v <PATH_TO_CONFIG_YAML_FILE>:/usr/app/lmd-ng/config.yaml \
      -v <PATH_TO_BE_SCANNED_OR_MONITORED>:/data:rw \
      --name lmd-ng \
      --restart unless-stopped \
      dimaskiddo/lmd-ng:latest \
      lmd-ng daemon --config /usr/app/lmd-ng/config.yaml
    ```

### 📦 **Using Pre-Built Binaries**

Speed is of the essence! Grab a pre-built binary and go.

1.  Download the latest release from our [Releases Page](https://github.com/dimaskiddo/lmd-ng/releases).
2.  **Extract and Run:**
    ```sh
    # Give it execution power!
    chmod +x lmd-ng

    # Check version
    ./lmd-ng version

    # Run first database signature update
    ./lmd-ng update
    
    # Start the daemon
    ./lmd-ng daemon
    ```

### 🏗️ **Build From Source**

For the true crafters who love to build their own tools:

1.  **Clone the repository:**
    ```sh
    git clone https://github.com/dimaskiddo/lmd-ng.git
    cd lmd-ng
    ```
2.  **Install dependencies:**
    ```sh
    make vendor
    ```
3.  **Build the magic:**
    ```sh
    make build
    ```
4.  **Find your binary** in the `dist/` directory! 🎉

---

## 🕹️ Usage & Commands

LMD-NG comes with a powerful CLI. Here are the most common commands:

*   **`lmd-ng daemon`**: Start the resident monitor and internal scheduler. 💂‍♂️
*   **`lmd-ng scan <path>`**: Perform a manual, on-demand scan of a specific directory. 🔍
*   **`lmd-ng update`**: Manually trigger a signature database update. 🔄
*   **`lmd-ng quarantine list`**: List all files currently in quarantine. 📋
*   **`lmd-ng quarantine add <file>`**: Manually move a suspicious file to quarantine. 📥
*   **`lmd-ng quarantine restore <id|path>`**: Restore a file from quarantine to its original location. 📤
*   **`lmd-ng quarantine remove <id|path>`**: Permanently delete a quarantined file (requires `--force`). 🗑️
*   **`lmd-ng service <action>`**: Manage LMD-NG as a background service (supports Windows Services, macOS Launchd, and Linux Systemd/Upstart). ⚙️
    *   `install`: Register LMD-NG as a system service.
    *   `uninstall`: Stop and remove the system service.
    *   `start`: Start the LMD-NG background service.
    *   `stop`: Stop the LMD-NG background service.
    *   `restart`: Restart the LMD-NG background service.
*   **`lmd-ng version`**: Display the version information. ℹ️

---

## 🧪 Running The Tests

We take security seriously! Run the tests to ensure everything is perfect:
```sh
go test ./...
```
*(Note: Integration tests validate the compiled binary in `dist/` for real-world accuracy!)*

---

## 🏗️ Built With Love & Power

*   **[Go](https://golang.org/)** - The legendary programming language.
*   **[Cobra](https://github.com/spf13/cobra)** - Modern CLI framework.
*   **[fsnotify](https://github.com/fsnotify/fsnotify)** - Cross-platform file system watcher.
*   **[kardianos/service](https://github.com/kardianos/service)** - Multi-platform service manager.

---

## ✍️ Authors

*   **Dimas Restu Hidayanto** - *Initial Work & Architecture* - [DimasKiddo](https://github.com/dimaskiddo)

Love this project? Give it a ⭐ and help us grow!

---

## ⚖️ License

Copyright (C) 2026 Dimas Restu Hidayanto.

Distributed under the **MIT License**. See `LICENSE` for more information.

---
**LMD-NG** — *Next Generation Security for a Modern World.* 🛡️🌐
