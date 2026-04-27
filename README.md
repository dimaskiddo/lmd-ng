# 🛡️ Linux Malware Detect Next Generation (LMD-NG) 🚀

Welcome to the future of Linux security! **LMD-NG** is a complete, ground-up rewrite of the legendary **Linux Malware Detect (LMD/MalDet)**. We've taken the battle-tested logic of the original Bash-based tool and supercharged it with the speed, safety, and modern features of **Pure Golang**! 🐹✨

Whether you're protecting a high-traffic server, a personal workstation, or a fleet of cloud instances, LMD-NG is designed to be your lightweight, lightning-fast, and cross-platform guardian. No more heavy shell scripts—just pure, compiled power! 🦾

---

## ✨ Why LMD-NG?

*   **⚡ Blazing Performance:** Rewritten in Pure Go for maximum efficiency and minimal resource footprint.
*   **📦 Zero Dependencies:** Compiled with `CGO_ENABLED=0`. It's a single static binary that just *works*.
*   **🌍 Truly Cross-Platform:** Not just for Linux! LMD-NG runs beautifully on **macOS** and **Windows** too.
*   **🕵️ Real-Time Protection:** Native file system monitoring (using `fsnotify`) catches threats the moment they land.
*   **🔄 Modern Signature Updates:** Seamlessly pulls the latest threat definitions to keep you safe.
*   **🦠 Native ClamAV Support:** Built-in loader for ClamAV databases with **zero** `libclamav` dependency. Access a massive signature library natively! 
*   **🛠️ Service Integration:** Easily install/uninstall as a system service with a single command.
*   **🔒 Secure Quarantine:** Safely isolates threats with optional AES encryption to prevent accidental execution.
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
      --name lmd-ng \
      -v ./config.yaml:/etc/lmd-ng/config.yaml \
      -v /path/to/scan:/data:ro \
      dimaskiddo/lmd-ng:latest \
      lmd-ng daemon
    ```

### 📦 **Using Pre-Built Binaries**

Speed is of the essence! Grab a pre-built binary and go.

1.  Download the latest release from our [Releases Page](https://github.com/dimaskiddo/lmd-ng/releases).
2.  **Extract and Run:**
    ```sh
    # Give it execution power!
    chmod +x lmd-ng
    
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
*   **`lmd-ng service install`**: Automatically register LMD-NG as a background service. ⚙️
*   **`lmd-ng service uninstall`**: Cleanly remove the system service. 🧹

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
