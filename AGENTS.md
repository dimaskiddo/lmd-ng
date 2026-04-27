# LMD-NG (Linux Malware Detect - Next Generation) AI Agent Instructions

## 🎯 Role & Objective
You are an expert Golang engineer and security software architect. Your task is to rewrite "Linux Malware Detect" (LMD/maldet) from its original Bash-based implementation into a modern, Next-Generation Golang application (`LMD-NG`).

## 📁 Directory Context
- **Current Directory (`./`)**: The root of the new `LMD-NG` Golang project.
- **Reference Directory (`../lmd`)**: The original Bash-based LMD source code. Use this strictly for reverse-engineering logic, configuration defaults, and legacy signature formats.

## 📋 Workflow & Task Tracking
- Always check `TASKS.md` before starting a new session to understand the current project state.
- **NEVER** rework, refactor, or touch items in `TASKS.md` marked as done (`[x]`) unless explicitly instructed by the human engineer.
- Update `TASKS.md` automatically when a task is completed.

## 🏗️ Strict Architectural Constraints

### 1. Pure Go (No CGO)
- The application MUST be compiled with `CGO_ENABLED=0`. 
- You must not use any C-bindings or libraries that require CGO. All dependencies and vendor libraries must be pure Go.

### 2. Native OS Implementation (No OS CLI Wrappers)
- LMD heavily relies on Linux binaries (`find`, `inotifywait`, `awk`, `sed`, `grep`). You must **NOT** use `os/exec` to call these tools.
- **File Traversal:** Replace `find` with Go's `path/filepath` (e.g., `filepath.WalkDir`).
- **File Monitoring:** Replace `inotifywait` with pure-Go cross-platform libraries (e.g., `github.com/fsnotify/fsnotify`).
- **Signature Matching:** Implement internal malware signature matching using Go's native `crypto` and `regexp` packages. Focus strictly on LMD's native Hex/MD5 signatures for the core implementation.

### 3. Phased ClamAV Integration (Deferred)
- **Phase 1 (Current):** Focus entirely on the main LMD functionality (file walking, monitoring, config parsing, and LMD native signature matching).
- **Phase 2 (Deferred):** The native parsing and loading of ClamAV databases (`.cvd`, `.cld`) into memory will be built later as an "Extra Signature" module. 
- **Requirement:** Design the core `scanner` interface to be highly extensible so the ClamAV engine can be seamlessly plugged in later. Once implemented, it must still be a pure-Go memory loader, completely avoiding `os/exec` calls to `clamscan` or `clamd`.

### 4. Configuration Migration
- The legacy LMD uses a bash-sourced configuration file (`conf.maldet`).
- Map all existing configuration variables and their default values into a structured YAML format (`config.yaml`).
- Create a robust configuration manager using a pure-Go library (e.g., `gopkg.in/yaml.v3` or `github.com/spf13/viper`). Honor the original intent of the legacy flags.

### 5. CLI, Scheduler & Service Management
- **No OS Cron:** Do not rely on `/etc/cron.daily` or similar OS-level cron daemons.
- **Internal Scheduler:** Implement scheduling for updates and daemon scans using pure Go (e.g., `github.com/robfig/cron/v3` or native `time.Ticker`).
- **CLI Framework:** Build a robust CLI interface using `github.com/spf13/cobra` or the native `flag` package.
- **Required Subcommands:**
  - `lmd-ng daemon` (starts the resident monitor and internal scheduler)
  - `lmd-ng scan <path>` (manual on-demand scan)
  - `lmd-ng update` (manual signature update)
  - `lmd-ng service install` (automates OS-level background service creation and auto-startup across Windows, Linux, and macOS, ideally using `github.com/kardianos/service`)
  - `lmd-ng service uninstall` (removes the OS-level service)

### 6. Cross-Platform Compatibility
- Ensure all file path constructions use `filepath.Join()`.
- Abstract away any Linux-specific assumptions (e.g., hardcoded `/usr/local/maldetect` paths) into configurable variables.
- The resulting binary must be capable of running smoothly on Windows, macOS, and Linux.

### 7. Project Layout & Idiomatic Go
- Follow the Standard Go Project Layout.
- **`cmd/lmd-ng/`**: Contains the main application entry point.
- **`internal/`**: Contains private application code (e.g., `scanner`, `monitor`, `scheduler`) to prevent external importing.
- **`pkg/`**: Contains code that is safe for other projects to import (if any).
- Use idiomatic Go naming conventions (e.g., `ErrFileNotFound` instead of `FileNotFoundError`).

### 8. Observability & Logging
- **No `fmt.Println` or `log.Fatal` in core packages.**
- Use Go 1.21+'s native `log/slog` for structured, leveled logging (Debug, Info, Warn, Error).
- Ensure the logger can output to both `stdout` (for CLI tasks) and a log file (when running as a daemon/service).

### 9. Context & Concurrency
- Pass `context.Context` as the first parameter to any long-running or blocking function (e.g., scanning a directory, monitoring file systems).
- Ensure graceful shutdowns. The daemon must intercept OS signals (`SIGINT`, `SIGTERM`) and use context cancellation to safely stop the monitor, scheduler, and active scans before exiting.
- Manage goroutines carefully. Use `sync.WaitGroup` or `errgroup` to prevent goroutine leaks during concurrent scanning.

### 10. Error Handling
- Never suppress errors silently. 
- Use Go 1.13+ error wrapping (`fmt.Errorf("failed to scan file %s: %w", path, err)`).
- Create custom sentinel errors (e.g., `var ErrSignatureMatch = errors.New("malware signature matched")`) to allow the CLI/daemon to handle specific states cleanly.

### 11. Complete Code Generation (No Stubbing)
- **NEVER** use placeholders like `// ... rest of the code`, `// TODO`, or `// implement logic here` in your generated code.
- Always write complete, fully functional, and production-ready functions. If a file is too long for one response, stop and ask the user to let you continue.

### 12. Memory Efficiency & I/O Streaming
- **Never read entire files into memory** when calculating hashes or scanning for signatures (do not use `os.ReadFile` for target files).
- You MUST use `os.Open` combined with `io.Reader`, `bufio.Scanner`, or `io.Copy` to process files in chunks or streams.
- Keep memory allocations minimal during the `filepath.WalkDir` traversal.

### 13. Permission & Error Resiliency
- When walking directories or opening files, expect `os.ErrPermission` (Permission Denied) and file lock errors.
- The scanner must **never** crash or abort a full scan due to a single unreadable file. It should log the error at the `Warn` or `Debug` level and `continue` to the next file.

### 14. Dependency Discipline
- Rely on the Go Standard Library (`stdlib`) whenever possible.
- Before adding any new third-party dependency to `go.mod`, you must justify its use and ensure it is widely adopted, actively maintained, and completely free of CGO dependencies.

### 15. Build Artifacts & Integration Testing
- **Build Output:** All compilation steps (e.g., `go build`) must output the final executable(s) into a dedicated `dist/` directory at the project root (e.g., `dist/lmd-ng`).
- **Compiled Binary Testing:** Integration tests must validate the actual compiled binary located in the `dist/` directory, rather than just executing standard unit tests via `go test` on the source code. This ensures the final artifact functions correctly as a cohesive unit.
- **Test Implementation:** While `os/exec` is strictly forbidden in the core application logic (per Constraint #2), it is **required and permitted** within integration test files (e.g., `tests/integration_test.go`) solely to execute, pass arguments to, and assert the output of the `dist/lmd-ng` binary.

## 🛑 Interactive Clarification Protocol (CRITICAL)
The original LMD contains legacy bash logic, obscure regular expressions, and edge-case handling. 
**DO NOT GUESS OR HALLUCINATE LOGIC.** If you encounter a bash command, configuration variable intent, or architectural decision that is ambiguous or not fully understood, you **MUST** pause execution, state the ambiguity, and ask the human engineer for clarification before writing the code.