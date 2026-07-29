# LMD-NG — Agent Instructions

Rewrite Linux Malware Detect (LMD/Maldet) from Bash into a modern Golang application. Never guess legacy logic — ask when ambiguous.

---

## Workflow Rules

1. Read `TASKS.md` before every session to orient to current state.
2. Never rework items marked `[x]` in `TASKS.md` unless explicitly instructed.
3. Update `TASKS.md` immediately after completing a task.
4. Never attempt to write the entire codebase in a single response.

## Skills & Caveman Mode

- **GLOBAL:** All prompts processed as if `"Use caveman mode full"` is injected.
- Before ANY coding task, invoke and read: `using-superpowers`, `karpathy-guidelines`, `caveman`.
- Use `using-superpowers` to route to other relevant skills per task.

---

## Architecture

| Component | Role |
|---|---|
| **DBS** | Database Signature Server — TCP/TLS daemon holding signature engines in memory, streams scan requests from clients |
| **RTP** | Real-Time Protector — file system monitor client, streams changed files to DBS for matching, handles quarantine locally |
| **Scanner** | Core engine: `SignatureEngine` interface, `LMDSignatureScanner` (MD5+SHA256+RFXN+HEX), `ClamAVSignatureEngine`, `Walker`, `ScanCoordinator` |
| **Monitor** | Platform-specific FS events: FSEvents on macOS, fsnotify on Linux/Windows |
| **Scheduler** | Cron-based update + scan scheduling via `robfig/cron/v3` |
| **Updater** | Downloads LMD signature packs (.tar.gz) and ClamAV CVD databases; version checking, atomic writes |
| **Quarantine** | AES-256-GCM encryption, POSIX metadata capture/restore, short-ID lookup |
| **Protocol** | Custom binary wire protocol: `[1-byte type][4-byte length][payload]` over TLS |
| **Notifier** | `Notifier` interface + MultiNotifier; Email (SMTP) and Telegram (Bot API) |
| **Service** | OS service install/uninstall via `kardianos/service` — `dbs` and `rtp` as separate services |

## Signature Types

| Format | Source |
|---|---|
| MD5/SHA256 hashes | LMD native |
| HEX (hex-string) signatures | LMD native |
| RFXN (NDB hex-pattern) | LMD native via `pkg/clamav` NDB parser |
| ClamAV `.cvd`/`.cld`/`.ndb`/`.mdb`/`.hdb` | ClamAV |

## CLI

```
lmd-ng [--config <path>]
  daemon                  # Start DBS + RTP in single process
    dbs                   # Start only DBS server
    rtp                   # Start only RTP client
  scan <path>             # On-demand scan (DBS-first, local fallback)
  update                  # Manual signature update
  upgrade [--force]       # Self-upgrade binary from GitHub releases
  status                  # Display DBS status, signature counts, versions, quarantine, RTP, scheduler
  service
    install [dbs|rtp]     # Install as OS service
    uninstall [dbs|rtp]   # Remove OS service
    start/stop/restart    # [dbs|rtp]
  quarantine
    list                  # List quarantined files
    add <file>            # Manually quarantine
    restore <id|path>     # Restore quarantined file
    remove <id|path>      # Permanently delete (requires --force)
  version
```

---

## Critical Constraints

### Build — CGO + Zig
- `CGO_ENABLED=1` always. C/C++ via `hack/zcc.sh` only — never raw `gcc`/`clang`.

### Native Implementation (No os/exec in core)
- File traversal: `filepath.WalkDir`, not `find`.
- File monitoring: `fsnotify` (Linux/Windows), `fsnotify/fsevents` (macOS FSE via CGO).
- Signature matching: `crypto` for MD5/SHA256 hashes, `pkg/clamav` for HEX/NDB patterns.

### ClamAV
- Fully implemented: `ClamAVSignatureEngine`, pure-Go CVD/CLD/HDB/MDB/NDB parsers in `pkg/clamav/`.
- Toggled via `clamav_enabled: false` in config. Off by default — enable when needed.

### Configuration
- YAML via `spf13/viper`. Legacy `conf.maldet` vars → `config.yaml`. Search: `--config` flag → binary dir → `/etc/lmd-ng/` → `/usr/local/etc/lmd-ng/` → `/usr/local/lmd-ng/`.

### CLI & Scheduler
- `spf13/cobra` CLI, `robfig/cron/v3` scheduler. No OS cron.

### Cross-Platform
- `filepath.Join()` everywhere. No hardcoded paths.
- Service: `kardianos/service` (systemd/launchd/SCM).

### Logging
- `log/slog` only. No `fmt.Println` or `log.Fatal` in core packages.
- `lumberjack` for rotation. Rotation params bound to config.

### Context & Concurrency
- `context.Context` as first param for long-running functions.
- Graceful shutdown via OS signals + context cancellation.
- `sync.Mutex`/`sync.RWMutex` on all shared state.
- `errgroup` / `sync.WaitGroup` — no goroutine leaks.

### Permission Resiliency
- Expect `os.ErrPermission` during walks. Log at Warn/Debug, never crash or abort scan.

### Streaming I/O
- Never `os.ReadFile` on target files. Use `os.Open` + `io.Reader` / `bufio.Scanner` for chunked processing. Keep memory minimal during walks.

### Error Handling
- Wrap with `fmt.Errorf %w`. Custom sentinel errors. Never suppress silently.

### No Stubbing
- Every function must be complete and production-ready. No `// TODO`, `// rest of code`, or placeholder logic.

### Dependencies
- Stdlib first. Third-party deps must be justified, widely adopted, CGO-free.

### Build Artifacts
- Output to `dist/` via Makefile. Integration tests validate compiled binary.

---

## Non-Negotiable Rules

1. **No stubs.** Every file complete, production-ready.
2. **No guessing** on legacy bash logic, regex, or ambiguous architecture. Pause, state ambiguity, ask.
3. **Never auto-run pipeline.** Provide exact command + expected output, wait for user.
4. **No system temp dirs.** Runtime files in configured paths only.

---

## Directory Tree

```
lmd-ng/
├── cmd/lmd-ng/           # Entry: cobra CLI (main, daemon, scan, update, upgrade, status, service, quarantine, version)
├── internal/
│   ├── config/           # Viper YAML config, path resolution, hot-reload (SIGHUP)
│   ├── dbs/              # Database Signature Server (TCP/TLS, Unix socket)
│   ├── rtp/              # Real-Time Protector (FS monitor client)
│   ├── scanner/          # Signature engines, walker, scan coordinator
│   ├── monitor/          # Platform-specific FS events (darwin/other)
│   ├── scheduler/        # Cron-based update + scan scheduling
│   ├── updater/          # LMD + ClamAV signature download
│   ├── upgrade/          # Binary self-upgrade (GitHub Releases API, platform-specific swap)
│   ├── quarantine/       # AES-256-GCM quarantine, metadata capture
│   ├── protocol/         # Binary wire protocol + TLS
│   ├── notifier/         # Email + Telegram notifications
│   ├── service/          # OS service management (kardianos/service)
│   ├── log/              # slog wrapper + lumberjack rotation
│   ├── util/             # Helpers (size parsing, internet check)
│   └── syslimits/        # ulimit management (Unix)
├── pkg/clamav/           # Public ClamAV DB parser (pure Go)
├── docs/
│   ├── ARCHITECTURE.md   # Module map, component internals, data flows
│   └── WORKFLOWS.md      # Pipeline flow diagrams, operational sequences
├── hack/zcc.sh           # Zig C compiler wrapper
├── dist/                 # Build output
├── config.yaml.example   # Full annotated config template
├── Makefile              # Build targets (build, release, docker-build, clean)
├── .goreleaser.yml       # Cross-platform release config
└── Dockerfile            # Multi-stage Go+Zig build
```

---

## References

| File | Purpose |
|---|---|
| `config.yaml.example` | Full annotated config reference |
| `docs/ARCHITECTURE.md` | Module map, component internals, data flows |
| `docs/WORKFLOWS.md` | Pipeline flow diagrams, operational sequences |
| `TASKS.md` | Current project state — read before every session |
| `Makefile` | Build targets and cross-compilation |
| `.goreleaser.yml` | Release configuration (darwin/linux/windows × 386/amd64/arm64) |
| `hack/zcc.sh` | Zig CC wrapper — source of truth for build flags + security hardening |
| `internal/scanner/` | Core scanning logic — walker, signature engines, coordinator |
| `internal/dbs/` | DBS server implementation |
| `internal/rtp/` | RTP client implementation |
| `pkg/clamav/` | ClamAV database parser (CVD/CLD/HDB/MDB/NDB) |
