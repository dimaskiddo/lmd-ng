# LMD-NG — Agent Instructions

Rewrite Linux Malware Detect (LMD/Maldet) from Bash into a modern Golang application. Never guess legacy logic — ask when ambiguous.

---

## Workflow Rules

1. Read `TASKS.md` and project docs before every session to orient to current state.
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
| **ATP** | Anti-Tamper Protection — locks critical files (binary, config, signatures, TLS certs, quarantine) against modification/deletion. Linux: chattr +i + fanotify FAN_DENY; macOS: chflags SF_IMMUTABLE; Windows: DACL + exclusive handles |
| **DBS** | Database Signature Server — TCP/TLS daemon holding signature engines in memory, streams scan requests from clients |
| **RTP** | Real-Time Protector — file system monitor client, streams changed files to DBS for matching, handles quarantine locally |
| **Scanner** | Core engine: `SignatureEngine` interface + optional `HeuristicScanner`, two-pass orchestrator `ScanDataWithEngines` (Pass 1: hash-only `Scan`; Pass 2: heuristic `ScanHeuristics`). `LMDSignatureScanner` (LMD native MD5/SHA256/HEX + RFXN HDB/MDB/NDB), `ClamAVSignatureEngine` (ClamAV CVD HDB/MDB/NDB), `Walker`, `ScanCoordinator` |
| **Monitor** | Platform-specific FS events: FSEvents on macOS, fsnotify on Linux/Windows |
| **Scheduler** | Cron-based update + scan scheduling via `robfig/cron/v3` |
| **Updater** | Downloads LMD signature packs (.tar.gz) and ClamAV CVD databases; version checking, atomic writes |
| **Quarantine** | AES-256-GCM encryption, POSIX metadata capture/restore, short-ID lookup |
| **Protocol** | Custom binary wire protocol: `[1-byte type][4-byte length][payload]` over TLS |
| **Notifier** | `Notifier` interface + MultiNotifier; Email (SMTP), Telegram (Bot API), Discord (webhook), Slack (incoming webhook) |
| **Service** | OS service install/uninstall via `kardianos/service` — `atp`, `dbs`, and `rtp` as separate services with startup dependencies (DBS requires ATP; RTP requires ATP+DBS), verified via `StatusService` when a component starts as a service (`--service`) |
| **Upgrade** | Binary self-upgrade — GitHub Releases API, platform-specific swap (Unix: atomic rename; Windows: batch trampoline) |
| **Config** | Viper YAML config, path resolution, SIGHUP hot-reload |
| **Log** | `log/slog` + lumberjack rotation, dual stdout+file output |
| **Syslimits** | ulimit management (Unix) |
| **Util** | Helpers (size parsing, symlink resolution, internet check, temp path detection) |

## Signature Types

Scan runs in two passes. Pass 1 (hash-based, deterministic) runs all engines' `Scan()`. Pass 2 (heuristic, FP-prone) runs `ScanHeuristics()` on engines implementing `HeuristicScanner`, gated by `enabled_heuristics` config.

| Signature Type | Engine | Source | Pass | Gated By |
|---|---|---|---|---|
| `MD5` | LMDSignatureScanner | LMD native `dat/md5*.dat` | 1 (Scan) | — |
| `SHA256` | LMDSignatureScanner | LMD native `dat/sha256*.dat` | 1 (Scan) | — |
| `RFXN-MD5/SHA1/SHA256` | LMDSignatureScanner | RFXN `sigs/rfxn/` via `pkg/clamav` HDB | 1 (Scan) | — |
| `RFXN-MDB` | LMDSignatureScanner | RFXN `sigs/rfxn/` via `pkg/clamav` MDB | 1 (Scan) | — |
| `ClamAV-MD5/SHA1/SHA256` | ClamAVSignatureEngine | ClamAV CVD via `pkg/clamav` HDB | 1 (Scan) | `clamav_enabled` |
| `ClamAV-MDB` | ClamAVSignatureEngine | ClamAV CVD via `pkg/clamav` MDB | 1 (Scan) | `clamav_enabled` |
| `HEX` | LMDSignatureScanner | LMD native `dat/hex*.dat` | 2 (ScanHeuristics) | `enabled_heuristics: ["hex"]` |
| `RFXN-NDB` | LMDSignatureScanner | RFXN `sigs/rfxn/` via `pkg/clamav` NDB | 2 (ScanHeuristics) | `enabled_heuristics: ["ndb"]` |
| `ClamAV-NDB` | ClamAVSignatureEngine | ClamAV CVD via `pkg/clamav` NDB | 2 (ScanHeuristics) | `clamav_enabled` + `enabled_heuristics: ["ndb"]` |

## CLI

```
lmd-ng [--config <path>]
  daemon                  # Start ATP + DBS + RTP in single process (ATP starts first)
    atp [--log-file P]    # Start only Anti-Tamper Protection daemon (own log)
    dbs [--log-file P]    # Start only DBS server (own log)
    rtp [--log-file P]    # Start only RTP client (own log)
  scan <path> [--log-file P]  # On-demand scan (DBS-first, local fallback)
  update                  # Manual signature update
  upgrade [--force]       # Self-upgrade binary from GitHub releases
  status                  # Display DBS status, signature counts, versions, quarantine, RTP, scheduler
  service
    install [atp|dbs|rtp] [--log-file P]  # Install as OS service
    uninstall [atp|dbs|rtp]   # Remove OS service
    start/stop/restart    # [atp|dbs|rtp]
  quarantine
    list                  # List quarantined files
    add <file>            # Manually quarantine
    restore <id|path> [--to P]  # Restore to original path, or export to custom path (--to) keeping evidence
    remove <id|path>      # Permanently delete (requires --force)
  version
```

Each daemon component has its own log file: `daemon atp/dbs/rtp --log-file` (default `<logs_dir>/lmd-ng-<component>.log`). `scan` defaults to the config `logging.filepath` and only writes a separate file with `--log-file`. `service install` bakes the config path, the component's log file, and the internal `--service` flag into the service definition. When run as a service, startup verifies dependencies (DBS needs ATP, RTP needs ATP+DBS) and fails otherwise.

---

## Critical Constraints

### Build — CGO + Zig
- `CGO_ENABLED=1` always. C/C++ via `hack/zcc.sh` only — never raw `gcc`/`clang`.

### Native Implementation (No os/exec in core)
- File traversal: `filepath.WalkDir`, not `find`.
- File monitoring: `fsnotify` (Linux/Windows), `fsnotify/fsevents` (macOS FSE via CGO).
- Signature matching: `crypto` for MD5/SHA256 hashes; `internal/scanner/hex.go` for LMD native HEX patterns; `pkg/clamav` for RFXN/ClamAV HDB, MDB, and NDB signatures.

### ClamAV
- Fully implemented: `ClamAVSignatureEngine`, pure-Go CVD/CLD/HDB/MDB/NDB parsers in `pkg/clamav/`.
- Toggled via `clamav_enabled: false` in config. Off by default — enable when needed.
- ClamAV NDB body-pattern matching is additionally gated by `enabled_heuristics: ["ndb"]` — even with `clamav_enabled: true`, NDB requires explicit heuristic enablement.

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
- Per-component log files: `InitLoggerWithPath` splits ATP/DBS/RTP/scan logs; every logger shares the same rotation config (`max_size`, `max_backups`, `max_age`, `compress`) from `config.yaml`, only the filename differs.

### Context & Concurrency
- `context.Context` as first param for long-running functions. Scan methods check `ctx.Done()` intra-pass (hash computation, PE section parsing, heuristic scanning).
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
5. **Minimal comments.** Comments describe WHY, never WHAT or HOW.
   - No step-by-step process descriptions, algorithm blueprints, or protection-mechanism detail.
   - No inline comments restating code (`// increment counter` on `counter++`).
   - No section separator comments (`// --- Section ---`).
   - Go doc comments on exported symbols: one line for simple functions, max three for complex ones.
   - If a comment would help a malware author bypass a detection mechanism, delete it.

---

## Directory Tree

```
lmd-ng/
├── cmd/lmd-ng/           # Entry: cobra CLI (main, daemon, scan, update, upgrade, status, service, quarantine, version)
├── internal/
│   ├── config/           # Viper YAML config, path resolution, hot-reload (SIGHUP)
│   ├── atp/              # Anti-Tamper Protection (Linux chattr+fanotify, macOS chflags, Windows DACL)
│   ├── dbs/              # Database Signature Server (TCP/TLS, Unix socket, connection pool, client)
│   ├── rtp/              # Real-Time Protector (FS monitor client)
│   ├── scanner/          # Signature engines, walker, scan coordinator
│   ├── monitor/          # Platform-specific FS events (darwin/other)
│   ├── scheduler/        # Cron-based update + scan scheduling
│   ├── updater/          # LMD + ClamAV signature download
│   ├── upgrade/          # Binary self-upgrade (GitHub Releases API, platform-specific swap)
│   ├── quarantine/       # AES-256-GCM quarantine, metadata capture
│   ├── protocol/         # Binary wire protocol + TLS
│   ├── notifier/         # Email, Telegram, Discord, and Slack notifications
│   ├── service/          # OS service management (kardianos/service)
│   ├── log/              # slog wrapper + lumberjack rotation
│   ├── util/             # Helpers (size parsing, symlink resolution, internet check)
│   └── syslimits/        # ulimit management (Unix)
├── pkg/clamav/           # Public ClamAV DB parser (pure Go)
├── docs/
│   ├── ARCHITECTURE.md   # Module map, component internals, data flows
│   └── WORKFLOWS.md      # Pipeline flow diagrams, operational sequences
├── hack/zcc.sh           # Zig C compiler wrapper
├── hack/zcxx.sh          # Symlink to zcc.sh (C++ wrapper)
├── dist/                 # Build output (generated, not in repo)
├── config.yaml.example   # Full annotated config template
├── Makefile              # Build targets (build, release, docker-build, clean)
├── .goreleaser.yml       # Cross-platform release config
├── Dockerfile            # Multi-stage Go+Zig build
├── AGENTS.md             # Agent instructions (also via symlinks CLAUDE.md, GEMINI.md)
├── README.md             # Project readme
├── LICENSE               # License file
├── go.mod                # Go module definition
├── go.sum                # Dependency checksums
├── .gitignore            # Git ignore rules
├── .dockerignore         # Docker ignore (symlink → .gitignore)
└── vendor/               # Go vendored dependencies
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
