//go:build !windows

package service

import (
	"fmt"
	"os"

	kservice "github.com/kardianos/service"
)

var customLaunchdConfig = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Disabled</key>
	<false/>
	{{- if .EnvVars}}
	<key>EnvironmentVariables</key>
	<dict>
		{{- range $k, $v := .EnvVars}}
		<key>{{html $k}}</key>
		<string>{{html $v}}</string>
		{{- end}}
	</dict>
	{{- end}}
	<key>KeepAlive</key>
	<{{bool .KeepAlive}}/>
	<key>Label</key>
	<string>{{html .Name}}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{{html .Path}}</string>
		{{- if .Config.Arguments}}
		{{- range .Config.Arguments}}
		<string>{{html .}}</string>
		{{- end}}
	{{- end}}
	</array>
	{{- if .ChRoot}}
	<key>RootDirectory</key>
	<string>{{html .ChRoot}}</string>
	{{- end}}
	<key>RunAtLoad</key>
	<{{bool .RunAtLoad}}/>
	<key>SessionCreate</key>
	<{{bool .SessionCreate}}/>
	{{- if .StandardErrorPath}}
	<key>StandardErrorPath</key>
	<string>{{html .StandardErrorPath}}</string>
	{{- end}}
	{{- if .StandardOutPath}}
	<key>StandardOutPath</key>
	<string>{{html .StandardOutPath}}</string>
	{{- end}}
	{{- if .UserName}}
	<key>UserName</key>
	<string>{{html .UserName}}</string>
	{{- end}}
	{{- if .WorkingDirectory}}
	<key>WorkingDirectory</key>
	<string>{{html .WorkingDirectory}}</string>
	{{- end}}
	<key>SoftResourceLimits</key>
	<dict>
		<key>NumberOfFiles</key>
		<integer>10485760</integer>
	</dict>
	<key>HardResourceLimits</key>
	<dict>
		<key>NumberOfFiles</key>
		<integer>10485760</integer>
	</dict>
</dict>
</plist>`

// applyPlatformConfig applies Unix (Linux / macOS) specific settings to the
// kardianos/service Config.
//
// On POSIX systems:
//
//   - An empty UserName causes the service manager (systemd, launchd, OpenRC,
//     SysV) to run the process as root by default when installed system-wide.
//     We leave UserName empty rather than hardcoding "root" so that the
//     underlying service manager retains its natural, privileged default and
//     we avoid any confusion on non-Linux systems where the account name may
//     differ (e.g. macOS uses "root" too, but the intent is clearer this way).
//
//   - Restart=always (systemd) ensures the daemon is automatically restarted
//     if it crashes, matching the resilience expectations of a security tool.
//
//   - LimitNOFILE raises the open-file descriptor limit so that large directory
//     trees and concurrent scan workers don't hit the default system ulimit.
func applyPlatformConfig(cfg *kservice.Config) {
	// Leave UserName empty → service manager defaults to root for system-wide
	// services. Explicitly setting "root" is redundant and can cause issues
	// with non-systemd init systems (OpenRC, SysV) that handle User= differently.
	cfg.UserName = ""

	cfg.Option = kservice.KeyValue{
		"Restart":       "always",            // Restart the service automatically on any non-zero exit code (Systemd).
		"LimitNOFILE":   "infinity",          // Raise the open-file descriptor ceiling for large scans (Systemd).
		"LimitNPROC":    "infinity",          // Raise the open process limit for multi theread process (Systemd).
		"LimitMEMLOCK":  "infinity",          // Raise the memory lock limit for large scans (Systemd).
		"LimitCORE":     0,                   // Disable core dump (Systemd).
		"KeepAlive":     true,                // Restart the service automatically (macOS Launchd).
		"RunAtLoad":     true,                // Run the service at boot (macOS Launchd).
		"LaunchdConfig": customLaunchdConfig, // Inject the custom XML template with resource limits (macOS Launchd).
	}
}

// checkPrivilege verifies that the current process is running as root (UID 0).
// Service installation and removal require root privileges on Unix systems.
func checkPrivilege() error {
	if os.Getuid() != 0 {
		return fmt.Errorf("%w (current UID: %d)", ErrInsufficientPrivilege, os.Getuid())
	}

	return nil
}
