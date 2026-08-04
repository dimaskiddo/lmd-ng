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
		<integer>8192000</integer>
	</dict>
	<key>HardResourceLimits</key>
	<dict>
		<key>NumberOfFiles</key>
		<integer>8192000</integer>
	</dict>
</dict>
</plist>`

// applyPlatformConfig applies Unix-specific settings to the service Config.
func applyPlatformConfig(cfg *kservice.Config) {
	cfg.UserName = ""

	cfg.Option = kservice.KeyValue{
		"Restart":       "always",
		"LimitNOFILE":   "infinity",
		"LimitNPROC":    "infinity",
		"LimitMEMLOCK":  "infinity",
		"LimitCORE":     0,
		"KeepAlive":     true,
		"RunAtLoad":     true,
		"LaunchdConfig": customLaunchdConfig,
	}
}

// checkPrivilege verifies the process is running as root (UID 0).
func checkPrivilege() error {
	if os.Getuid() != 0 {
		return fmt.Errorf("%w (current UID: %d)", ErrInsufficientPrivilege, os.Getuid())
	}

	return nil
}
