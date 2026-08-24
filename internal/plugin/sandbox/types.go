// Package sandbox implements zero-trust sandboxing and capability isolation for out-of-process plugins
// (ARCHITECTURE.md §16 reserved slot 5).
package sandbox

import (
	"errors"
)

var (
	// ErrAccessDenied is returned when a plugin violates its capability sandbox.
	ErrAccessDenied = errors.New("sandbox: operation denied by security policy")
	// ErrIllegalPath is returned when a plugin attempts to access paths outside its sandbox root.
	ErrIllegalPath = errors.New("sandbox: path escape detected")
)

// IsolationLevel defines the enforcement rigor applied to a plugin.
type IsolationLevel string

const (
	LevelStrict     IsolationLevel = "strict"     // No network, read-only FS, restricted syscalls
	LevelStandard   IsolationLevel = "standard"   // Restricted network, read-only repo FS
	LevelPermissive IsolationLevel = "permissive" // Workspace write access
)

// SecurityPolicy defines the concrete boundary controls for a plugin execution.
type SecurityPolicy struct {
	Level                IsolationLevel `json:"level"`
	AllowedReadPaths     []string       `json:"allowedReadPaths"`
	AllowedWritePaths    []string       `json:"allowedWritePaths,omitempty"`
	AllowNetworkOutbound bool           `json:"allowNetworkOutbound"`
	MaxCPUTimeMillis     int64          `json:"maxCpuTimeMillis"`
	MaxMemoryBytes       int64          `json:"maxMemoryBytes"`
	DisallowedSyscalls   []string       `json:"disallowedSyscalls,omitempty"`
}

// DefaultStrictPolicy returns the zero-trust production baseline.
func DefaultStrictPolicy(workspaceRoot string) SecurityPolicy {
	return SecurityPolicy{
		Level:                LevelStrict,
		AllowedReadPaths:     []string{workspaceRoot},
		AllowedWritePaths:    nil,
		AllowNetworkOutbound: false,
		MaxCPUTimeMillis:     5000,
		MaxMemoryBytes:       256 * 1024 * 1024, // 256 MiB
		DisallowedSyscalls:   []string{"ptrace", "reboot", "mount", "setuid", "setgid", "chroot"},
	}
}
