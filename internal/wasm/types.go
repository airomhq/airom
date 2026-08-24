// Package wasm implements the pure-Go WebAssembly and sandboxed AST precision layer
// (ARCHITECTURE.md §16 reserved slot 4).
package wasm

import (
	"errors"
	"time"
)

var (
	// ErrTimeout is returned when WASM execution exceeds the configured deadline.
	ErrTimeout = errors.New("wasm: execution deadline exceeded")
	// ErrMemoryExceeded is returned when a module exceeds the sandboxed heap ceiling.
	ErrMemoryExceeded = errors.New("wasm: memory ceiling exceeded")
	// ErrGasExhausted is returned when instruction cycle budget is exhausted.
	ErrGasExhausted = errors.New("wasm: gas limit exhausted")
	// ErrInvalidBytecode is returned for corrupted or non-WASM inputs.
	ErrInvalidBytecode = errors.New("wasm: invalid module bytecode")
)

// Language identifies the target source language for AST parsing.
type Language string

const (
	LangPython     Language = "python"
	LangTypeScript Language = "typescript"
	LangJavaScript Language = "javascript"
	LangGo         Language = "go"
	LangRust       Language = "rust"
	LangJava       Language = "java"
	LangC          Language = "c"
	LangCPP        Language = "cpp"
)

// SandboxConfig specifies the safety boundaries for sandboxed AST execution.
type SandboxConfig struct {
	MaxMemoryBytes int64         // Default: 32 MiB
	TimeoutPerFile time.Duration // Default: 50 ms
	MaxGasCycles   int64         // Default: 10,000,000
	Concurrency    int           // Default: runtime.NumCPU()
}

// DefaultSandboxConfig returns the default production sandboxing limits.
func DefaultSandboxConfig() SandboxConfig {
	return SandboxConfig{
		MaxMemoryBytes: 32 * 1024 * 1024, // 32 MiB
		TimeoutPerFile: 50 * time.Millisecond,
		MaxGasCycles:   10_000_000,
		Concurrency:    16,
	}
}

// ExecutionStatus records the terminal outcome of a sandboxed execution.
type ExecutionStatus string

const (
	StatusSuccess        ExecutionStatus = "success"
	StatusTimeout        ExecutionStatus = "timeout"
	StatusMemoryExceeded ExecutionStatus = "memory_exceeded"
	StatusGasExhausted   ExecutionStatus = "gas_exhausted"
	StatusTrapped        ExecutionStatus = "trapped"
)

// ExecutionMetrics captures telemetry for a WASM invocation.
type ExecutionMetrics struct {
	Status           ExecutionStatus
	Duration         time.Duration
	AllocatedBytes   int64
	GasConsumed      int64
	NodesConstructed int
}

// ASTNode represents a single syntax node in the parsed AST.
type ASTNode struct {
	Type        string            `json:"type"`
	Text        string            `json:"text,omitempty"`
	StartLine   int               `json:"startLine"`
	EndLine     int               `json:"endLine"`
	StartColumn int               `json:"startColumn"`
	EndColumn   int               `json:"endColumn"`
	NamedFields map[string]string `json:"namedFields,omitempty"`
	Children    []*ASTNode        `json:"children,omitempty"`
}

// CallSite captures a function or method invocation with its argument bindings.
type CallSite struct {
	Function   string            `json:"function"`
	Receiver   string            `json:"receiver,omitempty"`
	Arguments  []string          `json:"arguments,omitempty"`
	Kwargs     map[string]string `json:"kwargs,omitempty"`
	LineNumber int               `json:"lineNumber"`
	SourceFile string            `json:"sourceFile,omitempty"`
}
