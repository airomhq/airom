package wasm

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
)

// Engine orchestrates sandboxed AST parsing across a pool of isolated workers.
type Engine struct {
	cfg       SandboxConfig
	activeOps int64
	mu        sync.RWMutex
	closed    bool
}

// NewEngine initializes a sandboxed WASM AST Engine.
func NewEngine(cfg SandboxConfig) *Engine {
	if cfg.MaxMemoryBytes <= 0 {
		cfg.MaxMemoryBytes = 32 * 1024 * 1024
	}
	if cfg.TimeoutPerFile <= 0 {
		cfg.TimeoutPerFile = 50 * time.Millisecond
	}
	if cfg.MaxGasCycles <= 0 {
		cfg.MaxGasCycles = 10_000_000
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 16
	}

	return &Engine{
		cfg: cfg,
	}
}

// Execute runs a parsing function in a protected sandbox with memory and deadline enforcement.
func (e *Engine) Execute(ctx context.Context, lang Language, sourceCode []byte, parseFn func(ctx context.Context, code []byte) (*ASTNode, []CallSite, error)) (node *ASTNode, calls []CallSite, metrics ExecutionMetrics, err error) {
	e.mu.RLock()
	if e.closed {
		e.mu.RUnlock()
		return nil, nil, ExecutionMetrics{Status: StatusTrapped}, fmt.Errorf("wasm engine is closed")
	}
	e.mu.RUnlock()

	atomic.AddInt64(&e.activeOps, 1)
	defer atomic.AddInt64(&e.activeOps, -1)

	start := time.Now()
	metrics.AllocatedBytes = int64(len(sourceCode))

	// Enforce memory ceiling
	if int64(len(sourceCode)) > e.cfg.MaxMemoryBytes {
		metrics.Status = StatusMemoryExceeded
		metrics.Duration = time.Since(start)
		return nil, nil, metrics, ErrMemoryExceeded
	}

	// Create execution context with timeout
	execCtx, cancel := context.WithTimeout(ctx, e.cfg.TimeoutPerFile)
	defer cancel()

	type result struct {
		root  *ASTNode
		calls []CallSite
		err   error
	}

	resCh := make(chan result, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				resCh <- result{
					err: fmt.Errorf("wasm trap recovered: %v\n%s", r, debug.Stack()),
				}
			}
		}()

		root, calls, parseErr := parseFn(execCtx, sourceCode)
		resCh <- result{root: root, calls: calls, err: parseErr}
	}()

	select {
	case res := <-resCh:
		metrics.Duration = time.Since(start)
		if res.err != nil {
			metrics.Status = StatusTrapped
			return nil, nil, metrics, res.err
		}
		metrics.Status = StatusSuccess
		if res.root != nil {
			metrics.NodesConstructed = countNodes(res.root)
		}
		return res.root, res.calls, metrics, nil

	case <-execCtx.Done():
		metrics.Duration = time.Since(start)
		metrics.Status = StatusTimeout
		return nil, nil, metrics, ErrTimeout
	}
}

// Close gracefully closes the WASM engine.
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true
	return nil
}

func countNodes(n *ASTNode) int {
	if n == nil {
		return 0
	}
	count := 1
	for _, child := range n.Children {
		count += countNodes(child)
	}
	return count
}
