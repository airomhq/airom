// Package grid implements the distributed scanning coordinator and worker grid for mega-repos
// and multi-cluster scanning (ARCHITECTURE.md §16 reserved slot 5).
package grid

import (
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

// NodeRole indicates worker node specialization.
type NodeRole string

const (
	RoleCoordinator NodeRole = "coordinator"
	RoleScanner     NodeRole = "scanner"
	RoleAuditor     NodeRole = "auditor"
)

// WorkerNode represents a registered worker in the distributed scanning grid.
type WorkerNode struct {
	ID        string    `json:"id"`
	Host      string    `json:"host"`
	Role      NodeRole  `json:"role"`
	Capacity  int       `json:"capacity"` // concurrent files / partitions
	LastHeart time.Time `json:"lastHeart"`
	IsActive  bool      `json:"isActive"`
}

// JobStatus describes the lifecycle state of a grid partition job.
type JobStatus string

const (
	StatusPending    JobStatus = "pending"
	StatusInProgress JobStatus = "in_progress"
	StatusCompleted  JobStatus = "completed"
	StatusFailed     JobStatus = "failed"
)

// PartitionJob represents a shard of work dispatched to a worker node.
type PartitionJob struct {
	JobID       string           `json:"jobId"`
	PartitionID int              `json:"partitionId"`
	Target      string           `json:"target"`
	FilePaths   []string         `json:"filePaths"`
	WorkerID    string           `json:"workerId,omitempty"`
	Status      JobStatus        `json:"status"`
	StartTime   time.Time        `json:"startTime,omitempty"`
	EndTime     time.Time        `json:"endTime,omitempty"`
	Result      *airom.Inventory `json:"result,omitempty"`
	Error       string           `json:"error,omitempty"`
}

// GridScanSpec defines a full distributed scan request.
type GridScanSpec struct {
	JobID     string        `json:"jobId"`
	OrgID     string        `json:"orgId"`
	Targets   []string      `json:"targets"`
	ShardSize int           `json:"shardSize"` // files per partition
	Timeout   time.Duration `json:"timeout"`
}
