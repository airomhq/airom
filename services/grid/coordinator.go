package grid

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

// Coordinator orchestrates distributed scanning partitions across worker nodes.
type Coordinator struct {
	workers    map[string]*WorkerNode
	partitions map[string][]*PartitionJob
	mu         sync.RWMutex
}

// NewCoordinator initializes a distributed grid coordinator.
func NewCoordinator() *Coordinator {
	return &Coordinator{
		workers:    make(map[string]*WorkerNode),
		partitions: make(map[string][]*PartitionJob),
	}
}

// RegisterWorker registers a worker node in the active pool.
func (c *Coordinator) RegisterWorker(w *WorkerNode) {
	c.mu.Lock()
	defer c.mu.Unlock()
	w.LastHeart = time.Now().UTC()
	w.IsActive = true
	c.workers[w.ID] = w
}

// PlanPartitions divides a list of files/targets into discrete partition jobs.
func (c *Coordinator) PlanPartitions(spec GridScanSpec, allFiles []string) []*PartitionJob {
	c.mu.Lock()
	defer c.mu.Unlock()

	shardSize := spec.ShardSize
	if shardSize <= 0 {
		shardSize = 500
	}

	var jobs []*PartitionJob
	partID := 0

	for i := 0; i < len(allFiles); i += shardSize {
		end := i + shardSize
		if end > len(allFiles) {
			end = len(allFiles)
		}

		job := &PartitionJob{
			JobID:       spec.JobID,
			PartitionID: partID,
			FilePaths:   allFiles[i:end],
			Status:      StatusPending,
		}
		jobs = append(jobs, job)
		partID++
	}

	c.partitions[spec.JobID] = jobs
	return jobs
}

// SubmitPartitionResult submits the completed partial inventory from a worker node.
func (c *Coordinator) SubmitPartitionResult(jobID string, partitionID int, result *airom.Inventory) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	jobs, ok := c.partitions[jobID]
	if !ok {
		return fmt.Errorf("job not found: %s", jobID)
	}

	if partitionID < 0 || partitionID >= len(jobs) {
		return fmt.Errorf("invalid partition ID: %d", partitionID)
	}

	job := jobs[partitionID]
	job.Status = StatusCompleted
	job.EndTime = time.Now().UTC()
	job.Result = result

	return nil
}

// AggregateMasterInventory merges all completed partitions into a single deduplicated Inventory.
func (c *Coordinator) AggregateMasterInventory(ctx context.Context, jobID string) (*airom.Inventory, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	jobs, ok := c.partitions[jobID]
	if !ok {
		return nil, fmt.Errorf("job not found: %s", jobID)
	}

	compMap := make(map[airom.ID]airom.Component)
	relMap := make(map[string]airom.Relationship)

	for _, job := range jobs {
		if job.Status != StatusCompleted {
			return nil, fmt.Errorf("partition %d is not completed (status=%s)", job.PartitionID, job.Status)
		}
		if job.Result == nil {
			continue
		}

		for _, comp := range job.Result.Components {
			if existing, exists := compMap[comp.ID]; exists {
				// Deduplicate and merge occurrences
				if len(comp.Evidence.Occurrences) > 0 {
					existing.Evidence.Occurrences = append(existing.Evidence.Occurrences, comp.Evidence.Occurrences...)
					compMap[comp.ID] = existing
				}
			} else {
				compMap[comp.ID] = comp
			}
		}

		for _, rel := range job.Result.Relationships {
			key := fmt.Sprintf("%s:%s:%s", rel.From, rel.To, rel.Type)
			relMap[key] = rel
		}
	}

	var finalComponents []airom.Component
	for _, comp := range compMap {
		finalComponents = append(finalComponents, comp)
	}
	sort.Slice(finalComponents, func(i, j int) bool {
		return finalComponents[i].ID < finalComponents[j].ID
	})

	var finalRelationships []airom.Relationship
	for _, rel := range relMap {
		finalRelationships = append(finalRelationships, rel)
	}
	sort.Slice(finalRelationships, func(i, j int) bool {
		if finalRelationships[i].From != finalRelationships[j].From {
			return finalRelationships[i].From < finalRelationships[j].From
		}
		return finalRelationships[i].To < finalRelationships[j].To
	})

	masterInv := &airom.Inventory{
		SchemaVersion: "1",
		Timestamp:     time.Now().UTC(),
		Tool: airom.ToolInfo{
			Name:    "airom-grid",
			Version: "1.0.0",
		},
		Source: airom.SourceInfo{
			Kind:   "grid",
			Target: fmt.Sprintf("grid-job-%s", jobID),
		},
		Components:    finalComponents,
		Relationships: finalRelationships,
	}

	return masterInv, nil
}
