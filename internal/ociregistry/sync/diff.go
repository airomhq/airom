// Package sync implements air-gapped mirroring and differential rule updates for AIROM.
package sync

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
)

// RuleDelta captures the precise additions, updates, and deletions in a rule synchronization.
type RuleDelta struct {
	Added    map[string][]byte `json:"added"`
	Modified map[string][]byte `json:"modified"`
	Removed  []string          `json:"removed"`
}

// ComputeRuleDiff calculates changes between local rules and newly downloaded remote rules.
func ComputeRuleDiff(localRules, remoteRules map[string][]byte) RuleDelta {
	delta := RuleDelta{
		Added:    make(map[string][]byte),
		Modified: make(map[string][]byte),
		Removed:  make([]string, 0),
	}

	// Check additions and modifications
	for name, remoteContent := range remoteRules {
		localContent, exists := localRules[name]
		if !exists {
			delta.Added[name] = remoteContent
		} else if !bytes.Equal(localContent, remoteContent) {
			delta.Modified[name] = remoteContent
		}
	}

	// Check removals
	for name := range localRules {
		if _, exists := remoteRules[name]; !exists {
			delta.Removed = append(delta.Removed, name)
		}
	}

	sort.Strings(delta.Removed)
	return delta
}

// HasChanges returns true if the delta contains any added, modified, or removed rules.
func (d RuleDelta) HasChanges() bool {
	return len(d.Added) > 0 || len(d.Modified) > 0 || len(d.Removed) > 0
}

// HashRules computes a deterministic content hash of a rule set.
func HashRules(rules map[string][]byte) string {
	var keys []string
	for k := range rules {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write(rules[k])
	}
	return fmt.Sprintf("sha256:%s", hex.EncodeToString(h.Sum(nil)))
}
