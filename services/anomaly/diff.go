// Package anomaly provides differential analysis and tripwire detection for AI components.
package anomaly

import (
	"github.com/airomhq/airom/pkg/airom"
)

// ComputeDiff compares base and head inventories to identify added, removed, and modified components.
func ComputeDiff(base *airom.Inventory, head *airom.Inventory) DiffReport {
	report := DiffReport{
		Added:    []airom.Component{},
		Removed:  []airom.Component{},
		Modified: []ComponentDelta{},
	}

	if base != nil && base.Source.Git != nil {
		report.BaseCommit = base.Source.Git.Commit
	}
	if head != nil && head.Source.Git != nil {
		report.HeadCommit = head.Source.Git.Commit
	}

	baseMap := make(map[string]airom.Component)
	if base != nil {
		for _, c := range base.Components {
			key := c.PURL
			if key == "" {
				key = string(c.ID)
			}
			baseMap[key] = c
		}
	}

	headMap := make(map[string]airom.Component)
	if head != nil {
		for _, c := range head.Components {
			key := c.PURL
			if key == "" {
				key = string(c.ID)
			}
			headMap[key] = c

			if baseC, ok := baseMap[key]; ok {
				delta := ComponentDelta{
					ComponentID: string(c.ID),
					PURL:        c.PURL,
					ParamDeltas: make(map[string]ParamDelta),
				}
				isModified := false

				ov, _ := baseC.Version.Value()
				nv, _ := c.Version.Value()
				if ov != nv {
					delta.OldVersion = ov
					delta.NewVersion = nv
					isModified = true
				}

				op, _ := baseC.Provider.Value()
				np, _ := c.Provider.Value()
				if op != np {
					delta.OldProvider = op
					delta.NewProvider = np
					isModified = true
				}

				baseParams := getParams(baseC)
				headParams := getParams(c)

				for k, hv := range headParams {
					bv, exists := baseParams[k]
					if !exists || bv != hv {
						delta.ParamDeltas[k] = ParamDelta{OldValue: bv, NewValue: hv}
						isModified = true
					}
				}
				for k, bv := range baseParams {
					if _, exists := headParams[k]; !exists {
						delta.ParamDeltas[k] = ParamDelta{OldValue: bv, NewValue: ""}
						isModified = true
					}
				}

				if isModified {
					report.Modified = append(report.Modified, delta)
				}
			} else {
				report.Added = append(report.Added, c)
			}
		}
	}

	if base != nil {
		for _, c := range base.Components {
			key := c.PURL
			if key == "" {
				key = string(c.ID)
			}
			if _, ok := headMap[key]; !ok {
				report.Removed = append(report.Removed, c)
			}
		}
	}

	return report
}

func getParams(c airom.Component) map[string]string {
	params := make(map[string]string)
	if c.Model != nil {
		for _, p := range c.Model.GenerationParams {
			params[p.Name] = p.Value
		}
	}
	return params
}
