// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package taskcoord

import (
	"fmt"
	"sort"
)

// DependencyMode defines how the edges in one dependency group are
// satisfied. Multiple groups on one Task are conjunctive.
type DependencyMode string

const (
	DependencyAll    DependencyMode = "ALL"
	DependencyAny    DependencyMode = "ANY"
	DependencyQuorum DependencyMode = "QUORUM"
)

// Dependency is a typed wait-for edge. Delegation provenance is deliberately
// represented by DelegationRecord instead of this graph.
type Dependency struct {
	Schema       string         `json:"schema"`
	DependencyID string         `json:"dependency_id"`
	FromTaskID   string         `json:"from_task_id"`
	ToTaskID     string         `json:"to_task_id"`
	GroupID      string         `json:"group_id"`
	Mode         DependencyMode `json:"mode"`
	Quorum       uint32         `json:"quorum,omitempty"`
	Active       bool           `json:"active"`
	Satisfied    bool           `json:"satisfied"`
}

// Validate checks one wait-for edge. Self-dependencies are valid input so
// they can be identified explicitly as deadlocks rather than hidden.
func (d Dependency) Validate() error {
	if d.Schema != DependencySchemaV1 {
		return fmt.Errorf("task coordination: invalid dependency: unsupported schema")
	}
	for field, value := range map[string]string{
		"dependency_id": d.DependencyID,
		"from_task_id":  d.FromTaskID,
		"to_task_id":    d.ToTaskID,
		"group_id":      d.GroupID,
	} {
		if err := validateID(field, value); err != nil {
			return fmt.Errorf("task coordination: invalid dependency: %v", err)
		}
	}
	switch d.Mode {
	case DependencyAll, DependencyAny:
		if d.Quorum != 0 {
			return fmt.Errorf("task coordination: invalid dependency: quorum is only valid for QUORUM")
		}
	case DependencyQuorum:
		if d.Quorum == 0 {
			return fmt.Errorf("task coordination: invalid dependency: positive quorum required")
		}
	default:
		return fmt.Errorf("task coordination: invalid dependency: unsupported mode")
	}
	return nil
}

// TaskLiveness is the minimum runtime projection needed for conservative
// deadlock detection. ExternalEscape covers timers, signals, manual
// escalation, and other progress sources outside the wait-for graph.
type TaskLiveness struct {
	TaskID         string
	Terminal       bool
	Runnable       bool
	ExternalEscape bool
}

type dependencyGroup struct {
	mode   DependencyMode
	quorum uint32
	edges  []Dependency
}

// DetectDeadlockedTasks returns Tasks that provably cannot progress within
// the supplied graph. Unknown dependency targets are treated as possible
// external progress, making this detector conservative rather than producing
// a false deadlock from an incomplete graph.
func DetectDeadlockedTasks(tasks []TaskLiveness, dependencies []Dependency) ([]string, error) {
	taskByID := make(map[string]TaskLiveness, len(tasks))
	for _, task := range tasks {
		if err := validateID("task_id", task.TaskID); err != nil {
			return nil, err
		}
		if _, exists := taskByID[task.TaskID]; exists {
			return nil, fmt.Errorf("duplicate task_id %s", task.TaskID)
		}
		taskByID[task.TaskID] = task
	}

	groups := make(map[string]map[string]*dependencyGroup)
	dependencyIDs := make(map[string]struct{}, len(dependencies))
	for _, dependency := range dependencies {
		if err := dependency.Validate(); err != nil {
			return nil, err
		}
		if _, exists := dependencyIDs[dependency.DependencyID]; exists {
			return nil, fmt.Errorf("duplicate dependency_id %s", dependency.DependencyID)
		}
		dependencyIDs[dependency.DependencyID] = struct{}{}
		if !dependency.Active {
			continue
		}
		byGroup := groups[dependency.FromTaskID]
		if byGroup == nil {
			byGroup = make(map[string]*dependencyGroup)
			groups[dependency.FromTaskID] = byGroup
		}
		group := byGroup[dependency.GroupID]
		if group == nil {
			group = &dependencyGroup{mode: dependency.Mode, quorum: dependency.Quorum}
			byGroup[dependency.GroupID] = group
		} else if group.mode != dependency.Mode || group.quorum != dependency.Quorum {
			return nil, fmt.Errorf("inconsistent dependency group %s", dependency.GroupID)
		}
		group.edges = append(group.edges, dependency)
	}
	for _, byGroup := range groups {
		for groupID, group := range byGroup {
			targets := make(map[string]struct{}, len(group.edges))
			for _, edge := range group.edges {
				if _, exists := targets[edge.ToTaskID]; exists {
					return nil, fmt.Errorf("duplicate target in dependency group %s", groupID)
				}
				targets[edge.ToTaskID] = struct{}{}
			}
			if group.mode == DependencyQuorum && group.quorum > uint32(len(group.edges)) {
				return nil, fmt.Errorf("quorum exceeds dependency group %s size", groupID)
			}
		}
	}

	candidates := make(map[string]struct{})
	for id, task := range taskByID {
		if !task.Terminal && !task.Runnable && !task.ExternalEscape {
			candidates[id] = struct{}{}
		}
	}

	for changed := true; changed; {
		changed = false
		for taskID := range candidates {
			if !taskBlockedBySet(groups[taskID], candidates) {
				delete(candidates, taskID)
				changed = true
			}
		}
	}

	result := make([]string, 0, len(candidates))
	for id := range candidates {
		result = append(result, id)
	}
	sort.Strings(result)
	return result, nil
}

func taskBlockedBySet(groups map[string]*dependencyGroup, candidates map[string]struct{}) bool {
	for _, group := range groups {
		if groupBlockedBySet(group, candidates) {
			return true
		}
	}
	return false
}

func groupBlockedBySet(group *dependencyGroup, candidates map[string]struct{}) bool {
	satisfied := uint32(0)
	unsatisfiedInside := uint32(0)
	unsatisfiedOutside := uint32(0)
	for _, edge := range group.edges {
		if edge.Satisfied {
			satisfied++
			continue
		}
		if _, inside := candidates[edge.ToTaskID]; inside {
			unsatisfiedInside++
		} else {
			unsatisfiedOutside++
		}
	}

	switch group.mode {
	case DependencyAll:
		return unsatisfiedInside > 0
	case DependencyAny:
		return satisfied == 0 && unsatisfiedInside > 0 && unsatisfiedOutside == 0
	case DependencyQuorum:
		if satisfied >= group.quorum {
			return false
		}
		return unsatisfiedInside > 0 && satisfied+unsatisfiedOutside < group.quorum
	default:
		return false
	}
}
