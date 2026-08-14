// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package actionbinding

import (
	"fmt"
	"sort"

	"github.com/thinksyncs/agents-secure-binding/pkg/actionlifecycle"
	"github.com/thinksyncs/agents-secure-binding/pkg/taskcoord"
)

type taskAggregate struct {
	count          int
	allTerminal    bool
	runnable       bool
	externalEscape bool
}

// ProjectTaskLiveness derives the minimum conservative view consumed by the
// existing TaskCoord deadlock detector. Only a validated dependency WAIT is
// treated as blocked solely inside the supplied graph.
func ProjectTaskLiveness(linked []LinkedAction, dependencies []taskcoord.Dependency) ([]taskcoord.TaskLiveness, error) {
	if _, err := taskcoord.DetectDeadlockedTasks(nil, dependencies); err != nil {
		return nil, err
	}
	aggregates := make(map[string]*taskAggregate)
	seenActions := make(map[string]struct{}, len(linked))
	for _, item := range linked {
		if _, exists := seenActions[item.Action.ActionID]; exists {
			return nil, fmt.Errorf("duplicate action_id %s", item.Action.ActionID)
		}
		seenActions[item.Action.ActionID] = struct{}{}
		if err := ValidateCurrent(item.Binding, item.Assignment, item.Action); err != nil {
			return nil, err
		}
		aggregate := aggregates[item.Binding.TaskID]
		if aggregate == nil {
			aggregate = &taskAggregate{allTerminal: true}
			aggregates[item.Binding.TaskID] = aggregate
		}
		aggregate.count++
		terminal := item.Action.State.Terminal()
		aggregate.allTerminal = aggregate.allTerminal && terminal
		if terminal {
			continue
		}
		if item.Assignment.Status != taskcoord.AssignmentAccepted {
			aggregate.externalEscape = true
			continue
		}
		switch item.Action.State {
		case actionlifecycle.StateAccepted, actionlifecycle.StateRunning, actionlifecycle.StateCanceling:
			aggregate.runnable = true
		case actionlifecycle.StateWaiting:
			if item.DependencyWait == nil {
				aggregate.externalEscape = true
				continue
			}
			if err := validateCurrentWait(item.Binding, item.Action, *item.DependencyWait, dependencies); err != nil {
				return nil, err
			}
		case actionlifecycle.StatePaused, actionlifecycle.StateOrphaned, actionlifecycle.StateIndeterminate:
			aggregate.externalEscape = true
		default:
			return nil, fmt.Errorf("unsupported Action state %s", item.Action.State)
		}
	}

	result := make([]taskcoord.TaskLiveness, 0, len(aggregates))
	for taskID, aggregate := range aggregates {
		result = append(result, taskcoord.TaskLiveness{
			TaskID: taskID, Terminal: aggregate.count > 0 && aggregate.allTerminal,
			Runnable: aggregate.runnable, ExternalEscape: aggregate.externalEscape,
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].TaskID < result[j].TaskID })
	return result, nil
}

// DetectDeadlockedActions connects validated Action snapshots to the existing
// conservative Task dependency detector.
func DetectDeadlockedActions(linked []LinkedAction, dependencies []taskcoord.Dependency) ([]string, error) {
	tasks, err := ProjectTaskLiveness(linked, dependencies)
	if err != nil {
		return nil, err
	}
	return taskcoord.DetectDeadlockedTasks(tasks, dependencies)
}
