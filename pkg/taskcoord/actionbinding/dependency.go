// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package actionbinding

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"

	"github.com/thinksyncs/agents-secure-binding/pkg/actionlifecycle"
	"github.com/thinksyncs/agents-secure-binding/pkg/taskcoord"
)

const (
	dependencyTopologyDomain = "ASB-TASK-ACTION-DEPENDENCY-TOPOLOGY-v1\x00"
	dependencySignalDomain   = "ASB-TASK-ACTION-DEPENDENCY-SIGNAL-v1\x00"
	dependencyEvidenceDomain = "ASB-TASK-ACTION-DEPENDENCY-EVIDENCE-v1\x00"
	dependencySignalPrefix   = "taskcoord-dependencies:"
	dependencyEvidencePrefix = "urn:asb:taskcoord-dependency-resolution:v1:sha256:"
)

type dependencyGroup struct {
	mode      taskcoord.DependencyMode
	quorum    uint32
	edges     []taskcoord.Dependency
	targetIDs map[string]struct{}
}

// DependencyWaitSignal returns the signal that must be placed into the next
// WAITING Action snapshot. The digest excludes mutable satisfaction flags.
func DependencyWaitSignal(taskID, actionID string, actionRevision uint64, dependencies []taskcoord.Dependency) (string, error) {
	if err := validateID("task_id", taskID); err != nil {
		return "", err
	}
	if err := validateID("action_id", actionID); err != nil {
		return "", err
	}
	if actionRevision == 0 {
		return "", fmt.Errorf("action_revision must be positive")
	}
	_, topologyDigest, err := canonicalDependencies(taskID, dependencies, false)
	if err != nil {
		return "", err
	}
	var encoded bytes.Buffer
	encoded.WriteString(dependencySignalDomain)
	writeField(&encoded, "task_id", taskID)
	writeField(&encoded, "action_id", actionID)
	writeField(&encoded, "action_revision", strconv.FormatUint(actionRevision, 10))
	writeField(&encoded, "dependency_set_digest", topologyDigest)
	sum := sha256.Sum256(encoded.Bytes())
	return dependencySignalPrefix + hex.EncodeToString(sum[:]), nil
}

// DependenciesSatisfied evaluates all active groups for one Task. Multiple
// groups are conjunctive; group members use ALL, ANY, or QUORUM semantics.
func DependenciesSatisfied(taskID string, dependencies []taskcoord.Dependency) (bool, error) {
	edges, _, err := canonicalDependencies(taskID, dependencies, false)
	if err != nil {
		return false, err
	}
	groups := make(map[string][]taskcoord.Dependency)
	for _, edge := range edges {
		groups[edge.GroupID] = append(groups[edge.GroupID], edge)
	}
	for _, group := range groups {
		satisfied := uint32(0)
		for _, edge := range group {
			if edge.Satisfied {
				satisfied++
			}
		}
		switch group[0].Mode {
		case taskcoord.DependencyAll:
			if satisfied != uint32(len(group)) {
				return false, nil
			}
		case taskcoord.DependencyAny:
			if satisfied == 0 {
				return false, nil
			}
		case taskcoord.DependencyQuorum:
			if satisfied < group[0].Quorum {
				return false, nil
			}
		}
	}
	return true, nil
}

// WaitForDependencies applies a dependency-specific WAIT and returns its
// immutable companion record. Commit both through Store.CommitDependencyWait.
func WaitForDependencies(
	binding Binding,
	assignment taskcoord.Assignment,
	current actionlifecycle.Snapshot,
	dependencies []taskcoord.Dependency,
	event actionlifecycle.Event,
) (actionlifecycle.Transition, DependencyWait, error) {
	if err := requireAcceptedCurrent(binding, assignment, current); err != nil {
		return actionlifecycle.Transition{}, DependencyWait{}, err
	}
	if current.State != actionlifecycle.StateRunning || event.Kind != actionlifecycle.EventWait ||
		event.Reason.Code != actionlifecycle.ReasonDependencyPending {
		return actionlifecycle.Transition{}, DependencyWait{}, fmt.Errorf("%w: dependency wait requires RUNNING, WAIT, and DEPENDENCY_PENDING", ErrInvalidDependencyWait)
	}
	satisfied, err := DependenciesSatisfied(binding.TaskID, dependencies)
	if err != nil {
		return actionlifecycle.Transition{}, DependencyWait{}, err
	}
	if satisfied {
		return actionlifecycle.Transition{}, DependencyWait{}, ErrDependenciesSatisfied
	}
	signal, err := DependencyWaitSignal(binding.TaskID, binding.ActionID, current.Revision+1, dependencies)
	if err != nil {
		return actionlifecycle.Transition{}, DependencyWait{}, err
	}
	event.ResumeCondition = &actionlifecycle.ResumeCondition{Type: actionlifecycle.ResumeSignal, Signal: signal}
	transition, err := actionlifecycle.Apply(current, event)
	if err != nil {
		return actionlifecycle.Transition{}, DependencyWait{}, err
	}
	wait, err := NewDependencyWait(binding, assignment, transition, dependencies)
	if err != nil {
		return actionlifecycle.Transition{}, DependencyWait{}, err
	}
	return transition, wait, nil
}

// NewDependencyWait validates an already-produced dependency WAIT transition.
func NewDependencyWait(binding Binding, assignment taskcoord.Assignment, transition actionlifecycle.Transition, dependencies []taskcoord.Dependency) (DependencyWait, error) {
	if err := validateTransition(transition); err != nil {
		return DependencyWait{}, err
	}
	if err := requireAcceptedCurrent(binding, assignment, transition.Snapshot); err != nil {
		return DependencyWait{}, err
	}
	snapshot := transition.Snapshot
	if snapshot.State != actionlifecycle.StateWaiting || transition.Record.Kind != actionlifecycle.EventWait ||
		transition.Record.From != actionlifecycle.StateRunning || snapshot.Reason.Code != actionlifecycle.ReasonDependencyPending ||
		snapshot.ResumeCondition == nil || snapshot.ResumeCondition.Type != actionlifecycle.ResumeSignal {
		return DependencyWait{}, fmt.Errorf("%w: Action is not a dependency WAIT transition", ErrInvalidDependencyWait)
	}
	edges, digest, err := canonicalDependencies(binding.TaskID, dependencies, false)
	if err != nil {
		return DependencyWait{}, err
	}
	satisfied, err := DependenciesSatisfied(binding.TaskID, dependencies)
	if err != nil {
		return DependencyWait{}, err
	}
	if satisfied {
		return DependencyWait{}, ErrDependenciesSatisfied
	}
	signal, err := DependencyWaitSignal(binding.TaskID, binding.ActionID, snapshot.Revision, dependencies)
	if err != nil {
		return DependencyWait{}, err
	}
	if snapshot.ResumeCondition.Signal != signal {
		return DependencyWait{}, fmt.Errorf("%w: Action signal does not bind dependency topology", ErrInvalidDependencyWait)
	}
	ids := make([]string, 0, len(edges))
	for _, edge := range edges {
		ids = append(ids, edge.DependencyID)
	}
	ids = sortedCopy(ids)
	wait := DependencyWait{
		Schema: DependencyWaitSchemaV1, TaskID: binding.TaskID, ActionID: binding.ActionID,
		ActionRevision: snapshot.Revision, DependencyIDs: ids, DependencySetDigest: digest,
		CreatedAt: snapshot.UpdatedAt,
	}
	if err := wait.Validate(); err != nil {
		return DependencyWait{}, err
	}
	return wait, nil
}

// ResumeDependencyWait proves that the exact stored dependency topology is
// now satisfied, supplies deterministic evidence, and applies RESUME.
func ResumeDependencyWait(
	binding Binding,
	assignment taskcoord.Assignment,
	current actionlifecycle.Snapshot,
	wait DependencyWait,
	dependencies []taskcoord.Dependency,
	event actionlifecycle.Event,
) (actionlifecycle.Transition, error) {
	evidence, err := dependencyResumeEvidence(binding, assignment, current, wait, dependencies)
	if err != nil {
		return actionlifecycle.Transition{}, err
	}
	if event.Kind != actionlifecycle.EventResume || event.Reason.Code != actionlifecycle.ReasonResumed {
		return actionlifecycle.Transition{}, fmt.Errorf("%w: dependency resume requires RESUME and RESUMED", ErrInvalidDependencyWait)
	}
	event.EvidenceRef = evidence
	return actionlifecycle.Apply(current, event)
}

func dependencyResumeEvidence(binding Binding, assignment taskcoord.Assignment, current actionlifecycle.Snapshot, wait DependencyWait, dependencies []taskcoord.Dependency) (string, error) {
	if err := requireAcceptedCurrent(binding, assignment, current); err != nil {
		return "", err
	}
	if err := validateCurrentWait(binding, current, wait, dependencies); err != nil {
		return "", err
	}
	satisfied, err := DependenciesSatisfied(binding.TaskID, dependencies)
	if err != nil {
		return "", err
	}
	if !satisfied {
		return "", ErrDependenciesPending
	}
	_, satisfactionDigest, err := canonicalDependencies(binding.TaskID, dependencies, true)
	if err != nil {
		return "", err
	}
	var encoded bytes.Buffer
	encoded.WriteString(dependencyEvidenceDomain)
	writeField(&encoded, "task_id", wait.TaskID)
	writeField(&encoded, "action_id", wait.ActionID)
	writeField(&encoded, "action_revision", strconv.FormatUint(wait.ActionRevision, 10))
	writeField(&encoded, "dependency_set_digest", wait.DependencySetDigest)
	writeField(&encoded, "satisfaction_digest", satisfactionDigest)
	sum := sha256.Sum256(encoded.Bytes())
	return dependencyEvidencePrefix + hex.EncodeToString(sum[:]), nil
}

func validateCurrentWait(binding Binding, current actionlifecycle.Snapshot, wait DependencyWait, dependencies []taskcoord.Dependency) error {
	if err := wait.Validate(); err != nil {
		return err
	}
	if wait.TaskID != binding.TaskID || wait.ActionID != binding.ActionID || wait.ActionRevision != current.Revision ||
		current.State != actionlifecycle.StateWaiting || current.ResumeCondition == nil ||
		current.ResumeCondition.Type != actionlifecycle.ResumeSignal || !wait.CreatedAt.Equal(current.UpdatedAt) {
		return fmt.Errorf("%w: wait does not match current Action", ErrInvalidDependencyWait)
	}
	edges, digest, err := canonicalDependencies(binding.TaskID, dependencies, false)
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(edges))
	for _, edge := range edges {
		ids = append(ids, edge.DependencyID)
	}
	ids = sortedCopy(ids)
	if digest != wait.DependencySetDigest || !sameStrings(ids, wait.DependencyIDs) {
		return ErrDependencyTopologyChanged
	}
	signal, err := DependencyWaitSignal(wait.TaskID, wait.ActionID, wait.ActionRevision, dependencies)
	if err != nil {
		return err
	}
	if current.ResumeCondition.Signal != signal {
		return fmt.Errorf("%w: stored signal mismatch", ErrInvalidDependencyWait)
	}
	return nil
}

func requireAcceptedCurrent(binding Binding, assignment taskcoord.Assignment, action actionlifecycle.Snapshot) error {
	if err := ValidateCurrent(binding, assignment, action); err != nil {
		return err
	}
	if assignment.Status != taskcoord.AssignmentAccepted {
		return ErrAssignmentNotAccepted
	}
	return nil
}

func canonicalDependencies(taskID string, dependencies []taskcoord.Dependency, includeSatisfaction bool) ([]taskcoord.Dependency, string, error) {
	if err := validateID("task_id", taskID); err != nil {
		return nil, "", err
	}
	seenIDs := make(map[string]struct{}, len(dependencies))
	edges := make([]taskcoord.Dependency, 0)
	groups := make(map[string]*dependencyGroup)
	for _, dependency := range dependencies {
		if err := dependency.Validate(); err != nil {
			return nil, "", err
		}
		if _, exists := seenIDs[dependency.DependencyID]; exists {
			return nil, "", fmt.Errorf("duplicate dependency_id %s", dependency.DependencyID)
		}
		seenIDs[dependency.DependencyID] = struct{}{}
		if !dependency.Active || dependency.FromTaskID != taskID {
			continue
		}
		group := groups[dependency.GroupID]
		if group == nil {
			group = &dependencyGroup{mode: dependency.Mode, quorum: dependency.Quorum, targetIDs: make(map[string]struct{})}
			groups[dependency.GroupID] = group
		} else if group.mode != dependency.Mode || group.quorum != dependency.Quorum {
			return nil, "", fmt.Errorf("inconsistent dependency group %s", dependency.GroupID)
		}
		if _, exists := group.targetIDs[dependency.ToTaskID]; exists {
			return nil, "", fmt.Errorf("duplicate target in dependency group %s", dependency.GroupID)
		}
		group.targetIDs[dependency.ToTaskID] = struct{}{}
		group.edges = append(group.edges, dependency)
		edges = append(edges, dependency)
	}
	if len(edges) == 0 {
		return nil, "", fmt.Errorf("%w: no active dependencies for task", ErrInvalidDependencyWait)
	}
	for groupID, group := range groups {
		if group.mode == taskcoord.DependencyQuorum && group.quorum > uint32(len(group.edges)) {
			return nil, "", fmt.Errorf("quorum exceeds dependency group %s size", groupID)
		}
	}
	sort.Slice(edges, func(i, j int) bool { return edges[i].DependencyID < edges[j].DependencyID })
	var encoded bytes.Buffer
	encoded.WriteString(dependencyTopologyDomain)
	writeField(&encoded, "task_id", taskID)
	for _, edge := range edges {
		writeField(&encoded, "dependency_id", edge.DependencyID)
		writeField(&encoded, "from_task_id", edge.FromTaskID)
		writeField(&encoded, "to_task_id", edge.ToTaskID)
		writeField(&encoded, "group_id", edge.GroupID)
		writeField(&encoded, "mode", string(edge.Mode))
		writeField(&encoded, "quorum", strconv.FormatUint(uint64(edge.Quorum), 10))
		if includeSatisfaction {
			writeField(&encoded, "satisfied", strconv.FormatBool(edge.Satisfied))
		}
	}
	sum := sha256.Sum256(encoded.Bytes())
	return edges, "sha256:" + hex.EncodeToString(sum[:]), nil
}

func writeField(buffer *bytes.Buffer, name, value string) {
	writeLengthPrefixed(buffer, []byte(name))
	writeLengthPrefixed(buffer, []byte(value))
}

func writeLengthPrefixed(buffer *bytes.Buffer, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	buffer.Write(length[:])
	buffer.Write(value)
}
