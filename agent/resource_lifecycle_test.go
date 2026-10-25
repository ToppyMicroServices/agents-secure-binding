// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/agent/algorithm"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/agent/events/mocks"
	runnerpb "github.com/ToppyMicroServices/agents-secure-binding/v2/agent/runner"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/agent/statemachine"
	mglog "github.com/ToppyMicroServices/agents-secure-binding/v2/internal/runtime/logging"
	runnermocks "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients/grpc/runner/mocks"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/oci"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"
)

const oldComputationID = "old-computation"

type blockedResourceClient struct {
	started  chan string
	deadline chan time.Time
}

func (c *blockedResourceClient) PullAndDecrypt(ctx context.Context, source oci.ResourceSource, destDir string) error {
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(destDir, "plaintext"), []byte("private"), 0o600); err != nil {
		return err
	}
	deadline, _ := ctx.Deadline()
	c.deadline <- deadline
	c.started <- filepath.Dir(destDir)
	<-ctx.Done()
	// A successful return racing cancellation must still be discarded.
	return nil
}

func (*blockedResourceClient) ToDockerArchive(context.Context, string, string) error { return nil }

func TestStopCancelsAutomaticResourcePullBeforeServiceLock(t *testing.T) {
	for _, kind := range []string{resourceTypeAlgorithm, "dataset"} {
		t.Run(kind, func(t *testing.T) {
			t.Chdir(t.TempDir())
			parentCtx, cancel := context.WithCancel(context.Background())
			defer cancel()
			events := new(mocks.Service)
			events.On("SendEvent", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return()
			runner := new(runnermocks.Client)
			runner.On("Stop", mock.Anything, mock.AnythingOfType("*runner.StopRequest")).Return(&emptypb.Empty{}, nil)
			svc := New(parentCtx, mglog.NewMock(), events, nil, runner, 0).(*agentService)
			defer svc.cancel()
			client := &blockedResourceClient{started: make(chan string, 1), deadline: make(chan time.Time, 1)}
			svc.ociClient = client
			svc.computation.ID = oldComputationID
			svc.computation.KBS.Enabled = true
			source := &ResourceSource{Type: "oci-image", URL: "docker://test/stalled"}
			var action statemachine.Action
			if kind == resourceTypeAlgorithm {
				svc.computation.Algorithm.Source = source
				action = svc.downloadAlgorithmIfRemote
			} else {
				svc.computation.Datasets = []Dataset{{Filename: "data.csv", Source: source}}
				action = svc.downloadDatasetsIfRemote
			}
			finished := make(chan struct{})
			go func() {
				action(ReceivingAlgorithm)
				close(finished)
			}()
			var workspace string
			select {
			case workspace = <-client.started:
			case <-time.After(2 * time.Second):
				t.Fatal("automatic download did not start")
			}
			require.False(t, (<-client.deadline).IsZero(), "automatic pull must have a finite deadline")
			stopped := make(chan error, 1)
			go func() { stopped <- svc.StopComputation(context.Background()) }()
			select {
			case err := <-stopped:
				require.NoError(t, err)
			case <-time.After(2 * time.Second):
				t.Fatal("Stop waited for a download-held service lock without canceling the download")
			}
			<-finished
			_, err := os.Stat(workspace)
			require.True(t, os.IsNotExist(err), "canceled pull retained its plaintext workspace")
			require.Equal(t, ReceivingManifest, svc.sm.GetState())
			require.Empty(t, svc.computation.ID)
			require.Nil(t, svc.runError)
			require.False(t, svc.algoReceived)
			_, err = os.Stat("algo")
			require.True(t, os.IsNotExist(err))
			_, err = os.Stat(algorithm.DatasetsDir)
			require.True(t, os.IsNotExist(err))
			// Reset now owns a fresh context; the canceled operation has exited.
			require.NoError(t, svc.ctx.Err())
			svc.computation = Computation{ID: "next-computation"}
			require.Equal(t, "next-computation", svc.computation.ID)
			runner.AssertCalled(t, "Stop", mock.Anything, &runnerpb.StopRequest{ComputationId: oldComputationID})
		})
	}
}

func TestLateRunnerResponseCannotModifyNextComputation(t *testing.T) {
	t.Chdir(t.TempDir())
	parentCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := new(mocks.Service)
	events.On("SendEvent", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return()
	runner := new(runnermocks.Client)
	started := make(chan context.Context, 1)
	release := make(chan struct{})
	runner.On("Run", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		started <- args.Get(0).(context.Context)
		<-release
	}).Return(&runnerpb.RunResponse{}, nil).Once()
	runner.On("Stop", mock.Anything, mock.Anything).Return(&emptypb.Empty{}, nil)
	svc := New(parentCtx, mglog.NewMock(), events, nil, runner, 0).(*agentService)
	svc.computation.ID = oldComputationID
	oldLifecycle := svc.ctx
	require.NoError(t, os.WriteFile("algo", []byte("old algorithm"), 0o700))
	finished := make(chan struct{})
	go func() {
		svc.runComputationForContext(oldLifecycle, Running)
		close(finished)
	}()
	var runCtx context.Context
	select {
	case runCtx = <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("runner call did not start")
	}
	require.NoError(t, svc.StopComputation(context.Background()))
	require.ErrorIs(t, runCtx.Err(), context.Canceled)
	svc.mu.Lock()
	svc.computation.ID = "next-computation"
	svc.result = []byte("next result")
	svc.mu.Unlock()
	for _, dir := range []string{algorithm.DatasetsDir, algorithm.ResultsDir} {
		require.NoError(t, os.MkdirAll(dir, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "next"), []byte("next data"), 0o600))
	}
	require.NoError(t, os.WriteFile("algo", []byte("next algorithm"), 0o700))
	close(release)
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("old runner response was not discarded")
	}
	require.Equal(t, []byte("next result"), svc.result)
	require.Nil(t, svc.runError)
	require.Equal(t, "next-computation", svc.computation.ID)
	for _, file := range []string{"algo", filepath.Join(algorithm.DatasetsDir, "next"), filepath.Join(algorithm.ResultsDir, "next")} {
		_, err := os.Stat(file)
		require.NoError(t, err, "late response removed a file from the next computation")
	}
	// State-machine actions already queued before Reset must also be inert.
	svc.runComputationForContext(oldLifecycle, Running)
	svc.downloadAlgorithmForContext(oldLifecycle, ReceivingAlgorithm)
	svc.downloadDatasetsForContext(oldLifecycle, ReceivingData)
	runner.AssertNumberOfCalls(t, "Run", 1)
}

func TestStopFailurePreservesCanceledLifecycleUntilTeardownConfirmed(t *testing.T) {
	t.Chdir(t.TempDir())
	parentCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := new(mocks.Service)
	events.On("SendEvent", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return()
	runner := new(runnermocks.Client)
	started := make(chan struct{})
	runner.On("Run", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		close(started)
		<-args.Get(0).(context.Context).Done()
	}).Return((*runnerpb.RunResponse)(nil), context.Canceled).Once()
	runner.On("Stop", mock.Anything, mock.Anything).Return((*emptypb.Empty)(nil), context.DeadlineExceeded).Once()
	runner.On("Stop", mock.Anything, mock.Anything).Return(&emptypb.Empty{}, nil).Once()
	svc := New(parentCtx, mglog.NewMock(), events, nil, runner, 0).(*agentService)
	svc.computation.ID = oldComputationID
	lifecycle := svc.ctx
	require.NoError(t, os.MkdirAll(algorithm.DatasetsDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(algorithm.DatasetsDir, "data"), []byte("private"), 0o600))
	require.NoError(t, os.WriteFile("algo", []byte("code"), 0o700))
	finished := make(chan struct{})
	go func() {
		svc.runComputationForContext(lifecycle, Running)
		close(finished)
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("runner did not start")
	}
	require.ErrorIs(t, svc.StopComputation(context.Background()), context.DeadlineExceeded)
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled Run did not return")
	}
	require.Same(t, lifecycle, svc.ctx)
	require.ErrorIs(t, svc.ctx.Err(), context.Canceled)
	require.Equal(t, oldComputationID, svc.computation.ID)
	require.ErrorIs(t, svc.InitComputation(context.Background(), Computation{ID: "next"}), ErrStateNotReady)
	for _, name := range []string{"algo", algorithm.ResultsDir, filepath.Join(algorithm.DatasetsDir, "data")} {
		_, err := os.Stat(name)
		require.NoError(t, err, "unconfirmed teardown removed computation data")
	}
	require.NoError(t, svc.StopComputation(context.Background()))
	require.NotSame(t, lifecycle, svc.ctx)
	require.NoError(t, svc.ctx.Err())
	require.Equal(t, ReceivingManifest, svc.sm.GetState())
	for _, name := range []string{"algo", algorithm.ResultsDir, algorithm.DatasetsDir} {
		_, err := os.Stat(name)
		require.True(t, os.IsNotExist(err))
	}
}
