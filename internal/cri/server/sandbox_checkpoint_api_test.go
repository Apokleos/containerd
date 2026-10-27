/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package server

import (
	"context"
	"errors"
	"fmt"
	goruntime "runtime"
	"testing"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/sandbox"
	"github.com/containerd/containerd/v2/internal/cri/server/podsandbox"
	containerstore "github.com/containerd/containerd/v2/internal/cri/store/container"
	sandboxstore "github.com/containerd/containerd/v2/internal/cri/store/sandbox"
	"github.com/containerd/containerd/v2/internal/eventq"
	"github.com/containerd/errdefs"
	"github.com/containerd/typeurl/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

type checkpointControllerStub struct {
	sandbox.Controller
	checkpoint func(context.Context, string, sandbox.CheckpointOptions) error
	restore    func(context.Context, string, sandbox.RestoreOptions) (sandbox.RestoreResult, error)
}

func (c *checkpointControllerStub) Checkpoint(ctx context.Context, sandboxID string, opts sandbox.CheckpointOptions) error {
	return c.checkpoint(ctx, sandboxID, opts)
}

func (c *checkpointControllerStub) Restore(ctx context.Context, sandboxID string, opts sandbox.RestoreOptions) (sandbox.RestoreResult, error) {
	return c.restore(ctx, sandboxID, opts)
}

type checkpointSandboxService struct {
	sandboxService
	controller       sandbox.Controller
	sandboxer        string
	err              error
	controllerStatus sandbox.ControllerStatus
}

func (s *checkpointSandboxService) SandboxController(sandboxer string) (sandbox.Controller, error) {
	s.sandboxer = sandboxer
	return s.controller, s.err
}

func (s *checkpointSandboxService) SandboxStatus(context.Context, string, string, bool) (sandbox.ControllerStatus, error) {
	return s.controllerStatus, s.err
}

func checkpointAPIContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestRejectExternalRestoreAnnotation(t *testing.T) {
	config := &runtime.PodSandboxConfig{Annotations: map[string]string{restoreAnnotation: "true"}}
	require.ErrorContains(t, rejectExternalRestoreAnnotation(config), "reserved for containerd restore")
	require.NoError(t, rejectExternalRestoreAnnotation(&runtime.PodSandboxConfig{}))
}

func TestCheckpointPodPassesDataToSelectedController(t *testing.T) {
	var gotID string
	var gotOptions sandbox.CheckpointOptions
	controller := &checkpointControllerStub{
		checkpoint: func(_ context.Context, id string, options sandbox.CheckpointOptions) error {
			gotID = id
			gotOptions = options
			return nil
		},
	}
	cri := newTestCRIService()
	if goruntime.GOOS == "linux" {
		cri.podCheckpointSupportCheck = nil
		cri.shimPath = t.TempDir()
	}
	sandboxService := &checkpointSandboxService{controller: controller}
	cri.sandboxService = sandboxService

	sandboxConfig := &runtime.PodSandboxConfig{
		Metadata: &runtime.PodSandboxMetadata{Name: "pod", Namespace: "default", Uid: "uid"},
		Linux:    &runtime.LinuxPodSandboxConfig{CgroupParent: "/pod"},
	}
	sb := sandboxstore.NewSandbox(
		sandboxstore.Metadata{ID: "sandbox-1", Config: sandboxConfig},
		sandboxstore.Status{State: sandboxstore.StateReady},
	)
	sb.Sandboxer = "custom-controller"
	require.NoError(t, cri.sandboxStore.Add(sb))

	containerConfig := &runtime.ContainerConfig{
		Metadata: &runtime.ContainerMetadata{Name: "app"},
		Image:    &runtime.ImageSpec{Image: "example/app:latest"},
	}
	cntr, err := containerstore.NewContainer(
		containerstore.Metadata{
			ID:        "container-1",
			SandboxID: sb.ID,
			Config:    containerConfig,
			ImageRef:  "sha256:image",
		},
		containerstore.WithFakeStatus(containerstore.Status{
			CreatedAt: 1,
			StartedAt: 2,
		}),
	)
	require.NoError(t, err)
	require.NoError(t, cri.containerStore.Add(cntr))

	_, err = cri.CheckpointPod(checkpointAPIContext(t), &runtime.CheckpointPodRequest{
		PodSandboxId: sb.ID,
		OutputPath:   "/controller-owned/output",
		ContainerIds: []string{cntr.ID},
		Options:      map[string]string{"controller-specific": "value"},
	})
	require.NoError(t, err)
	assert.Equal(t, sb.ID, gotID)
	assert.Equal(t, "custom-controller", sandboxService.sandboxer)
	assert.Equal(t, "/controller-owned/output", gotOptions.OutputPath)
	assert.Equal(t, map[string]string{"controller-specific": "value"}, gotOptions.Options)

	decodedSandbox := new(runtime.PodSandboxConfig)
	require.NoError(t, typeurl.UnmarshalTo(gotOptions.SandboxConfig, decodedSandbox))
	assert.True(t, proto.Equal(sandboxConfig, decodedSandbox))
	require.Len(t, gotOptions.Containers, 1)
	assert.Equal(t, cntr.ID, gotOptions.Containers[0].ID)
	assert.Equal(t, "app", gotOptions.Containers[0].Name)

	decodedConfig := new(runtime.ContainerConfig)
	require.NoError(t, typeurl.UnmarshalTo(gotOptions.Containers[0].Config, decodedConfig))
	assert.True(t, proto.Equal(containerConfig, decodedConfig))
	decodedStatus := new(runtime.ContainerStatus)
	require.NoError(t, typeurl.UnmarshalTo(gotOptions.Containers[0].Status, decodedStatus))
	assert.Equal(t, runtime.ContainerState_CONTAINER_RUNNING, decodedStatus.State)
	assert.Equal(t, "sha256:image", decodedStatus.ImageRef)
}

func TestCheckpointPodDoesNotInterpretControllerOptions(t *testing.T) {
	controllerErr := errdefs.ErrInvalidArgument
	controller := &checkpointControllerStub{
		checkpoint: func(_ context.Context, _ string, options sandbox.CheckpointOptions) error {
			assert.Equal(t, map[string]string{"unknown-to-cri": "value"}, options.Options)
			return controllerErr
		},
	}
	cri := newTestCRIService()
	cri.sandboxService = &checkpointSandboxService{controller: controller}
	sb := sandboxstore.NewSandbox(
		sandboxstore.Metadata{
			ID:     "sandbox-1",
			Config: &runtime.PodSandboxConfig{},
		},
		sandboxstore.Status{State: sandboxstore.StateReady},
	)
	sb.Sandboxer = "custom"
	require.NoError(t, cri.sandboxStore.Add(sb))
	cntr, err := containerstore.NewContainer(
		containerstore.Metadata{
			ID:        "container-1",
			SandboxID: sb.ID,
			Config: &runtime.ContainerConfig{
				Metadata: &runtime.ContainerMetadata{Name: "app"},
			},
		},
		containerstore.WithFakeStatus(containerstore.Status{CreatedAt: 1, StartedAt: 2}),
	)
	require.NoError(t, err)
	require.NoError(t, cri.containerStore.Add(cntr))

	_, err = cri.CheckpointPod(checkpointAPIContext(t), &runtime.CheckpointPodRequest{
		PodSandboxId: sb.ID,
		OutputPath:   "/opaque",
		ContainerIds: []string{cntr.ID},
		Options:      map[string]string{"unknown-to-cri": "value"},
	})
	require.ErrorIs(t, err, controllerErr)
}

func TestRestoreOptionsFromCRIContainsOnlyData(t *testing.T) {
	request := &runtime.RestorePodRequest{
		CheckpointPath: "/checkpoint",
		RuntimeHandler: "vm-runtime",
		Options:        map[string]string{"controller-specific": "value"},
		Config: &runtime.PodSandboxConfig{
			Metadata: &runtime.PodSandboxMetadata{Name: "pod", Namespace: "default", Uid: "new-uid"},
		},
		ContainerConfigs: []*runtime.ContainerConfig{{
			Metadata: &runtime.ContainerMetadata{Name: "app"},
			Image:    &runtime.ImageSpec{Image: "example/app:latest"},
		}},
	}
	options, err := restoreOptionsFromCRI(request)
	require.NoError(t, err)
	assert.Equal(t, request.CheckpointPath, options.CheckpointPath)
	assert.Equal(t, request.Options, options.Options)
	require.Len(t, options.Containers, 1)
	assert.Empty(t, options.Containers[0].ID)
	assert.Equal(t, "app", options.Containers[0].Name)

	sandboxConfig := new(runtime.PodSandboxConfig)
	require.NoError(t, typeurl.UnmarshalTo(options.SandboxConfig, sandboxConfig))
	assert.True(t, proto.Equal(request.Config, sandboxConfig))
	containerConfig := new(runtime.ContainerConfig)
	require.NoError(t, typeurl.UnmarshalTo(options.Containers[0].Config, containerConfig))
	assert.True(t, proto.Equal(request.ContainerConfigs[0], containerConfig))
}

func TestValidateRestoreResult(t *testing.T) {
	requested := []sandbox.RestoreContainer{
		{ID: "one", Name: "app"},
		{ID: "two", Name: "sidecar"},
	}
	prepared, err := validateRestoreResult(requested, sandbox.RestoreResult{
		RestoredContainers: []sandbox.RestoredContainer{
			{Name: "sidecar"},
			{Name: "app", TaskCheckpointImage: "localhost/checkpoint:app"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		"app":     "localhost/checkpoint:app",
		"sidecar": "",
	}, prepared)

	_, err = validateRestoreResult(requested, sandbox.RestoreResult{
		RestoredContainers: []sandbox.RestoredContainer{
			{Name: "app"},
			{Name: "app"},
		},
	})
	require.ErrorContains(t, err, "more than once")

	_, err = validateRestoreResult(requested, sandbox.RestoreResult{
		RestoredContainers: []sandbox.RestoredContainer{
			{Name: "app"},
			{Name: "unexpected"},
		},
	})
	require.ErrorContains(t, err, "unexpected")
}

type restoreOperationsStub struct {
	calls                []string
	contextErrs          []error
	containerIDs         []string
	createCalls          int
	createErrAt          int
	saveErr              error
	saved                map[string]string
	deleted              []string
	runRequest           *runtime.RunPodSandboxRequest
	createSandboxConfigs []*runtime.PodSandboxConfig
	restoreContexts      []bool
	publishErr           error
}

func (o *restoreOperationsStub) RunPodSandbox(ctx context.Context, request *runtime.RunPodSandboxRequest) (*runtime.RunPodSandboxResponse, error) {
	o.contextErrs = append(o.contextErrs, ctx.Err())
	o.calls = append(o.calls, "run:"+request.GetRuntimeHandler())
	o.runRequest = request
	o.restoreContexts = append(o.restoreContexts, isPodRestore(ctx))
	return &runtime.RunPodSandboxResponse{PodSandboxId: "new-sandbox"}, nil
}

func (o *restoreOperationsStub) CreateContainer(ctx context.Context, request *runtime.CreateContainerRequest) (*runtime.CreateContainerResponse, error) {
	o.contextErrs = append(o.contextErrs, ctx.Err())
	o.createSandboxConfigs = append(o.createSandboxConfigs, request.GetSandboxConfig())
	o.createCalls++
	o.restoreContexts = append(o.restoreContexts, isPodRestore(ctx))
	name := request.GetConfig().GetMetadata().GetName()
	o.calls = append(o.calls, "create:"+name)
	if o.createErrAt == o.createCalls {
		return nil, errors.New("create failed")
	}
	return &runtime.CreateContainerResponse{ContainerId: o.containerIDs[o.createCalls-1]}, nil
}

func (o *restoreOperationsStub) RemovePodSandbox(ctx context.Context, request *runtime.RemovePodSandboxRequest) (*runtime.RemovePodSandboxResponse, error) {
	o.contextErrs = append(o.contextErrs, ctx.Err())
	o.calls = append(o.calls, "remove:"+request.GetPodSandboxId())
	return &runtime.RemovePodSandboxResponse{}, nil
}

func (o *restoreOperationsStub) saveContainerTaskCheckpoint(containerID, image string) error {
	o.calls = append(o.calls, "save:"+containerID)
	if o.saveErr != nil {
		return o.saveErr
	}
	if o.saved == nil {
		o.saved = make(map[string]string)
	}
	o.saved[containerID] = image
	return nil
}

func (o *restoreOperationsStub) deleteTaskCheckpoint(_ context.Context, image string) error {
	o.calls = append(o.calls, "delete:"+image)
	o.deleted = append(o.deleted, image)
	return nil
}

func (o *restoreOperationsStub) publishRestoredSandbox(ctx context.Context, sandboxID string) error {
	o.restoreContexts = append(o.restoreContexts, isPodRestore(ctx))
	o.calls = append(o.calls, "publish:"+sandboxID)
	return o.publishErr
}

func TestRestorePodResourcesKeepsSequencingInCRI(t *testing.T) {
	request := restoreTransactionRequest()
	options, err := restoreOptionsFromCRI(request)
	require.NoError(t, err)
	operations := &restoreOperationsStub{containerIDs: []string{"new-app", "new-sidecar"}}
	controller := &checkpointControllerStub{
		restore: func(_ context.Context, sandboxID string, options sandbox.RestoreOptions) (sandbox.RestoreResult, error) {
			operations.calls = append(operations.calls, "controller:"+sandboxID)
			assert.Equal(t, "new-app", options.Containers[0].ID)
			assert.Equal(t, "new-sidecar", options.Containers[1].ID)
			return sandbox.RestoreResult{
				RestoredContainers: []sandbox.RestoredContainer{
					{Name: "app", TaskCheckpointImage: "localhost/checkpoint:app"},
					{Name: "sidecar"},
				},
			}, nil
		},
	}

	response, err := restorePodResources(context.Background(), request, options, controller, operations)
	require.NoError(t, err)
	assert.Equal(t, "new-sandbox", response.GetPodSandboxId())
	require.Len(t, response.GetRestoredContainers(), 2)
	assert.Equal(t, "new-app", response.GetRestoredContainers()[0].GetContainerId())
	assert.Equal(t, map[string]string{"new-app": "localhost/checkpoint:app"}, operations.saved)
	assert.Equal(t, []string{
		"run:vm-runtime",
		"create:app",
		"create:sidecar",
		"controller:new-sandbox",
		"save:new-app",
		"publish:new-sandbox",
	}, operations.calls)
	assert.Equal(t, []bool{true, true, true, true}, operations.restoreContexts)
}

func TestRestorePodResourcesUsesConsistentClonedRestoreConfig(t *testing.T) {
	request := restoreTransactionRequest()
	request.Config.Annotations = map[string]string{"example.test/preserved": "true"}
	options, err := restoreOptionsFromCRI(request)
	require.NoError(t, err)
	operations := &restoreOperationsStub{
		containerIDs: []string{"new-app", "new-sidecar"},
	}
	controller := &checkpointControllerStub{
		restore: func(_ context.Context, _ string, options sandbox.RestoreOptions) (sandbox.RestoreResult, error) {
			config := new(runtime.PodSandboxConfig)
			require.NoError(t, typeurl.UnmarshalTo(options.SandboxConfig, config))
			assert.Equal(t, "true", config.GetAnnotations()["example.test/preserved"])
			assert.Equal(t, "true", config.GetAnnotations()[restoreAnnotation])
			return sandbox.RestoreResult{
				RestoredContainers: []sandbox.RestoredContainer{{Name: "app"}, {Name: "sidecar"}},
			}, nil
		},
	}

	_, err = restorePodResources(context.Background(), request, options, controller, operations)
	require.NoError(t, err)
	require.NotNil(t, operations.runRequest)
	assert.Equal(t, "true", operations.runRequest.GetConfig().GetAnnotations()[restoreAnnotation])
	assert.Equal(t, "true", request.GetConfig().GetAnnotations()["example.test/preserved"])
	_, requestHasRestoreAnnotation := request.GetConfig().GetAnnotations()[restoreAnnotation]
	assert.False(t, requestHasRestoreAnnotation)
	require.Len(t, operations.createSandboxConfigs, 2)
	for _, config := range operations.createSandboxConfigs {
		assert.Same(t, operations.runRequest.GetConfig(), config)
	}
	assert.Equal(t, []bool{true, true, true, true}, operations.restoreContexts)
}

func TestRestorePodResourcesRollsBackControllerArtifacts(t *testing.T) {
	request := restoreTransactionRequest()
	request.ContainerConfigs = request.ContainerConfigs[:1]
	options, err := restoreOptionsFromCRI(request)
	require.NoError(t, err)
	operations := &restoreOperationsStub{containerIDs: []string{"new-app"}}
	controller := &checkpointControllerStub{
		restore: func(_ context.Context, _ string, _ sandbox.RestoreOptions) (sandbox.RestoreResult, error) {
			return sandbox.RestoreResult{
				RestoredContainers: []sandbox.RestoredContainer{{
					Name:                "unexpected",
					TaskCheckpointImage: "localhost/checkpoint:prepared",
				}},
			}, nil
		},
	}

	_, err = restorePodResources(context.Background(), request, options, controller, operations)
	require.ErrorContains(t, err, "unexpected container")
	assert.Equal(t, []string{
		"run:vm-runtime",
		"create:app",
		"delete:localhost/checkpoint:prepared",
		"remove:new-sandbox",
	}, operations.calls)
}

func TestRestorePodResourcesCleansTransferredTaskCheckpoint(t *testing.T) {
	request := restoreTransactionRequest()
	request.ContainerConfigs = request.ContainerConfigs[:1]
	options, err := restoreOptionsFromCRI(request)
	require.NoError(t, err)
	operations := &restoreOperationsStub{
		containerIDs: []string{"new-app"},
		saveErr:      errors.New("save failed"),
	}
	controller := &checkpointControllerStub{
		restore: func(_ context.Context, _ string, _ sandbox.RestoreOptions) (sandbox.RestoreResult, error) {
			return sandbox.RestoreResult{
				RestoredContainers: []sandbox.RestoredContainer{{
					Name:                "app",
					TaskCheckpointImage: "localhost/checkpoint:prepared",
				}},
			}, nil
		},
	}

	_, err = restorePodResources(context.Background(), request, options, controller, operations)
	require.ErrorContains(t, err, "save failed")
	assert.Equal(t, []string{
		"run:vm-runtime",
		"create:app",
		"save:new-app",
		"delete:localhost/checkpoint:prepared",
		"remove:new-sandbox",
	}, operations.calls)
}

func TestRestorePodResourcesRollsBackPublishFailure(t *testing.T) {
	request := restoreTransactionRequest()
	request.ContainerConfigs = request.ContainerConfigs[:1]
	options, err := restoreOptionsFromCRI(request)
	require.NoError(t, err)
	operations := &restoreOperationsStub{
		containerIDs: []string{"new-app"},
		publishErr:   errors.New("publish failed"),
	}
	controller := &checkpointControllerStub{
		restore: func(context.Context, string, sandbox.RestoreOptions) (sandbox.RestoreResult, error) {
			return sandbox.RestoreResult{
				RestoredContainers: []sandbox.RestoredContainer{{Name: "app"}},
			}, nil
		},
	}

	_, err = restorePodResources(context.Background(), request, options, controller, operations)
	require.ErrorContains(t, err, "publish failed")
	assert.Equal(t, []string{
		"run:vm-runtime",
		"create:app",
		"publish:new-sandbox",
		"remove:new-sandbox",
	}, operations.calls)
}

func TestPublishRestoredSandbox(t *testing.T) {
	createdAt := time.Now().UTC()
	stored := sandbox.Sandbox{ID: "sandbox-1"}
	require.NoError(t, stored.AddExtension(podsandbox.MetadataKey, &sandboxstore.Metadata{
		ID: "sandbox-1",
		Config: &runtime.PodSandboxConfig{Annotations: map[string]string{
			restoreAnnotation:       "true",
			"example.test/retained": "true",
		}, Linux: &runtime.LinuxPodSandboxConfig{
			SecurityContext: &runtime.LinuxSandboxSecurityContext{
				NamespaceOptions: &runtime.NamespaceOption{Network: runtime.NamespaceMode_NODE},
			},
		}},
	}))
	metadataStore := &restoreMetadataSandboxStore{stored: stored}
	cri := newTestCRIService(func(service *criService) {
		client, err := containerd.New("", containerd.WithServices(containerd.WithSandboxStore(metadataStore)))
		require.NoError(t, err)
		service.client = client
	})
	cri.containerEventsQ = eventq.New[*runtime.ContainerEventResponse](time.Minute, func(*runtime.ContainerEventResponse) {})
	t.Cleanup(cri.containerEventsQ.Shutdown)
	events, eventsCloser := cri.containerEventsQ.Subscribe()
	t.Cleanup(func() { require.NoError(t, eventsCloser.Close()) })
	cri.sandboxService = &checkpointSandboxService{
		controllerStatus: sandbox.ControllerStatus{
			SandboxID: "sandbox-1",
			Pid:       42,
			State:     runtime.PodSandboxState_SANDBOX_READY.String(),
			CreatedAt: createdAt,
		},
	}
	sb := sandboxstore.NewSandbox(
		sandboxstore.Metadata{
			ID: "sandbox-1",
			Config: &runtime.PodSandboxConfig{
				Annotations: map[string]string{restoreAnnotation: "true"},
				Linux: &runtime.LinuxPodSandboxConfig{
					SecurityContext: &runtime.LinuxSandboxSecurityContext{
						NamespaceOptions: &runtime.NamespaceOption{Network: runtime.NamespaceMode_NODE},
					},
				},
			},
		},
		sandboxstore.Status{State: sandboxstore.StateUnknown},
	)
	sb.Sandboxer = "shim"
	require.NoError(t, cri.sandboxStore.Add(sb))

	require.NoError(t, cri.publishRestoredSandbox(context.Background(), sb.ID))
	status := sb.Status.Get()
	assert.Equal(t, sandboxstore.StateReady, status.State)
	assert.Equal(t, uint32(42), status.Pid)
	assert.Equal(t, createdAt, status.CreatedAt)
	require.NotNil(t, metadataStore.updated)
	persisted := sandboxstore.Metadata{}
	require.NoError(t, metadataStore.updated.GetExtension(podsandbox.MetadataKey, &persisted))
	_, hasRestoreAnnotation := persisted.Config.GetAnnotations()[restoreAnnotation]
	assert.False(t, hasRestoreAnnotation)
	assert.Equal(t, "true", persisted.Config.GetAnnotations()["example.test/retained"])
	live, err := cri.sandboxStore.Get(sb.ID)
	require.NoError(t, err)
	_, hasRestoreAnnotation = live.Config.GetAnnotations()[restoreAnnotation]
	assert.False(t, hasRestoreAnnotation)
	select {
	case event := <-events:
		assert.Equal(t, runtime.ContainerEventType_CONTAINER_STARTED_EVENT, event.GetContainerEventType())
		assert.Equal(t, sb.ID, event.GetContainerId())
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for restored sandbox STARTED event")
	}
}

func TestPublishRestoredSandboxRejectsExitedSandbox(t *testing.T) {
	cri := newTestCRIService()
	cri.sandboxService = &checkpointSandboxService{
		controllerStatus: sandbox.ControllerStatus{
			SandboxID: "sandbox-1",
			State:     runtime.PodSandboxState_SANDBOX_READY.String(),
		},
	}
	sb := sandboxstore.NewSandbox(
		sandboxstore.Metadata{
			ID: "sandbox-1",
			Config: &runtime.PodSandboxConfig{Annotations: map[string]string{
				restoreAnnotation: "true",
			}},
		},
		sandboxstore.Status{State: sandboxstore.StateNotReady},
	)
	sb.Sandboxer = "shim"
	require.NoError(t, cri.sandboxStore.Add(sb))

	err := cri.publishRestoredSandbox(context.Background(), sb.ID)
	require.ErrorContains(t, err, "cannot be published")
	assert.Equal(t, sandboxstore.StateNotReady, sb.Status.Get().State)
	assert.False(t, sandboxRestoreInProgress(sb))
	assert.True(t, sandboxRestorePending(sb))
}

func TestPublishRestoredSandboxRejectsExitDuringCommit(t *testing.T) {
	stored := sandbox.Sandbox{ID: "sandbox-1"}
	require.NoError(t, stored.AddExtension(podsandbox.MetadataKey, &sandboxstore.Metadata{
		ID: "sandbox-1",
		Config: &runtime.PodSandboxConfig{Annotations: map[string]string{
			restoreAnnotation: "true",
		}},
	}))
	metadataStore := &restoreMetadataSandboxStore{stored: stored}
	cri := newTestCRIService(func(service *criService) {
		client, err := containerd.New("", containerd.WithServices(containerd.WithSandboxStore(metadataStore)))
		require.NoError(t, err)
		service.client = client
	})
	cri.sandboxService = &checkpointSandboxService{
		controllerStatus: sandbox.ControllerStatus{
			SandboxID: "sandbox-1",
			State:     runtime.PodSandboxState_SANDBOX_READY.String(),
		},
	}
	sb := sandboxstore.NewSandbox(
		sandboxstore.Metadata{
			ID: "sandbox-1",
			Config: &runtime.PodSandboxConfig{Annotations: map[string]string{
				restoreAnnotation: "true",
			}},
		},
		sandboxstore.Status{State: sandboxstore.StateUnknown},
	)
	sb.Sandboxer = "shim"
	require.NoError(t, cri.sandboxStore.Add(sb))
	metadataStore.onUpdate = func() {
		require.NoError(t, sb.Status.Update(func(status sandboxstore.Status) (sandboxstore.Status, error) {
			status.State = sandboxstore.StateNotReady
			return status, nil
		}))
	}

	err := cri.publishRestoredSandbox(context.Background(), sb.ID)
	require.ErrorContains(t, err, "cannot be published")
	assert.Equal(t, sandboxstore.StateNotReady, sb.Status.Get().State)
}

type restoreMetadataSandboxStore struct {
	sandbox.Store
	stored   sandbox.Sandbox
	updated  *sandbox.Sandbox
	onUpdate func()
}

func (s *restoreMetadataSandboxStore) Get(context.Context, string) (sandbox.Sandbox, error) {
	return s.stored, nil
}

func (s *restoreMetadataSandboxStore) Update(_ context.Context, stored sandbox.Sandbox, _ ...string) (sandbox.Sandbox, error) {
	s.updated = &stored
	if s.onUpdate != nil {
		s.onUpdate()
	}
	return stored, nil
}

func TestRestorePodResourcesRollsBackCreateFailure(t *testing.T) {
	request := restoreTransactionRequest()
	options, err := restoreOptionsFromCRI(request)
	require.NoError(t, err)
	operations := &restoreOperationsStub{
		containerIDs: []string{"new-app", "new-sidecar"},
		createErrAt:  2,
	}
	controller := &checkpointControllerStub{
		restore: func(context.Context, string, sandbox.RestoreOptions) (sandbox.RestoreResult, error) {
			return sandbox.RestoreResult{}, fmt.Errorf("controller must not be called")
		},
	}

	_, err = restorePodResources(context.Background(), request, options, controller, operations)
	require.ErrorContains(t, err, "create failed")
	assert.Equal(t, []string{
		"run:vm-runtime",
		"create:app",
		"create:sidecar",
		"remove:new-sandbox",
	}, operations.calls)
}

func restoreTransactionRequest() *runtime.RestorePodRequest {
	return &runtime.RestorePodRequest{
		CheckpointPath: "/checkpoint",
		RuntimeHandler: "vm-runtime",
		Config: &runtime.PodSandboxConfig{
			Metadata: &runtime.PodSandboxMetadata{Name: "pod", Namespace: "default", Uid: "new-uid"},
		},
		ContainerConfigs: []*runtime.ContainerConfig{
			{
				Metadata: &runtime.ContainerMetadata{Name: "app"},
				Image:    &runtime.ImageSpec{Image: "example/app:latest"},
			},
			{
				Metadata: &runtime.ContainerMetadata{Name: "sidecar"},
				Image:    &runtime.ImageSpec{Image: "example/sidecar:latest"},
			},
		},
	}
}

func TestPodCheckpointRequestsRequireDeadline(t *testing.T) {
	require.ErrorContains(t, requirePodCheckpointDeadline(context.Background(), "pod checkpoint"), "finite context deadline")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ctx, deadlineCancel := context.WithTimeout(ctx, time.Second)
	defer deadlineCancel()
	require.ErrorIs(t, requirePodCheckpointDeadline(ctx, "pod checkpoint"), context.Canceled)
}

func TestPodCheckpointAPIsRequireRuntimeSupport(t *testing.T) {
	cri := newTestCRIService()
	cri.podCheckpointSupportCheck = func() error {
		return errors.New("CRIU unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := cri.CheckpointPod(ctx, &runtime.CheckpointPodRequest{PodSandboxId: "sandbox"})
	require.ErrorContains(t, err, "pod checkpoint is unavailable")
	require.ErrorContains(t, err, "CRIU unavailable")

	_, err = cri.RestorePod(ctx, &runtime.RestorePodRequest{})
	require.ErrorContains(t, err, "pod restore is unavailable")
	require.ErrorContains(t, err, "CRIU unavailable")
}

func TestCheckpointControllerCapability(t *testing.T) {
	cri := newTestCRIService()
	service := &checkpointSandboxService{controller: &fakeSandboxController{}}
	cri.sandboxService = service

	_, err := cri.checkpointController("vm-runtime", "restore")
	require.ErrorIs(t, err, errdefs.ErrNotImplemented)
	assert.Equal(t, "vm-runtime", service.sandboxer)
}

func TestReserveContainerCheckpoints(t *testing.T) {
	cri := newTestCRIService()
	release, err := cri.reserveContainerCheckpoints([]string{"container-a", "container-b"})
	require.NoError(t, err)

	_, err = cri.reserveContainerCheckpoints([]string{"container-b"})
	require.ErrorContains(t, err, "already in progress")

	release()
	releaseAgain, err := cri.reserveContainerCheckpoints([]string{"container-b"})
	require.NoError(t, err)
	releaseAgain()
}
