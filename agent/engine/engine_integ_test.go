// +build integration
// Copyright 2014-2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//	http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package engine

import (
	"context"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/amazon-ecs-agent/agent/api"
	"github.com/aws/amazon-ecs-agent/agent/config"
	"github.com/aws/amazon-ecs-agent/agent/credentials"
	"github.com/aws/amazon-ecs-agent/agent/ec2"
	"github.com/aws/amazon-ecs-agent/agent/engine/dockerclient"
	"github.com/aws/amazon-ecs-agent/agent/engine/dockerstate"
	"github.com/aws/amazon-ecs-agent/agent/eventstream"
	"github.com/stretchr/testify/assert"
)

const testDockerStopTimeout = 2 * time.Second

func createTestTask(arn string) *api.Task {
	return &api.Task{
		Arn:           arn,
		Family:        arn,
		Version:       "1",
		DesiredStatus: api.TaskRunning,
		Containers:    []*api.Container{createTestContainer()},
	}
}

func defaultTestConfigIntegTest() *config.Config {
	cfg, _ := config.NewConfig(ec2.NewBlackholeEC2MetadataClient())
	return cfg
}

func setupWithDefaultConfig(t *testing.T) (TaskEngine, func(), credentials.Manager) {
	return setup(defaultTestConfigIntegTest(), t)
}

func setup(cfg *config.Config, t *testing.T) (TaskEngine, func(), credentials.Manager) {
	if os.Getenv("ECS_SKIP_ENGINE_INTEG_TEST") != "" {
		t.Skip("ECS_SKIP_ENGINE_INTEG_TEST")
	}
	if !isDockerRunning() {
		t.Skip("Docker not running")
	}
	clientFactory := dockerclient.NewFactory(dockerEndpoint)
	dockerClient, err := NewDockerGoClient(clientFactory, false, cfg)
	if err != nil {
		t.Fatalf("Error creating Docker client: %v", err)
	}
	credentialsManager := credentials.NewManager()
	state := dockerstate.NewDockerTaskEngineState()
	imageManager := NewImageManager(cfg, dockerClient, state)
	taskEngine := NewDockerTaskEngine(cfg, dockerClient, credentialsManager,
		eventstream.NewEventStream("ENGINEINTEGTEST", context.Background()), imageManager, state)
	taskEngine.Init()
	return taskEngine, func() {
		taskEngine.Shutdown()
	}, credentialsManager
}

func discardEvents(from interface{}) func() {
	done := make(chan bool)

	go func() {
		for {
			ndx, _, _ := reflect.Select([]reflect.SelectCase{
				reflect.SelectCase{
					Dir:  reflect.SelectRecv,
					Chan: reflect.ValueOf(from),
				},
				reflect.SelectCase{
					Dir:  reflect.SelectRecv,
					Chan: reflect.ValueOf(done),
				},
			})
			if ndx == 1 {
				break
			}
		}
	}()
	return func() {
		done <- true
	}
}

func TestHostVolumeMount(t *testing.T) {
	taskEngine, done, _ := setupWithDefaultConfig(t)
	defer done()

	taskEvents, contEvents := taskEngine.TaskEvents()

	defer discardEvents(contEvents)()

	tmpPath, _ := ioutil.TempDir("", "ecs_volume_test")
	defer os.RemoveAll(tmpPath)
	ioutil.WriteFile(filepath.Join(tmpPath, "test-file"), []byte("test-data"), 0644)

	testTask := createTestHostVolumeMountTask(tmpPath)

	go taskEngine.AddTask(testTask)

	verifyTaskIsStopped(taskEvents, testTask)

	assert.NotNil(t, testTask.Containers[0].KnownExitCode, "No exit code found")
	assert.Equal(t, 42, *testTask.Containers[0].KnownExitCode, "Wrong exit code")

	data, err := ioutil.ReadFile(filepath.Join(tmpPath, "hello-from-container"))
	assert.Nil(t, err, "Unexpected error")
	assert.Equal(t, "hi", strings.TrimSpace(string(data)), "Incorrect file contents")
}

func verifyTaskIsRunning(taskEvents <-chan api.TaskStateChange, testTask *api.Task) error {
	for {
		select {
		case taskEvent := <-taskEvents:
			if taskEvent.TaskArn != testTask.Arn {
				continue
			}
			if taskEvent.Status == api.TaskRunning {
				return nil
			} else if taskEvent.Status > api.TaskRunning {
				return errors.New("Task went straight to " + taskEvent.Status.String() + " without running")
			}
		}
	}
}

func verifyTaskIsStopped(taskEvents <-chan api.TaskStateChange, testTask *api.Task) {
	for {
		select {
		case taskEvent := <-taskEvents:
			if taskEvent.TaskArn != testTask.Arn {
				continue
			}
			if taskEvent.Status >= api.TaskStopped {
				return
			}
		}
	}
}
