// Copyright 2015-2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

// Automatically generated by MockGen. DO NOT EDIT!
// Source: github.com/aws/amazon-ecs-agent/agent/engine/dockeriface (interfaces: Client)

package mock_dockeriface

import (
	go_dockerclient "github.com/fsouza/go-dockerclient"
	gomock "github.com/golang/mock/gomock"
	context "golang.org/x/net/context"
)

// Mock of Client interface
type MockClient struct {
	ctrl     *gomock.Controller
	recorder *_MockClientRecorder
}

// Recorder for MockClient (not exported)
type _MockClientRecorder struct {
	mock *MockClient
}

func NewMockClient(ctrl *gomock.Controller) *MockClient {
	mock := &MockClient{ctrl: ctrl}
	mock.recorder = &_MockClientRecorder{mock}
	return mock
}

func (_m *MockClient) EXPECT() *_MockClientRecorder {
	return _m.recorder
}

func (_m *MockClient) AddEventListener(_param0 chan<- *go_dockerclient.APIEvents) error {
	ret := _m.ctrl.Call(_m, "AddEventListener", _param0)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockClientRecorder) AddEventListener(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "AddEventListener", arg0)
}

func (_m *MockClient) CreateContainer(_param0 go_dockerclient.CreateContainerOptions) (*go_dockerclient.Container, error) {
	ret := _m.ctrl.Call(_m, "CreateContainer", _param0)
	ret0, _ := ret[0].(*go_dockerclient.Container)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockClientRecorder) CreateContainer(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "CreateContainer", arg0)
}

func (_m *MockClient) ImportImage(_param0 go_dockerclient.ImportImageOptions) error {
	ret := _m.ctrl.Call(_m, "ImportImage", _param0)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockClientRecorder) ImportImage(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "ImportImage", arg0)
}

func (_m *MockClient) InspectContainer(_param0 string) (*go_dockerclient.Container, error) {
	ret := _m.ctrl.Call(_m, "InspectContainer", _param0)
	ret0, _ := ret[0].(*go_dockerclient.Container)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockClientRecorder) InspectContainer(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "InspectContainer", arg0)
}

func (_m *MockClient) InspectContainerWithContext(_param0 string, _param1 context.Context) (*go_dockerclient.Container, error) {
	ret := _m.ctrl.Call(_m, "InspectContainerWithContext", _param0, _param1)
	ret0, _ := ret[0].(*go_dockerclient.Container)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockClientRecorder) InspectContainerWithContext(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "InspectContainerWithContext", arg0, arg1)
}

func (_m *MockClient) InspectImage(_param0 string) (*go_dockerclient.Image, error) {
	ret := _m.ctrl.Call(_m, "InspectImage", _param0)
	ret0, _ := ret[0].(*go_dockerclient.Image)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockClientRecorder) InspectImage(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "InspectImage", arg0)
}

func (_m *MockClient) ListContainers(_param0 go_dockerclient.ListContainersOptions) ([]go_dockerclient.APIContainers, error) {
	ret := _m.ctrl.Call(_m, "ListContainers", _param0)
	ret0, _ := ret[0].([]go_dockerclient.APIContainers)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockClientRecorder) ListContainers(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "ListContainers", arg0)
}

func (_m *MockClient) Ping() error {
	ret := _m.ctrl.Call(_m, "Ping")
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockClientRecorder) Ping() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Ping")
}

func (_m *MockClient) PullImage(_param0 go_dockerclient.PullImageOptions, _param1 go_dockerclient.AuthConfiguration) error {
	ret := _m.ctrl.Call(_m, "PullImage", _param0, _param1)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockClientRecorder) PullImage(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "PullImage", arg0, arg1)
}

func (_m *MockClient) RemoveContainer(_param0 go_dockerclient.RemoveContainerOptions) error {
	ret := _m.ctrl.Call(_m, "RemoveContainer", _param0)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockClientRecorder) RemoveContainer(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "RemoveContainer", arg0)
}

func (_m *MockClient) RemoveEventListener(_param0 chan *go_dockerclient.APIEvents) error {
	ret := _m.ctrl.Call(_m, "RemoveEventListener", _param0)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockClientRecorder) RemoveEventListener(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "RemoveEventListener", arg0)
}

func (_m *MockClient) RemoveImage(_param0 string) error {
	ret := _m.ctrl.Call(_m, "RemoveImage", _param0)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockClientRecorder) RemoveImage(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "RemoveImage", arg0)
}

func (_m *MockClient) StartContainer(_param0 string, _param1 *go_dockerclient.HostConfig) error {
	ret := _m.ctrl.Call(_m, "StartContainer", _param0, _param1)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockClientRecorder) StartContainer(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "StartContainer", arg0, arg1)
}

func (_m *MockClient) StartContainerWithContext(_param0 string, _param1 *go_dockerclient.HostConfig, _param2 context.Context) error {
	ret := _m.ctrl.Call(_m, "StartContainerWithContext", _param0, _param1, _param2)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockClientRecorder) StartContainerWithContext(arg0, arg1, arg2 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "StartContainerWithContext", arg0, arg1, arg2)
}

func (_m *MockClient) Stats(_param0 go_dockerclient.StatsOptions) error {
	ret := _m.ctrl.Call(_m, "Stats", _param0)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockClientRecorder) Stats(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Stats", arg0)
}

func (_m *MockClient) StopContainer(_param0 string, _param1 uint) error {
	ret := _m.ctrl.Call(_m, "StopContainer", _param0, _param1)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockClientRecorder) StopContainer(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "StopContainer", arg0, arg1)
}

func (_m *MockClient) StopContainerWithContext(_param0 string, _param1 uint, _param2 context.Context) error {
	ret := _m.ctrl.Call(_m, "StopContainerWithContext", _param0, _param1, _param2)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockClientRecorder) StopContainerWithContext(arg0, arg1, arg2 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "StopContainerWithContext", arg0, arg1, arg2)
}

func (_m *MockClient) Version() (*go_dockerclient.Env, error) {
	ret := _m.ctrl.Call(_m, "Version")
	ret0, _ := ret[0].(*go_dockerclient.Env)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockClientRecorder) Version() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Version")
}
