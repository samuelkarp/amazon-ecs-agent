package engine

import (
	"time"

	"github.com/pkg/errors"

	"golang.org/x/net/context"

	"github.com/aws/amazon-ecs-agent/agent/api"
	"github.com/aws/amazon-ecs-agent/agent/engine/dockerclient"
	"github.com/cihub/seelog"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
	docker "github.com/fsouza/go-dockerclient"
)

type unimplementedError struct {
	error
}

func (unimplementedError) ErrorName() string {
	return "unimplemented"
}

var unimplemented = unimplementedError{errors.New("unimplemented")}

const (
	containerdImage = "docker.io/library/busybox:latest"

	ecsNamespace = "ecs-test"
)

func NewContainerdClient() (DockerClient, error) {
	client, err := containerd.New("/tmp/containerd.sock")
	if err != nil {
		return nil, err
	}
	version, err := client.Version(context.TODO())
	if err != nil {
		return nil, err
	}
	seelog.Debugf("CONTAINERD VERSION %s %s", version.Version, version.Revision)
	return &containerdClient{
		client: client,
	}, nil
}

// containerdClient implements DockerClient interface
type containerdClient struct {
	client *containerd.Client
}

// SupportedVersions returns a slice of the supported docker versions (or at least supposedly supported).
func (c *containerdClient) SupportedVersions() []dockerclient.DockerVersion {
	return nil
}

// WithVersion returns a new DockerClient for which all operations will use the given remote api version.
// A default version will be used for a client not produced via this method.
func (c *containerdClient) WithVersion(dockerclient.DockerVersion) DockerClient {
	return c
}
func (c *containerdClient) ContainerEvents(ctx context.Context) (<-chan DockerContainerChangeEvent, error) {
	neverevereverdata := make(chan DockerContainerChangeEvent)
	return neverevereverdata, nil
}

func (c *containerdClient) PullImage(image string, authData *api.RegistryAuthenticationData) DockerContainerMetadata {
	ctx := namespaces.WithNamespace(context.TODO(), ecsNamespace)
	image = containerdImage // TODO
	seelog.Debugf("Pulling %s.  No progress will be shown.", image)
	pullResponse, err := c.client.Pull(ctx, image, containerd.WithPullUnpack)
	if err != nil {
		return DockerContainerMetadata{Error: CannotPullContainerError{err}}
	}
	seelog.Debug("Pulled", pullResponse)
	// 2017-06-07T04:32:26Z [DEBUG] Pulled&{0xc4201d4520 {docker.io/library/redis:alpine {application/vnd.docker.distribution.manifest.v2+json sha256:03789f402b2ecfb98184bf128d180f398f81c63364948ff1454583b02442f73b 1568 [] map[] <nil>}}}

	return DockerContainerMetadata{}
}

func (c *containerdClient) CreateContainer(dockerConfig *docker.Config, dockerHostConfig *docker.HostConfig, name string, timeout time.Duration) DockerContainerMetadata {
	ctx := namespaces.WithNamespace(context.TODO(), ecsNamespace)
	image, err := c.client.GetImage(ctx, containerdImage) // TODO
	if err != nil {
		wrapped := errors.Wrapf(err, "containerd create: failed to resolve image %s", containerdImage)
		return DockerContainerMetadata{Error: CannotPullContainerError{wrapped}}
	}
	opts := []containerd.SpecOpts{
		containerd.WithImageConfig(ctx, image),
		// env
		// mounts
		containerd.WithProcessArgs("/bin/sleep", "60"),
	}
	spec, err := containerd.GenerateSpec(opts...)
	if err != nil {
		wrapped := errors.Wrap(err, "containerd create: failed to generate spec")
		return DockerContainerMetadata{Error: CannotPullContainerError{wrapped}}
	}
	id := "ecs-test-container"
	rootfs := containerd.WithNewRootFS(id, image)
	container, err := c.client.NewContainer(ctx, id, containerd.WithSpec(spec), containerd.WithImage(image), rootfs)
	if err != nil {
		wrapped := errors.Wrap(err, "containerd create: failed to create container")
		return DockerContainerMetadata{Error: CannotPullContainerError{wrapped}}
	}
	seelog.Debugf("created container with id %s", container.ID())

	return DockerContainerMetadata{DockerID: container.ID()}
}
func (c *containerdClient) StartContainer(string, time.Duration) DockerContainerMetadata {
	return DockerContainerMetadata{Error: unimplemented}
}
func (c *containerdClient) StopContainer(string, time.Duration) DockerContainerMetadata {
	return DockerContainerMetadata{Error: unimplemented}
}
func (c *containerdClient) DescribeContainer(string) (api.ContainerStatus, DockerContainerMetadata) {
	return api.ContainerStatusNone, DockerContainerMetadata{Error: unimplemented}
}
func (c *containerdClient) RemoveContainer(string, time.Duration) error {
	return unimplemented
}

func (c *containerdClient) InspectContainer(string, time.Duration) (*docker.Container, error) {
	return nil, unimplemented
}
func (c *containerdClient) ListContainers(bool, time.Duration) ListContainersResponse {
	return ListContainersResponse{Error: unimplemented}
}
func (c *containerdClient) Stats(string, context.Context) (<-chan *docker.Stats, error) {
	return nil, unimplemented
}

func (c *containerdClient) Version() (string, error) {
	version, err := c.client.Version(context.TODO())
	if err != nil {
		return "", err
	}
	return "containerd-" + version.Version, nil
}
func (c *containerdClient) InspectImage(string) (*docker.Image, error) {
	return nil, unimplemented
}
func (c *containerdClient) RemoveImage(string, time.Duration) error {
	return unimplemented
}
