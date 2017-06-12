package engine

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	"github.com/aws/amazon-ecs-agent/agent/api"
	"github.com/aws/amazon-ecs-agent/agent/config"
	"github.com/aws/amazon-ecs-agent/agent/ecr"
	"github.com/aws/amazon-ecs-agent/agent/engine/dockerauth"
	"github.com/aws/amazon-ecs-agent/agent/engine/dockerclient"

	"github.com/cihub/seelog"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/remotes"
	dockerresolver "github.com/containerd/containerd/remotes/docker"
	docker "github.com/fsouza/go-dockerclient"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
)

/*
 Notes:
 * The DockerClient interface isn't super clean. We should generalize the interface a bit more.
 * Auth data for pull is handled explicitly in dockerGoClient, but should really be injected by the caller.
 * Most of the methods take a timeout parameter, but should really take a context (with a deadline)
*/

type unimplementedError struct {
	error
}

func (unimplementedError) ErrorName() string {
	return "unimplemented"
}

var unimplemented = unimplementedError{errors.New("unimplemented")}

const (
	ecsNamespace = "ecs-test"
)

func NewContainerdClient(cfg *config.Config) (DockerClient, error) {
	client, err := containerd.New("/run/containerd/containerd.sock")
	if err != nil {
		return nil, err
	}
	version, err := client.Version(context.TODO())
	if err != nil {
		return nil, err
	}
	seelog.Debugf("CONTAINERD VERSION %s %s", version.Version, version.Revision)

	var dockerAuthData json.RawMessage
	if cfg.EngineAuthData != nil {
		dockerAuthData = cfg.EngineAuthData.Contents()
	}

	return &containerdClient{
		client:           client,
		ecrClientFactory: ecr.NewECRFactory(cfg.AcceptInsecureCert),
		auth:             dockerauth.NewDockerAuthProvider(cfg.EngineAuthType, dockerAuthData),
		config:           cfg,
	}, nil
}

// containerdClient implements DockerClient interface
type containerdClient struct {
	client *containerd.Client

	// TODO shouldn't have ecrClientFactory + auth here, should be injected during pull
	ecrClientFactory ecr.ECRFactory
	auth             dockerauth.DockerAuthProvider
	config           *config.Config
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
	ref := imageToRef(image)
	authConfig, err := c.getAuthdata(image, authData)
	if err != nil {
		return DockerContainerMetadata{Error: CannotPullContainerError{err}}
	}
	resolver, err := c.getResolver(ctx, authConfig)
	if err != nil {
		return DockerContainerMetadata{Error: CannotPullContainerError{err}}
	}
	seelog.Debugf("Pulling %s.  No progress will be shown.", ref)
	pullResponse, err := c.client.Pull(ctx, ref, containerd.WithResolver(resolver), containerd.WithPullUnpack)
	if err != nil {
		return DockerContainerMetadata{Error: CannotPullContainerError{err}}
	}
	seelog.Debug("Pulled", pullResponse)
	// 2017-06-07T04:32:26Z [DEBUG] Pulled&{0xc4201d4520 {docker.io/library/redis:alpine {application/vnd.docker.distribution.manifest.v2+json sha256:03789f402b2ecfb98184bf128d180f398f81c63364948ff1454583b02442f73b 1568 [] map[] <nil>}}}

	return DockerContainerMetadata{}
}

// imageToRef is a super simple set of rules to try and find a ref from a Docker-style image name
func imageToRef(image string) string {
	httpsPrefix := "https://"
	if strings.HasPrefix(image, httpsPrefix) {
		image = image[len(httpsPrefix):]
	}

	repo, tag := parseRepositoryTag(image)
	if tag == "" {
		image += ":" + dockerDefaultTag
	}

	if ok := strings.Contains(repo, "/"); !ok {
		// no slash, looks like it's a library image
		return "docker.io/library/" + image
	}
	parts := strings.SplitN(repo, "/", 2)
	ok := strings.Contains(parts[0], ".")
	if !ok {
		// no . in part before /, looks like it's on Docker Hub
		return "docker.io/" + image
	}
	// if the first part has a . and there is a /, looks like it's a fully-qualified ref?
	return image
}

// getResolver prepares the resolver from the environment and options.
func (c *containerdClient) getResolver(ctx context.Context, authConfig docker.AuthConfiguration) (remotes.Resolver, error) {
	username := authConfig.Username
	secret := authConfig.Password
	options := dockerresolver.ResolverOptions{}

	options.Credentials = func(host string) (string, string, error) {
		// Only one host
		return username, secret, nil
	}

	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: c.config.AcceptInsecureCert,
		},
		ExpectContinueTimeout: 5 * time.Second,
	}

	options.Client = &http.Client{
		Transport: tr,
	}

	return dockerresolver.NewResolver(options), nil
}

func (c *containerdClient) getAuthdata(image string, authData *api.RegistryAuthenticationData) (docker.AuthConfiguration, error) {
	if authData == nil || authData.Type != "ecr" {
		return c.auth.GetAuthconfig(image)
	}
	provider := dockerauth.NewECRAuthProvider(authData.ECRAuthData, c.ecrClientFactory)
	authConfig, err := provider.GetAuthconfig(image)
	if err != nil {
		return authConfig, CannotPullECRContainerError{err}
	}
	return authConfig, nil
}

func (c *containerdClient) CreateContainer(dockerConfig *docker.Config, dockerHostConfig *docker.HostConfig, name string, timeout time.Duration) DockerContainerMetadata {
	ctx := namespaces.WithNamespace(context.TODO(), ecsNamespace)
	image, err := c.client.GetImage(ctx, imageToRef(dockerConfig.Image))
	if err != nil {
		wrapped := errors.Wrapf(err, "containerd create: failed to resolve image %s", image)
		return DockerContainerMetadata{Error: CannotCreateContainerError{wrapped}}
	}
	opts := []containerd.SpecOpts{
		containerd.WithImageConfig(ctx, image),
		// env
		// mounts
		containerd.WithProcessArgs("/bin/sh", "-c", "echo '**********hello'; sleep 600; echo '**********bye'"),
	}
	spec, err := containerd.GenerateSpec(opts...)
	if err != nil {
		wrapped := errors.Wrap(err, "containerd create: failed to generate spec")
		return DockerContainerMetadata{Error: CannotCreateContainerError{wrapped}}
	}
	id := name
	container, err := c.client.NewContainer(ctx, id, containerd.WithSpec(spec), containerd.WithNewRootFS(id, image), containerd.WithImage(image))
	if err != nil {
		wrapped := errors.Wrap(err, "containerd create: failed to create container")
		return DockerContainerMetadata{Error: CannotCreateContainerError{wrapped}}
	}
	seelog.Debugf("created container with id %s", container.ID())

	return DockerContainerMetadata{DockerID: container.ID()}
}
func (c *containerdClient) StartContainer(name string, timeout time.Duration) DockerContainerMetadata {
	ctx := namespaces.WithNamespace(context.TODO(), ecsNamespace)
	id := name
	container, err := c.client.LoadContainer(ctx, id)
	if err != nil {
		seelog.Error(err)
		wrapped := errors.Wrapf(err, "containerd start: failed to get container with id %s", id)
		return DockerContainerMetadata{Error: CannotStartContainerError{wrapped}}
	}
	task, err := container.NewTask(ctx, containerd.Stdio)
	if err != nil {
		seelog.Error(err)
		wrapped := errors.Wrapf(err, "containerd start: failed to create task for container with id %s", id)
		return DockerContainerMetadata{Error: CannotStartContainerError{wrapped}}
	}
	err = task.CloseIO(ctx, containerd.WithStdinCloser)
	if err != nil {
		seelog.Error(err)
		return DockerContainerMetadata{Error: CannotStartContainerError{err}}
	}
	err = task.Start(ctx)
	if err != nil {
		seelog.Error(err)
		wrapped := errors.Wrapf(err, "containerd start: failed to start task for container with id %s", id)
		return DockerContainerMetadata{Error: CannotStartContainerError{wrapped}}
	}

	return DockerContainerMetadata{DockerID: container.ID()}
}
func (c *containerdClient) StopContainer(name string, timeout time.Duration) DockerContainerMetadata {
	ctx := namespaces.WithNamespace(context.TODO(), ecsNamespace)
	id := name
	container, err := c.client.LoadContainer(ctx, id)
	if err != nil {
		seelog.Error(err)
		wrapped := errors.Wrapf(err, "containerd stop: failed to get container with id %s", id)
		return DockerContainerMetadata{Error: CannotStopContainerError{wrapped}}
	}
	task, err := container.Task(ctx, nil)
	if err != nil {
		seelog.Error(err)
		wrapped := errors.Wrapf(err, "containerd stop: failed to get task for container with id %s", id)
		return DockerContainerMetadata{Error: CannotStopContainerError{wrapped}}
	}

	err = task.Kill(ctx, syscall.SIGKILL)
	if err != nil {
		seelog.Error(err)
		wrapped := errors.Wrapf(err, "containerd stop: failed to kill task for container with id %s", id)
		return DockerContainerMetadata{Error: CannotStopContainerError{wrapped}}
	}

	status, err := task.Delete(ctx)
	if err != nil {
		seelog.Error(err)
		wrapped := errors.Wrapf(err, "containerd stop: failed to delete task for container with id %s", id)
		return DockerContainerMetadata{Error: CannotStopContainerError{wrapped}}
	}

	exitCode := int(status)
	return DockerContainerMetadata{DockerID: id, ExitCode: &exitCode}
}
func (c *containerdClient) DescribeContainer(id string) (api.ContainerStatus, DockerContainerMetadata) {
	dockerContainer, err := c.InspectContainer(id, inspectContainerTimeout)
	if err != nil {
		return api.ContainerStatusNone, DockerContainerMetadata{Error: CannotDescribeContainerError{err}}
	}
	return dockerStateToState(dockerContainer.State), metadataFromContainer(dockerContainer)
}

func (c *containerdClient) InspectContainer(id string, timeout time.Duration) (*docker.Container, error) {
	ctx := namespaces.WithNamespace(context.TODO(), ecsNamespace)
	container, err := c.client.LoadContainer(ctx, id)
	if err != nil {
		seelog.Error(err)
		return nil, errors.Wrapf(err, "containerd inspect: failed to get container with id %s", id)

	}
	task, err := container.Task(ctx, nil)
	if err != nil && err != containerd.ErrNoRunningTask {
		seelog.Error(err)
		return nil, errors.Wrapf(err, "containerd inspect: failed to get task for container with id %s", id)
	}

	state := docker.State{}
	if err == containerd.ErrNoRunningTask {
		state.Status = string(containerd.Stopped)
		state.Running = false
	} else {
		s, _ := task.Status(ctx) // TODO
		state.Status = string(s)
		switch s {
		case containerd.Running:
			state.Running = true
		case containerd.Stopped:
			state.Running = false
			// TODO get exit code
		}
	}

	dockerContainer := &docker.Container{
		ID:    container.ID(),
		State: state,
	}
	return dockerContainer, unimplemented
}

func (c *containerdClient) RemoveContainer(name string, timeout time.Duration) error {
	ctx := namespaces.WithNamespace(context.TODO(), ecsNamespace)
	id := name
	container, err := c.client.LoadContainer(ctx, id)
	if err != nil {
		seelog.Error(err)
		return errors.Wrapf(err, "containerd remove: failed to get container with id %s", id)
	}

	err = container.Delete(ctx)
	if err != nil {
		seelog.Error(err)
		return errors.Wrapf(err, "containerd stop: failed to delete container with id %s", id)
	}
	return unimplemented
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
