package engine

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestImageToRef(t *testing.T) {
	refTests := []struct {
		Image string
		Ref   string
	}{
		{"busybox", "docker.io/library/busybox:latest"},
		{"busybox:latest", "docker.io/library/busybox:latest"},
		{"busybox@sha256:abcd", "docker.io/library/busybox@sha256:abcd"},
		{"busybox:me@sha256:abcd", "docker.io/library/busybox:me@sha256:abcd"},
		{"amazon/none", "docker.io/amazon/none:latest"},
		{"amazon/none:latest", "docker.io/amazon/none:latest"},
		{"amazon/none@sha256:abcd", "docker.io/amazon/none@sha256:abcd"},
		{"my.registry/image", "my.registry/image:latest"},
		{"my.registry/image:latest", "my.registry/image:latest"},
		{"https://my.registry/image@sha256:abcd", "my.registry/image@sha256:abcd"},
	}
	for _, testCase := range refTests {
		t.Run(testCase.Image, func(t *testing.T) {
			actualRef := imageToRef(testCase.Image)
			assert.Equal(t, testCase.Ref, actualRef)
		})
	}
}
