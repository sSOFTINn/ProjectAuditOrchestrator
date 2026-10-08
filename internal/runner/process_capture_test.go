package runner

import "testing"

func TestDockerSafeEnvironmentRemovesDockerOverrides(t *testing.T) {
	values := dockerSafeEnvironment([]string{"PATH=C:\\safe", "DOCKER_HOST=tcp://remote", "docker_context=unsafe", "KEEP=yes"})
	for _, value := range values {
		if value == "DOCKER_HOST=tcp://remote" || value == "docker_context=unsafe" {
			t.Fatalf("unsafe Docker override retained: %q", value)
		}
	}
	if len(values) != 2 {
		t.Fatalf("unexpected environment: %#v", values)
	}
}
