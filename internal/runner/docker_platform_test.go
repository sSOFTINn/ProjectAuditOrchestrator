package runner

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestDockerConnectionPinsDesktopAndNonRootIdentity(t *testing.T) {
	for _, tc := range []struct {
		platform, home string
		uid, gid       int
		endpoint, user string
	}{
		{"windows", "", -1, -1, dockerDesktopLinuxEndpoint, "65532:65532"},
		{"linux", "/home/alice", 1001, 1002, "unix:///home/alice/.docker/desktop/docker.sock", "1001:1002"},
	} {
		got, err := resolveDockerConnection(tc.platform, tc.home, tc.uid, tc.gid)
		if err != nil || got.endpoint != tc.endpoint || got.user != tc.user {
			t.Fatalf("%s connection = %#v, %v", tc.platform, got, err)
		}
	}
	for _, tc := range []struct {
		platform, home string
		uid, gid       int
	}{
		{"darwin", "/Users/alice", 501, 20},
		{"linux", "/root", 0, 0},
		{"linux", "/home/alice", 1001, 0},
		{"linux", "/home/alice", -1, 1001},
		{"linux", "/", 1001, 1001},
		{"linux", "relative", 1001, 1001},
		{"linux", "/home/../root", 1001, 1001},
		{"linux", "/home/ali\nce", 1001, 1001},
	} {
		if _, err := resolveDockerConnection(tc.platform, tc.home, tc.uid, tc.gid); err == nil {
			t.Fatalf("unsupported/root/unsafe connection accepted: %#v", tc)
		}
	}
}

func TestDockerEngineIdentityRefusesNativeAndUnknownEngines(t *testing.T) {
	for _, body := range []string{
		`{"OSType":"linux","OperatingSystem":"Docker Desktop","Name":"docker-desktop","KernelVersion":"6.12.1-linuxkit"}`,
		fixtureDesktopInfo,
	} {
		if err := validateDesktopEngine([]byte(body)); err != nil {
			t.Fatalf("supported VM identity rejected: %v", err)
		}
	}
	for _, body := range []string{
		`{"OSType":"linux","OperatingSystem":"Ubuntu 24.04","Name":"host","KernelVersion":"6.8.0-generic"}`,
		`{"OSType":"linux","OperatingSystem":"Docker Desktop","Name":"docker-desktop","KernelVersion":"6.8.0-generic"}`,
		`{"OSType":"linux","OperatingSystem":"Docker Desktop","Name":"docker-desktop","KernelVersion":"6.12.1-linuxkit","SecurityOptions":["name=rootless"]}`,
		`{"OSType":"linux","OperatingSystem":"Docker Desktop","Name":"docker-desktop","KernelVersion":"6.12.1-linuxkit","SecurityOptions":["name=userns"]}`,
		`{"OSType":"windows","OperatingSystem":"Docker Desktop","Name":"docker-desktop","KernelVersion":"linuxkit"}`,
		`{"OSType":"linux"}`,
		`{}`,
		`null`,
		`invalid`,
	} {
		host := fixtureDockerHost(nil)
		calls := 0
		host.runDocker = func(context.Context, string, ...string) ([]byte, error) {
			calls++
			return []byte(body), nil
		}
		if capabilities, err := host.Capabilities(context.Background()); err == nil || capabilities.Isolation != "" || calls != 1 {
			t.Fatalf("unproved engine accepted: %q: %#v %v", body, capabilities, err)
		}
		spec, _, _ := verifiedFixture(t)
		if _, err := host.Launch(context.Background(), spec); err == nil || calls != 2 {
			t.Fatal("direct launch bypassed engine proof")
		}
	}
}

func TestDockerUnsupportedPlatformFailsBeforeCommand(t *testing.T) {
	host := fixtureDockerHost(func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("Docker command ran despite unsupported platform")
		return nil, nil
	})
	host.connection = func() (dockerConnection, error) {
		return dockerConnection{}, errors.New("unsupported platform")
	}
	if _, err := host.Capabilities(context.Background()); err == nil {
		t.Fatal("unsupported platform advertised capabilities")
	}
	if _, err := host.launchCommand(context.Background(), "run"); err == nil {
		t.Fatal("unsupported platform launched scanner")
	}
}

func TestDockerLinuxDesktopUsesPrivateOwnerUIDAndPinnedSocket(t *testing.T) {
	connection, err := resolveDockerConnection("linux", "/home/alice", 1001, 1002)
	if err != nil {
		t.Fatal(err)
	}
	host := fixtureDockerHost(nil)
	host.connection = func() (dockerConnection, error) { return connection, nil }
	host.runDocker = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if len(args) < 3 || args[0] != "--host" || args[1] != connection.endpoint {
			t.Fatalf("ambient/native Docker endpoint used: %#v", args)
		}
		switch args[2] {
		case "info":
			return []byte(fixtureDesktopInfo), nil
		case "image":
			if len(args) > 5 && args[5] == "{{json .Config.Volumes}}" {
				return []byte(`null`), nil
			}
			return []byte(fixtureImage), nil
		case "run":
			if !strings.Contains(strings.Join(args, "\n"), "--user\n1001:1002") {
				t.Fatal("private host owner identity was not preserved")
			}
			return []byte(`{"ok":true}`), nil
		}
		t.Fatalf("unexpected Docker command: %#v", args)
		return nil, nil
	}
	spec, _, _ := verifiedFixture(t)
	if result, err := host.Launch(context.Background(), spec); err != nil || result.Status != Succeeded {
		t.Fatalf("Linux Desktop synthetic launch failed: %#v %v", result, err)
	}
}

func TestDockerCapturedLaunchPinsEndpoint(t *testing.T) {
	host := fixtureDockerHost(nil)
	host.runCaptured = func(_ context.Context, _ string, args ...string) (commandOutput, error) {
		if len(args) < 3 || args[0] != "--host" || args[1] != dockerDesktopLinuxEndpoint || args[2] != "run" {
			t.Fatalf("capture command did not pin endpoint: %#v", args)
		}
		return commandOutput{}, nil
	}
	if _, err := host.launchCommand(context.Background(), "run", "synthetic"); err != nil {
		t.Fatal(err)
	}
}
