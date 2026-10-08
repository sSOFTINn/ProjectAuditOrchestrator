package runner

import (
	"errors"
	"fmt"
	"os"
	"path"
	"runtime"
	"strings"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditconfig"
)

type dockerConnection struct {
	endpoint string
	user     string
}

func (h DockerHost) localConnection() (dockerConnection, error) {
	if h.connection != nil {
		return h.connection()
	}
	home := ""
	if runtime.GOOS == "linux" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			return dockerConnection{}, errors.New("local Docker Desktop user home is unavailable")
		}
	}
	connection, err := resolveDockerConnection(runtime.GOOS, home, os.Getuid(), os.Getgid())
	if err != nil {
		return dockerConnection{}, err
	}
	if runtime.GOOS == "linux" {
		socket := strings.TrimPrefix(connection.endpoint, "unix://")
		if err := auditconfig.CheckPath(socket, false); err != nil {
			return dockerConnection{}, errors.New("local Docker Desktop socket path is unsafe or unavailable")
		}
		info, err := os.Lstat(socket)
		if err != nil || info.Mode()&os.ModeSocket == 0 {
			return dockerConnection{}, errors.New("local Docker Desktop endpoint must be a Unix socket")
		}
	}
	return connection, nil
}

// Supported engines are deliberately narrow. Do not add the system Docker
// socket or an ambient context: native Linux shares the host kernel and cannot
// provide the required container-VM boundary.
func resolveDockerConnection(platform, home string, uid, gid int) (dockerConnection, error) {
	switch platform {
	case "windows":
		return dockerConnection{endpoint: dockerDesktopLinuxEndpoint, user: "65532:65532"}, nil
	case "linux":
		if uid <= 0 || gid <= 0 {
			return dockerConnection{}, errors.New("Linux Docker Desktop requires a non-root host user and group")
		}
		if !path.IsAbs(home) || path.Clean(home) != home || home == "/" || strings.ContainsAny(home, "\\\x00\r\n") {
			return dockerConnection{}, errors.New("Linux Docker Desktop requires an absolute local user home")
		}
		// Use the caller's numeric identity rather than broadening private input
		// file/directory modes to let an unrelated fixed UID read them. Desktop
		// file-sharing/UID mapping must still pass the opt-in acceptance test.
		return dockerConnection{
			endpoint: "unix://" + path.Join(home, ".docker", "desktop", "docker.sock"),
			user:     fmt.Sprintf("%d:%d", uid, gid),
		}, nil
	default:
		return dockerConnection{}, errors.New("container-vm execution requires verified local Docker Desktop Linux on a supported Windows or Linux host")
	}
}
