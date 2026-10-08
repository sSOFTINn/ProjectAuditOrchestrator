//go:build !windows

package auditconfig

import "os"

func reparse(string) bool { return false }

func localPath(string) bool { return true }

func MakePrivateDirectory(path string) error { return os.Mkdir(path, 0o700) }
