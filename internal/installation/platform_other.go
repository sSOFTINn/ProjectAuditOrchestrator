//go:build !windows

package installation

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/auditconfig"
)

func ValidatePrivatePath(path string, directory bool) error {
	if err := auditconfig.CheckPath(path, false); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 || (directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular()) {
		return errors.New("installation object requires owner-only permissions and the current owner")
	}
	for p := filepath.Dir(path); ; p = filepath.Dir(p) {
		i, err := os.Lstat(p)
		if err != nil {
			return err
		}
		s, ok := i.Sys().(*syscall.Stat_t)
		if !ok || (s.Uid != uint32(os.Geteuid()) && s.Uid != 0) || (i.Mode().Perm()&0022 != 0 && i.Mode()&os.ModeSticky == 0) {
			return errors.New("installation ancestor is writable by another user")
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return nil
}

func tryLock(f *os.File, exclusive bool) (bool, error) {
	flag := syscall.LOCK_SH
	if exclusive {
		flag = syscall.LOCK_EX
	}
	err := syscall.Flock(int(f.Fd()), flag|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return false, nil
	}
	return err == nil, err
}
func unlock(f *os.File) error           { return syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
func replaceFile(from, to string) error { return os.Rename(from, to) }
func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
