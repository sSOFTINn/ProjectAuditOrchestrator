//go:build linux

package doctor

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strings"
)

func supportedHost() error {
	// This fixed root-owned operating-system source may be the distribution's
	// standard symlink. No caller/target path is used or followed here.
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return errors.New("host OS identity unavailable")
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(raw) > 65536 {
		return errors.New("host OS identity invalid")
	}
	fields := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}
		if key == "ID" || key == "VERSION_ID" {
			if _, exists := fields[key]; exists {
				return errors.New("duplicate host identity")
			}
			fields[key] = strings.Trim(value, "\"'")
		}
	}
	if scanner.Err() != nil || fields["ID"] != "ubuntu" || fields["VERSION_ID"] != "24.04" {
		return errors.New("Ubuntu 24.04 LTS is required")
	}
	return nil
}
