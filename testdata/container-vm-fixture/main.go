// A static synthetic executable for the opt-in Docker Desktop isolation test.
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	if len(os.Args) != 3 {
		fail("expected target and scratch paths")
	}
	target, scratch := os.Args[1], os.Args[2]
	if os.Getenv("PAO_PROVIDER_FIXTURE") != "1" {
		fail("sanitized environment marker missing")
	}
	if os.Geteuid() == 0 {
		fail("scanner must not run as root")
	}
	if data, err := os.ReadFile(filepath.Join(target, "sentinel.txt")); err != nil || string(data) != "unchanged" {
		fail("private target input is unreadable or unexpected")
	}
	if err := os.WriteFile(filepath.Join(target, "must-not-write"), []byte("blocked"), 0o600); err == nil {
		fail("read-only target mount accepted a write")
	}
	if err := os.WriteFile(filepath.Join(scratch, "scratch-ok"), []byte("created"), 0o600); err != nil {
		fail("temporary write mount unavailable: " + err.Error())
	}
	stateReadOnly := true
	if os.Getenv("PAO_PROVIDER_STATE_FIXTURE") == "1" {
		if data, err := os.ReadFile("/pao/state/cache.txt"); err != nil || string(data) != "synthetic-state" {
			fail("prepared state mount unavailable or unexpected")
		}
		if err := os.WriteFile("/pao/state/must-not-write", []byte("blocked"), 0o600); err == nil {
			fail("prepared state mount accepted a write")
		}
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		fail("inspect network: " + err.Error())
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback == 0 && iface.Flags&net.FlagUp != 0 {
			fail("network interface unexpectedly available: " + iface.Name)
		}
	}
	switch os.Getenv("PAO_QUOTA_FIXTURE") {
	case "bytes", "entries":
		quotaFixture(scratch, os.Getenv("PAO_QUOTA_FIXTURE"))
	case "stream":
		_, _ = os.Stdout.WriteString(strings.Repeat("x", 2<<20))
		return
	case "timeout":
		time.Sleep(20 * time.Second)
		return
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]bool{
		"non_root":             true,
		"private_input_read":   true,
		"network_denied":       true,
		"target_read_only":     true,
		"temporary_write_only": true,
		"state_read_only":      stateReadOnly,
	})
}

func quotaFixture(scratch, kind string) {
	var written int64
	var count int
	var writeErr error
	block := []byte(strings.Repeat("x", 64<<10))
	if kind == "bytes" {
		file, err := os.Create(filepath.Join(scratch, "undeclared-bomb"))
		if err != nil {
			fail("create synthetic bomb")
		}
		for count = 0; count < 4096; count++ {
			n, err := file.Write(block)
			written += int64(n)
			if err != nil {
				writeErr = err
				break
			}
		}
		_ = file.Close()
	} else {
		for count = 0; count < 5000; count++ {
			if err := os.WriteFile(filepath.Join(scratch, fmt.Sprintf("undeclared-%04d", count)), nil, 0600); err != nil {
				writeErr = err
				break
			}
		}
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"quota_exhausted": writeErr != nil, "written_bytes": written, "entries": count})
	// A tool that exhausts its scratch budget cannot claim successful analysis.
	os.Exit(42)
}

func fail(reason string) {
	fmt.Fprintln(os.Stderr, reason)
	os.Exit(42)
}
