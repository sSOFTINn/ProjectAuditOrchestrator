// Synthetic contract probe, not the upstream sbomqs executable.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	if len(os.Args) != 5 || os.Args[1] != "score" || os.Args[3] != "--legacy" || os.Args[4] != "--json" {
		fail("unexpected invocation")
	}
	input := os.Args[2]
	data, err := os.ReadFile(input)
	if err != nil || !bytes.Contains(data, []byte(`"bomFormat":"CycloneDX"`)) {
		fail("captured SBOM unavailable")
	}
	entries, err := os.ReadDir(filepath.Dir(input))
	if err != nil || len(entries) != 1 {
		fail("unrelated evidence is visible")
	}
	if _, err := os.Stat("/pao/target/sentinel.txt"); !os.IsNotExist(err) {
		fail("target is visible")
	}
	if err := os.WriteFile(input, []byte("changed"), 0600); err == nil {
		fail("SBOM is writable")
	}
	if err := os.WriteFile("/pao/tool/unexpected", []byte("changed"), 0600); err == nil {
		fail("toolchain is writable")
	}
	if err := os.WriteFile("/pao/out/scratch-ok", []byte("synthetic"), 0600); err != nil {
		fail("scratch unavailable")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		fail("network inspection failed")
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback == 0 && iface.Flags&net.FlagUp != 0 {
			fail("network available")
		}
	}
	self, err := os.ReadFile(os.Args[0])
	if err != nil || os.WriteFile("/tmp/probe", self, 0700) != nil {
		fail("temporary executable probe unavailable")
	}
	if err := exec.Command("/tmp/probe").Start(); err == nil {
		fail("temporary directory permits execution")
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"files": []any{map[string]any{
		"avg_score": 8.5, "synthetic_isolation_verified": true,
	}}})
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(42)
}
