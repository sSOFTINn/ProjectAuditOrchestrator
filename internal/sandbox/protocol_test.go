package sandbox

import (
	"encoding/json"
	"testing"
)

func TestEnvelopeRejectsUndeclaredFilesAndAggregateOverflow(t *testing.T) {
	request := Request{Version: Version, Entrypoint: "/pao/tool/probe", Arguments: []string{"scan"}, Files: []string{"result.json"}, MaxBytes: 7}
	code := 0
	for _, invalid := range []string{"", "undeclared", "overflow", "trailing", "unknown", "version"} {
		result := Result{Version: Version, ExitCode: &code, Stdout: []byte("x"), Files: map[string][]byte{"result.json": []byte("{}")}}
		switch invalid {
		case "undeclared":
			result.Files["private-other.json"] = []byte("x")
		case "overflow":
			result.Files["result.json"] = []byte("1234567")
		case "version":
			result.Version = "future"
		}
		data, _ := json.Marshal(result)
		if invalid == "trailing" {
			data = append(data, []byte(`{}`)...)
		}
		if invalid == "unknown" {
			data = append([]byte(`{"shell":"untrusted",`), data[1:]...)
		}
		_, err := Decode(data, request)
		if (invalid == "") != (err == nil) {
			t.Fatalf("%s: %v", invalid, err)
		}
	}
}

func TestSupervisorRequestRestrictsEntrypointsAndOutputPaths(t *testing.T) {
	request := Request{Version: Version, Entrypoint: "/pao/state/bin/scanner", Arguments: []string{"scan"}, MaxBytes: 1}
	if request.Validate() != nil {
		t.Fatal("declared state entrypoint rejected")
	}
	for _, path := range []string{"/bin/sh", "/pao/state/../out/scanner", "/pao/tool/../../bin/sh"} {
		copy := request
		copy.Entrypoint = path
		if copy.Validate() == nil {
			t.Fatalf("undeclared entrypoint accepted: %s", path)
		}
	}
	for _, name := range []string{"../outside", "/private/file", "a\\b", ".", "a/../b", ""} {
		copy := request
		copy.Files = []string{name}
		if copy.Validate() == nil {
			t.Fatalf("unsafe output accepted: %s", name)
		}
	}
}
