package buildinfo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCurrentProducerIdentifiesThisImageWithoutExposingItsPath(t *testing.T) {
	producer, err := Current()
	if err != nil || producer.Validate() != nil {
		t.Fatalf("producer unavailable: %#v %v", producer, err)
	}
	if producer.IdentityStatus != "DEVELOPMENT" || producer.SourceTreeSHA256 != "unknown" || producer.Revision != "unknown" {
		t.Fatal("test/development image impersonated a release")
	}
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	want, err := executableDigest(path)
	if err != nil {
		t.Fatal(err)
	}
	if producer.ExecutableSHA256 != want {
		t.Fatal("producer does not identify the actual executable")
	}
	data, _ := json.Marshal(producer)
	if strings.Contains(string(data), path) || strings.Contains(string(data), filepath.Dir(path)) {
		t.Fatal("portable producer disclosed a local path")
	}
}

func TestDistinctProducerBytesCannotShareTheSameExecutableIdentity(t *testing.T) {
	root := t.TempDir()
	var identities []Producer
	for _, contents := range []string{"synthetic build A", "synthetic build B"} {
		path := filepath.Join(root, strings.ReplaceAll(contents, " ", "-"))
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		digest, err := executableDigest(path)
		if err != nil {
			t.Fatal(err)
		}
		identities = append(identities, identity(digest))
	}
	if identities[0].Version != identities[1].Version || identities[0].ExecutableSHA256 == identities[1].ExecutableSHA256 {
		t.Fatal("equal version labels concealed different producer bytes")
	}
}

func TestReleaseProducerRequiresAllDeclaredBuildIdentity(t *testing.T) {
	producer := Producer{APIVersion: ProducerVersion, Version: "0.2.0", Revision: strings.Repeat("a", 40), SourceState: "clean", SourceTreeSHA256: "sha256:" + strings.Repeat("b", 64), ExecutableSHA256: "sha256:" + strings.Repeat("c", 64), GoVersion: "go1.27.0", IdentityStatus: "RELEASE_CANDIDATE"}
	if producer.Validate() != nil {
		t.Fatal("complete candidate identity rejected")
	}
	for _, field := range []string{"revision", "source", "state", "version", "executable"} {
		copy := producer
		switch field {
		case "revision":
			copy.Revision = "unknown"
		case "source":
			copy.SourceTreeSHA256 = "unknown"
		case "state":
			copy.SourceState = "modified"
		case "version":
			copy.Version = "dev"
		case "executable":
			copy.ExecutableSHA256 = "unknown"
		}
		if copy.Validate() == nil {
			t.Fatalf("unproven %s accepted as release identity", field)
		}
	}
}
