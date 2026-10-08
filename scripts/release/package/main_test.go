package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testVersion = "0.2.0-test"

func fixture(t *testing.T, platform string) (string, string) {
	t.Helper()
	stage := t.TempDir()
	for _, name := range allowed(platform) {
		if name == "PACKAGE-CONTENTS.json" {
			continue
		}
		data := []byte("synthetic fixture; never executed\n")
		if blank, ok := blankTemplates()[name]; ok {
			data, _ = json.Marshal(blank)
		}
		if strings.HasPrefix(name, "adapters/") {
			data = []byte(`{"api_version":"pao.dev/adapter/v1alpha2","id":"` + strings.Split(name, "/")[1] + `"}`)
		}
		if name == "VERSION.json" {
			data, _ = json.Marshal(publicVersion{Version: testVersion, Platform: platform, Architecture: "amd64"})
		}
		path := filepath.Join(stage, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	privatePath := filepath.Join(t.TempDir(), "BUILD-METADATA.json")
	fixtureHash := digest([]byte("synthetic fixture; never executed\n"))
	data, err := json.Marshal(metadata{Version: testVersion, Revision: strings.Repeat("a", 40), SourceState: "modified", SourceTreeSHA256: strings.Repeat("b", 64), SandboxSHA256: fixtureHash, PaoSHA256: map[string]string{"windows": fixtureHash, "linux": fixtureHash}, GoVersion: "go1.27.1", AsOf: "2026-10-01T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privatePath, data, 0600); err != nil {
		t.Fatal(err)
	}
	return stage, privatePath
}
func archiveName(platform string) string {
	ext := ".tar.gz"
	if platform == "windows" {
		ext = ".zip"
	}
	return "pao-" + testVersion + "-" + platform + "-amd64" + ext
}

func TestPackageReproducibleAndExternalIdentity(t *testing.T) {
	for _, platform := range []string{"windows", "linux"} {
		t.Run(platform, func(t *testing.T) {
			stage, metadataPath := fixture(t, platform)
			first := filepath.Join(t.TempDir(), archiveName(platform))
			second := filepath.Join(t.TempDir(), archiveName(platform))
			if err := pack(stage, first, platform, testVersion, metadataPath); err != nil {
				t.Fatal(err)
			}
			if err := pack(stage, second, platform, testVersion, metadataPath); err != nil {
				t.Fatal(err)
			}
			a, _ := os.ReadFile(first)
			b, _ := os.ReadFile(second)
			if !bytes.Equal(a, b) {
				t.Fatal("same source produced different archives")
			}
			if err := verify(first, platform, testVersion); err != nil {
				t.Fatal(err)
			}
			bindArchiveMetadata(t, metadataPath, first, platform)
			if err := verifyWithMetadata(first, platform, testVersion, metadataPath); err != nil {
				t.Fatal(err)
			}
			bad := filepath.Join(t.TempDir(), "metadata.json")
			if err := os.WriteFile(bad, []byte("{}"), 0600); err != nil {
				t.Fatal(err)
			}
			if verifyWithMetadata(first, platform, testVersion, bad) == nil {
				t.Fatal("accepted different build identity")
			}
			if err := pack(stage, first, platform, testVersion, metadataPath); err == nil {
				t.Fatal("overwrote existing archive")
			}
		})
	}
}

func TestPackRejectsMissingAndUnexpectedInputs(t *testing.T) {
	for _, change := range []string{"missing-adapter", "private-file", "wrong-version", "filled-template", "duplicate-template-key"} {
		t.Run(change, func(t *testing.T) {
			stage, metadataPath := fixture(t, "windows")
			switch change {
			case "filled-template":
				path := filepath.Join(stage, "audit.json")
				data, _ := os.ReadFile(path)
				if err := os.WriteFile(path, bytes.ReplaceAll(data, []byte("REPLACE_WITH_ABSOLUTE_TARGET_DIRECTORY"), []byte("/private/project")), 0600); err != nil {
					t.Fatal(err)
				}
			case "duplicate-template-key":
				path := filepath.Join(stage, "audit.json")
				data, _ := os.ReadFile(path)
				data = append([]byte(`{"target":"/private/project",`), data[1:]...)
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-adapter":
				if err := os.Remove(filepath.Join(stage, "adapters/syft/manifest.json")); err != nil {
					t.Fatal(err)
				}
			case "private-file":
				if err := os.WriteFile(filepath.Join(stage, "private-evidence.json"), []byte("synthetic"), 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong-version":
				path := filepath.Join(stage, "VERSION.json")
				data, _ := os.ReadFile(path)
				if err := os.WriteFile(path, bytes.ReplaceAll(data, []byte(testVersion), []byte("9.9.9")), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if pack(stage, filepath.Join(t.TempDir(), archiveName("windows")), "windows", testVersion, metadataPath) == nil {
				t.Fatal("accepted invalid input")
			}
		})
	}
}

func TestZIPRejectsTamperLinksDuplicateAndTraversal(t *testing.T) {
	good := filepath.Join(t.TempDir(), archiveName("windows"))
	stage, metadataPath := fixture(t, "windows")
	if err := pack(stage, good, "windows", testVersion, metadataPath); err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"tamper", "duplicate", "traversal", "link", "extra", "missing"} {
		t.Run(change, func(t *testing.T) {
			bad := filepath.Join(t.TempDir(), archiveName("windows"))
			in, err := zip.OpenReader(good)
			if err != nil {
				t.Fatal(err)
			}
			defer in.Close()
			out, err := os.Create(bad)
			if err != nil {
				t.Fatal(err)
			}
			writer := zip.NewWriter(out)
			for _, entry := range in.File {
				if change == "missing" && entry.Name == "LICENSE" {
					continue
				}
				r, err := entry.Open()
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(r)
				r.Close()
				if err != nil {
					t.Fatal(err)
				}
				header := entry.FileHeader
				if entry.Name == "NOTICE" {
					switch change {
					case "tamper":
						data = []byte("changed")
					case "traversal":
						header.Name = "../NOTICE"
					case "link":
						header.SetMode(os.ModeSymlink | 0777)
					}
				}
				w, err := writer.CreateHeader(&header)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = w.Write(data); err != nil {
					t.Fatal(err)
				}
			}
			if change == "duplicate" || change == "extra" {
				name := "LICENSE"
				if change == "extra" {
					name = "scanner.exe"
				}
				w, err := writer.Create(name)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = w.Write([]byte("synthetic")); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			out.Close()
			if verify(bad, "windows", testVersion) == nil {
				t.Fatal("accepted hostile archive")
			}
		})
	}
}

func TestTarRejectsNonExecutableLinuxAndLink(t *testing.T) {
	good := filepath.Join(t.TempDir(), archiveName("linux"))
	stage, metadataPath := fixture(t, "linux")
	if err := pack(stage, good, "linux", testVersion, metadataPath); err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"mode", "link"} {
		t.Run(change, func(t *testing.T) {
			in, err := os.Open(good)
			if err != nil {
				t.Fatal(err)
			}
			defer in.Close()
			gz, err := gzip.NewReader(in)
			if err != nil {
				t.Fatal(err)
			}
			defer gz.Close()
			reader := tar.NewReader(gz)
			bad := filepath.Join(t.TempDir(), archiveName("linux"))
			out, err := os.Create(bad)
			if err != nil {
				t.Fatal(err)
			}
			compressed := gzip.NewWriter(out)
			writer := tar.NewWriter(compressed)
			for {
				header, err := reader.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(reader)
				if err != nil {
					t.Fatal(err)
				}
				if header.Name == "pao" {
					if change == "mode" {
						header.Mode = 0644
					} else {
						header.Typeflag = tar.TypeSymlink
						header.Linkname = "/etc/passwd"
						header.Size = 0
						data = nil
					}
				}
				if err := writer.WriteHeader(header); err != nil {
					t.Fatal(err)
				}
				if _, err := writer.Write(data); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			if err := compressed.Close(); err != nil {
				t.Fatal(err)
			}
			out.Close()
			if verify(bad, "linux", testVersion) == nil {
				t.Fatal("accepted unsafe Linux archive")
			}
		})
	}
}

func TestPublicArchiveContainsOnlyMinimalVersion(t *testing.T) {
	for _, platform := range []string{"windows", "linux"} {
		t.Run(platform, func(t *testing.T) {
			stage, metadataPath := fixture(t, platform)
			archive := filepath.Join(t.TempDir(), archiveName(platform))
			if err := pack(stage, archive, platform, testVersion, metadataPath); err != nil {
				t.Fatal(err)
			}
			files := archiveFiles(t, archive, platform)
			if _, present := files["BUILD-METADATA.json"]; present {
				t.Fatal("private build metadata leaked into archive")
			}
			var identity map[string]string
			if err := json.Unmarshal(files["VERSION.json"], &identity); err != nil {
				t.Fatal(err)
			}
			if len(identity) != 3 || identity["version"] != testVersion || identity["platform"] != platform || identity["architecture"] != "amd64" {
				t.Fatalf("unexpected public identity: %v", identity)
			}
		})
	}
}

func TestPrivateFilesRejectedByPackAndVerify(t *testing.T) {
	for _, platform := range []string{"windows", "linux"} {
		for _, name := range []string{"BUILD-METADATA.json", "report.json", "sbom.spdx.json", "provenance.json"} {
			t.Run(platform+"/"+name, func(t *testing.T) {
				stage, metadataPath := fixture(t, platform)
				good := filepath.Join(t.TempDir(), archiveName(platform))
				if err := pack(stage, good, platform, testVersion, metadataPath); err != nil {
					t.Fatal(err)
				}
				privateData := []byte(`{"private":"synthetic evidence"}`)
				if err := os.WriteFile(filepath.Join(stage, name), privateData, 0600); err != nil {
					t.Fatal(err)
				}
				output := filepath.Join(t.TempDir(), archiveName(platform))
				if pack(stage, output, platform, testVersion, metadataPath) == nil {
					t.Fatal("pack accepted private input")
				}
				if _, err := os.Stat(output); !os.IsNotExist(err) {
					t.Fatalf("invalid inputs created an archive: %v", err)
				}
				files := archiveFiles(t, good, platform)
				files[name] = privateData
				rehashContents(t, files)
				bad := writeArchiveFiles(t, files, platform)
				if verify(bad, platform, testVersion) == nil {
					t.Fatal("verify accepted private file even with matching content hash")
				}
			})
		}
	}
}

func TestVersionIdentityRejectsRehashedMutations(t *testing.T) {
	for _, platform := range []string{"windows", "linux"} {
		stage, metadataPath := fixture(t, platform)
		good := filepath.Join(t.TempDir(), archiveName(platform))
		if err := pack(stage, good, platform, testVersion, metadataPath); err != nil {
			t.Fatal(err)
		}
		valid := `{"version":"` + testVersion + `","platform":"` + platform + `","architecture":"amd64"}`
		mutations := map[string]string{
			"private-field": strings.TrimSuffix(valid, "}") + `,"revision":"private"}`,
			"duplicate-key": `{"version":"wrong",` + valid[1:],
			"trailing-json": valid + `{}`,
			"null":          `null`,
			"missing":       `{"version":"` + testVersion + `","platform":"` + platform + `"}`,
			"architecture":  strings.ReplaceAll(valid, "amd64", "arm64"),
			"platform":      strings.ReplaceAll(valid, platform, "unknown"),
			"version":       strings.ReplaceAll(valid, testVersion, "9.9.9"),
		}
		for name, value := range mutations {
			t.Run(platform+"/"+name, func(t *testing.T) {
				files := archiveFiles(t, good, platform)
				files["VERSION.json"] = []byte(value)
				rehashContents(t, files)
				if verify(writeArchiveFiles(t, files, platform), platform, testVersion) == nil {
					t.Fatal("accepted invalid public identity with matching content hash")
				}
			})
		}
	}
}

func TestExternalMetadataRejectsRehashedSupervisorReplacement(t *testing.T) {
	for _, platform := range []string{"windows", "linux"} {
		t.Run(platform, func(t *testing.T) {
			stage, metadataPath := fixture(t, platform)
			good := filepath.Join(t.TempDir(), archiveName(platform))
			if err := pack(stage, good, platform, testVersion, metadataPath); err != nil {
				t.Fatal(err)
			}
			bindArchiveMetadata(t, metadataPath, good, platform)
			files := archiveFiles(t, good, platform)
			files["pao-sandbox-linux-amd64"] = []byte("replacement synthetic supervisor")
			rehashContents(t, files)
			changed := writeArchiveFiles(t, files, platform)
			// Public verification establishes composition and internal consistency,
			// while the private metadata supplies the expected supervisor identity.
			if err := verify(changed, platform, testVersion); err != nil {
				t.Fatalf("internally consistent public archive failed: %v", err)
			}
			if verifyWithMetadata(changed, platform, testVersion, metadataPath) == nil {
				t.Fatal("accepted supervisor that differs from private build metadata")
			}
			if err := os.WriteFile(filepath.Join(stage, "pao-sandbox-linux-amd64"), files["pao-sandbox-linux-amd64"], 0600); err != nil {
				t.Fatal(err)
			}
			if pack(stage, filepath.Join(t.TempDir(), archiveName(platform)), platform, testVersion, metadataPath) == nil {
				t.Fatal("pack accepted supervisor that differs from private build metadata")
			}
		})
	}
}

func TestPrivateMetadataRequiredForPackAndStrictWhenProvided(t *testing.T) {
	stage, metadataPath := fixture(t, "windows")
	good := filepath.Join(t.TempDir(), archiveName("windows"))
	if err := pack(stage, good, "windows", testVersion, metadataPath); err != nil {
		t.Fatal(err)
	}
	bindArchiveMetadata(t, metadataPath, good, "windows")
	if pack(stage, filepath.Join(t.TempDir(), archiveName("windows")), "windows", testVersion, "") == nil {
		t.Fatal("pack accepted missing external metadata")
	}
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		t.Fatal(err)
	}
	valid := string(data)
	mutations := map[string]string{
		"empty":          "",
		"unknown-field":  strings.TrimSuffix(valid, "}") + `,"unexpected":true}`,
		"duplicate-key":  `{"version":"wrong",` + valid[1:],
		"trailing-json":  valid + `{}`,
		"version":        strings.ReplaceAll(valid, testVersion, "9.9.9"),
		"revision":       strings.ReplaceAll(valid, strings.Repeat("a", 40), "invalid"),
		"source-tree":    strings.ReplaceAll(valid, strings.Repeat("b", 64), "invalid"),
		"source-state":   strings.ReplaceAll(valid, "modified", "unknown"),
		"go-version":     strings.ReplaceAll(valid, "go1.27.1", "unknown"),
		"timestamp":      strings.ReplaceAll(valid, "2026-10-01T00:00:00Z", "unknown"),
		"oversized":      strings.Repeat(" ", 16385) + valid,
		"sandbox-digest": strings.ReplaceAll(valid, digest([]byte("synthetic fixture; never executed\n")), strings.Repeat("0", 64)),
	}
	for name, value := range mutations {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "BUILD-METADATA.json")
			if err := os.WriteFile(path, []byte(value), 0600); err != nil {
				t.Fatal(err)
			}
			if pack(stage, filepath.Join(t.TempDir(), archiveName("windows")), "windows", testVersion, path) == nil {
				t.Fatal("pack accepted invalid private metadata")
			}
			if verifyWithMetadata(good, "windows", testVersion, path) == nil {
				t.Fatal("verify accepted invalid private metadata")
			}
		})
	}
}

func TestPrivateMetadataRejectsLegitimateForeignBuild(t *testing.T) {
	for _, platform := range []string{"windows", "linux"} {
		t.Run(platform, func(t *testing.T) {
			stageA, metadataA := fixture(t, platform)
			archiveA := filepath.Join(t.TempDir(), archiveName(platform))
			if err := pack(stageA, archiveA, platform, testVersion, metadataA); err != nil {
				t.Fatal(err)
			}
			bindArchiveMetadata(t, metadataA, archiveA, platform)
			stageB, metadataB := fixture(t, platform)
			cliB := []byte("different valid synthetic build of the same version")
			if err := os.WriteFile(filepath.Join(stageB, cliName(platform)), cliB, 0600); err != nil {
				t.Fatal(err)
			}
			updateMetadata(t, metadataB, func(m *metadata) {
				m.PaoSHA256[platform] = digest(cliB)
				m.Revision = strings.Repeat("c", 40)
				m.SourceTreeSHA256 = strings.Repeat("d", 64)
			})
			archiveB := filepath.Join(t.TempDir(), archiveName(platform))
			if err := pack(stageB, archiveB, platform, testVersion, metadataB); err != nil {
				t.Fatal(err)
			}
			bindArchiveMetadata(t, metadataB, archiveB, platform)
			for archive, metadataPath := range map[string]string{archiveA: metadataA, archiveB: metadataB} {
				if err := verifyWithMetadata(archive, platform, testVersion, metadataPath); err != nil {
					t.Fatalf("valid build's private verification failed: %v", err)
				}
			}
			if err := verifyWithMetadata(archiveA, platform, testVersion, metadataB); err == nil || !strings.Contains(err.Error(), "CLI identity mismatch") {
				t.Fatalf("foreign build metadata was not rejected by CLI binding: %v", err)
			}
			if err := pack(stageA, filepath.Join(t.TempDir(), archiveName(platform)), platform, testVersion, metadataB); err == nil || !strings.Contains(err.Error(), "CLI identity mismatch") {
				t.Fatalf("pack accepted foreign CLI metadata: %v", err)
			}
		})
	}
}

func TestPrivateMetadataRejectsRehashedArchiveMutations(t *testing.T) {
	for _, platform := range []string{"windows", "linux"} {
		for _, name := range []string{cliName(platform), "NOTICE"} {
			t.Run(platform+"/"+name, func(t *testing.T) {
				stage, metadataPath := fixture(t, platform)
				good := filepath.Join(t.TempDir(), archiveName(platform))
				if err := pack(stage, good, platform, testVersion, metadataPath); err != nil {
					t.Fatal(err)
				}
				bindArchiveMetadata(t, metadataPath, good, platform)
				files := archiveFiles(t, good, platform)
				files[name] = []byte("changed synthetic contents")
				rehashContents(t, files)
				changed := writeArchiveFiles(t, files, platform)
				if err := verify(changed, platform, testVersion); err != nil {
					t.Fatalf("internally consistent mutation failed public verification: %v", err)
				}
				want := "archive identity mismatch"
				if name == cliName(platform) {
					want = "CLI identity mismatch"
				}
				if err := verifyWithMetadata(changed, platform, testVersion, metadataPath); err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("private verification did not reject changed identity (%s): %v", want, err)
				}
			})
		}
	}
}

func TestPrivateVerificationRequiresSelectedArchiveBinding(t *testing.T) {
	for _, platform := range []string{"windows", "linux"} {
		t.Run(platform, func(t *testing.T) {
			stage, metadataPath := fixture(t, platform)
			archive := filepath.Join(t.TempDir(), archiveName(platform))
			// The initial metadata intentionally has no completed archive digests.
			if err := pack(stage, archive, platform, testVersion, metadataPath); err != nil {
				t.Fatal(err)
			}
			if err := verifyWithMetadata(archive, platform, testVersion, metadataPath); err == nil || !strings.Contains(err.Error(), "lacks selected platform archive identity") {
				t.Fatalf("missing final archive binding was accepted: %v", err)
			}
			other := "linux"
			if platform == "linux" {
				other = "windows"
			}
			updateMetadata(t, metadataPath, func(m *metadata) {
				m.ArchivesSHA256 = map[string]string{other: strings.Repeat("f", 64)}
			})
			if verifyWithMetadata(archive, platform, testVersion, metadataPath) == nil {
				t.Fatal("other platform's archive binding was accepted")
			}
			bindArchiveMetadata(t, metadataPath, archive, platform)
			if err := verifyWithMetadata(archive, platform, testVersion, metadataPath); err != nil {
				t.Fatalf("final bound metadata failed: %v", err)
			}
			if err := pack(stage, filepath.Join(t.TempDir(), archiveName(platform)), platform, testVersion, metadataPath); err != nil {
				t.Fatalf("reproducible pack with matching final binding failed: %v", err)
			}
			updateMetadata(t, metadataPath, func(m *metadata) {
				m.ArchivesSHA256[platform] = strings.Repeat("e", 64)
			})
			if err := pack(stage, filepath.Join(t.TempDir(), archiveName(platform)), platform, testVersion, metadataPath); err == nil || !strings.Contains(err.Error(), "archive identity mismatch") {
				t.Fatalf("pack ignored supplied but inconsistent final binding: %v", err)
			}
		})
	}
}

func TestPrivateMetadataPlatformMapsAreStrict(t *testing.T) {
	mutations := map[string]func(*metadata){
		"missing-cli-map":      func(m *metadata) { m.PaoSHA256 = nil },
		"empty-cli-map":        func(m *metadata) { m.PaoSHA256 = map[string]string{} },
		"missing-other-cli":    func(m *metadata) { delete(m.PaoSHA256, "linux") },
		"unknown-cli-platform": func(m *metadata) { m.PaoSHA256["darwin"] = strings.Repeat("a", 64) },
		"invalid-cli-hash":     func(m *metadata) { m.PaoSHA256["windows"] = "unknown" },
		"unknown-archive-platform": func(m *metadata) {
			m.ArchivesSHA256["darwin"] = strings.Repeat("a", 64)
		},
		"invalid-archive-hash": func(m *metadata) { m.ArchivesSHA256["windows"] = "unknown" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			stage, metadataPath := fixture(t, "windows")
			archive := filepath.Join(t.TempDir(), archiveName("windows"))
			if err := pack(stage, archive, "windows", testVersion, metadataPath); err != nil {
				t.Fatal(err)
			}
			bindArchiveMetadata(t, metadataPath, archive, "windows")
			updateMetadata(t, metadataPath, mutate)
			if pack(stage, filepath.Join(t.TempDir(), archiveName("windows")), "windows", testVersion, metadataPath) == nil {
				t.Fatal("pack accepted invalid private digest map")
			}
			if verifyWithMetadata(archive, "windows", testVersion, metadataPath) == nil {
				t.Fatal("private verification accepted invalid private digest map")
			}
		})
	}
}

func updateMetadata(t *testing.T, path string, change func(*metadata)) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m metadata
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	change(&m)
	data, err = json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func bindArchiveMetadata(t *testing.T, metadataPath, archivePath, platform string) {
	t.Helper()
	data, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	updateMetadata(t, metadataPath, func(m *metadata) {
		if m.ArchivesSHA256 == nil {
			m.ArchivesSHA256 = map[string]string{}
		}
		m.ArchivesSHA256[platform] = digest(data)
	})
}

func archiveFiles(t *testing.T, path, platform string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	if platform == "windows" {
		reader, err := zip.OpenReader(path)
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close()
		for _, entry := range reader.File {
			r, err := entry.Open()
			if err != nil {
				t.Fatal(err)
			}
			files[entry.Name], err = io.ReadAll(r)
			r.Close()
			if err != nil {
				t.Fatal(err)
			}
		}
		return files
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	compressed, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer compressed.Close()
	reader := tar.NewReader(compressed)
	for {
		entry, err := reader.Next()
		if err == io.EOF {
			return files
		}
		if err != nil {
			t.Fatal(err)
		}
		files[entry.Name], err = io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func rehashContents(t *testing.T, files map[string][]byte) {
	t.Helper()
	sums := map[string]string{}
	for name, data := range files {
		if name != "PACKAGE-CONTENTS.json" {
			sums[name] = digest(data)
		}
	}
	data, err := json.Marshal(sums)
	if err != nil {
		t.Fatal(err)
	}
	files["PACKAGE-CONTENTS.json"] = data
}

// Write intentionally modified archive contents without pack's admission checks.
func writeArchiveFiles(t *testing.T, files map[string][]byte, platform string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), archiveName(platform))
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if platform == "windows" {
		writer := zip.NewWriter(file)
		for name, data := range files {
			entry, err := writer.Create(name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := entry.Write(data); err != nil {
				t.Fatal(err)
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
	} else {
		compressed := gzip.NewWriter(file)
		writer := tar.NewWriter(compressed)
		for name, data := range files {
			mode := int64(0644)
			if name == "pao" || name == "pao-sandbox-linux-amd64" {
				mode = 0755
			}
			if err := writer.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(data)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write(data); err != nil {
				t.Fatal(err)
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		if err := compressed.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}
