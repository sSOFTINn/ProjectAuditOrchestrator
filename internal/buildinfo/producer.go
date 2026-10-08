package buildinfo

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"regexp"
	"runtime"
)

const ProducerVersion = "pao.dev/producer/v1"

// SourceTreeSHA256 identifies all declared build inputs. A developer build that
// does not inject it remains explicitly unknown; a parser version is no substitute.
var SourceTreeSHA256 = "unknown"

type Producer struct {
	APIVersion       string `json:"api_version"`
	Version          string `json:"version"`
	Revision         string `json:"revision"`
	SourceState      string `json:"source_state"`
	SourceTreeSHA256 string `json:"source_tree_sha256"`
	ExecutableSHA256 string `json:"executable_sha256"`
	GoVersion        string `json:"go_version"`
	IdentityStatus   string `json:"identity_status"`
}

var commitPattern = regexp.MustCompile(`^[a-f0-9]{40}$`)
var sourcePattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var releaseVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)

var goVersionPattern = regexp.MustCompile(`^go[0-9]+\.[0-9]+\.[0-9]+$`)

func Current() (Producer, error) {
	path, err := os.Executable()
	if err != nil {
		return Producer{}, err
	}
	// This kernel-owned link references the image actually running, including
	// after a path replacement. Do not hash a newly substituted pathname on Linux.
	if runtime.GOOS == "linux" {
		path = "/proc/self/exe"
	}
	digest, err := executableDigest(path)
	if err != nil {
		return Producer{}, err
	}
	return identity(digest), nil
}

func identity(digest string) Producer {
	producer := Producer{APIVersion: ProducerVersion, Version: Version, Revision: Revision, SourceState: SourceState, SourceTreeSHA256: SourceTreeSHA256, ExecutableSHA256: digest, GoVersion: runtime.Version(), IdentityStatus: "DEVELOPMENT"}
	if commitPattern.MatchString(producer.Revision) && sourcePattern.MatchString(producer.SourceTreeSHA256) && releaseVersionPattern.MatchString(producer.Version) {
		if producer.SourceState == "clean" {
			producer.IdentityStatus = "RELEASE_CANDIDATE"
		} else if producer.SourceState == "modified" {
			producer.IdentityStatus = "MODIFIED"
		}
	}
	return producer
}

func executableDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 128<<20 {
		return "", errors.New("producer executable must be a bounded regular file")
	}
	hash := sha256.New()
	bytes, err := io.Copy(hash, io.LimitReader(file, (128<<20)+1))
	after, statErr := file.Stat()
	if err != nil || statErr != nil || bytes != info.Size() || !os.SameFile(info, after) || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return "", errors.New("producer executable changed while hashing")
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func (p Producer) Validate() error {
	if p.APIVersion != ProducerVersion || !sourcePattern.MatchString(p.ExecutableSHA256) || !goVersionPattern.MatchString(p.GoVersion) || (p.Version != "dev" && !releaseVersionPattern.MatchString(p.Version)) || (p.Revision != "unknown" && !commitPattern.MatchString(p.Revision)) || (p.SourceTreeSHA256 != "unknown" && !sourcePattern.MatchString(p.SourceTreeSHA256)) {
		return errors.New("invalid PAO producer identity")
	}
	if p.SourceState != "unknown" && p.SourceState != "clean" && p.SourceState != "modified" {
		return errors.New("invalid producer source state")
	}
	switch p.IdentityStatus {
	case "DEVELOPMENT":
	case "RELEASE_CANDIDATE":
		if p.SourceState != "clean" || !commitPattern.MatchString(p.Revision) || !sourcePattern.MatchString(p.SourceTreeSHA256) || !releaseVersionPattern.MatchString(p.Version) {
			return errors.New("unproven release producer")
		}
	case "MODIFIED":
		if p.SourceState != "modified" || !commitPattern.MatchString(p.Revision) || !sourcePattern.MatchString(p.SourceTreeSHA256) || !releaseVersionPattern.MatchString(p.Version) {
			return errors.New("unproven modified producer")
		}
	default:
		return errors.New("invalid producer identity status")
	}
	return nil
}
