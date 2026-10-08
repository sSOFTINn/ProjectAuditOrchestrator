"""Seal a public candidate locally without copying its private build evidence.

The local transfer manifest binds exact public bytes to source/ref/run identity.
Only payload/ may be uploaded; transfer.json and external build metadata stay
runner-local. This verifies neither a signed tag nor owner release approval.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat

VERSION = "pao.dev/release-transfer/v2"
HEX = re.compile(r"[a-f0-9]{64}\Z")
RELEASE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?\Z")
MAX_FILE = 64 << 20
MAX_TOTAL = 256 << 20


def require(condition, message):
    if not condition:
        raise ValueError(message)


def checked_path(path):
    path = Path(path)
    require(path.is_absolute(), "absolute path is required")
    for item in (path, *path.parents):
        if item.exists() or item.is_symlink():
            info = item.lstat()
            require(not stat.S_ISLNK(info.st_mode), "linked path is refused")
            require(not (getattr(info, "st_file_attributes", 0) & 0x400), "reparse path is refused")
    return path


def read_file(path, maximum=MAX_FILE):
    path = checked_path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and 0 <= info.st_size <= maximum, "regular bounded file is required")
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    current = path.lstat()
    require(len(data) == info.st_size and len(data) <= maximum, "file changed or exceeded its limit")
    require((info.st_dev, info.st_ino, info.st_mtime_ns, info.st_size) ==
            (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_size) ==
            (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_size) ==
            (current.st_dev, current.st_ino, current.st_mtime_ns, current.st_size), "file changed during verification")
    return data


def digest(data):
    return hashlib.sha256(data).hexdigest()


def duplicate_safe(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def json_object(data):
    value = json.loads(data.decode("utf-8"), object_pairs_hook=duplicate_safe)
    require(isinstance(value, dict), "JSON object is required")
    return value


def context(version, repository, commit, ref, run_id, run_attempt, require_tag=False):
    require(RELEASE.fullmatch(version) is not None, "invalid release version")
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is not None, "invalid repository identity")
    require(re.fullmatch(r"[a-f0-9]{40}", commit) is not None, "invalid immutable commit")
    require(ref.startswith(("refs/tags/", "refs/heads/")) and len(ref) <= 256 and not any(ord(c) < 32 for c in ref), "invalid source ref")
    require(re.fullmatch(r"[1-9][0-9]{0,19}", str(run_id)) is not None, "invalid run ID")
    require(re.fullmatch(r"[1-9][0-9]{0,9}", str(run_attempt)) is not None, "invalid run attempt")
    if require_tag:
        require(repository == "sSOFTINn/ProjectAuditOrchestrator", "release repository differs")
        require(ref == "refs/tags/v" + version, "release requires the exact version tag; signature is checked separately")
    return {"version": version, "repository": repository, "commit": commit, "ref": ref,
            "run_id": str(run_id), "run_attempt": str(run_attempt)}


def asset_names(version):
    return sorted(["SHA256SUMS.txt", "pao-" + version + "-windows-amd64.zip",
                   "pao-" + version + "-linux-amd64.tar.gz"])


def exact_entries(directory, names):
    found = []
    for item in directory.iterdir():
        found.append(item.name)
        require(len(found) <= len(names), "too many directory entries")
    require(sorted(found) == sorted(names), "unexpected or missing directory entries")


def payload(directory, identity, build_metadata):
    directory = checked_path(directory)
    require(directory.is_dir(), "payload directory is required")
    names = asset_names(identity["version"])
    exact_entries(directory, names)
    data = {}
    remaining = MAX_TOTAL
    for name in names:
        data[name] = read_file(directory / name, min(MAX_FILE, remaining))
        remaining -= len(data[name])
    build_metadata = checked_path(build_metadata)
    require(directory not in build_metadata.parents, "private build metadata must be outside public payload")
    metadata = json_object(read_file(build_metadata, 16384))
    require(metadata.get("version") == identity["version"] and metadata.get("revision") == identity["commit"] and
            metadata.get("source_state") == "clean" and isinstance(metadata.get("source_tree_sha256"), str) and
            HEX.fullmatch(metadata["source_tree_sha256"]) is not None, "candidate source identity mismatch")
    checksums = {}
    for line in data["SHA256SUMS.txt"].decode("utf-8").splitlines():
        match = re.fullmatch(r"([a-f0-9]{64})  ([A-Za-z0-9_.-]+)", line)
        require(match is not None and match[2] not in checksums, "invalid checksum manifest")
        checksums[match[2]] = match[1]
    require(set(checksums) == set(names) - {"SHA256SUMS.txt"}, "checksum payload set mismatch")
    for name, expected in checksums.items():
        require(digest(data[name]) == expected, "checksum payload digest mismatch")
    return data, metadata["source_tree_sha256"]


def create(dist, output, identity, build_metadata):
    output = checked_path(output)
    dist = checked_path(dist)
    require(not output.exists(), "existing transfer directories are never overwritten")
    require(output != dist and dist not in output.parents and output not in dist.parents, "transfer and source directories overlap")
    data, source_digest = payload(dist, identity, build_metadata)
    manifest = {"schema_version": VERSION, "source": identity, "source_tree_sha256": source_digest,
                "files": [{"name": name, "bytes": len(data[name]), "sha256": digest(data[name])} for name in sorted(data)]}
    encoded = (json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("utf-8")
    output.mkdir(mode=0o700)
    (output / "payload").mkdir(mode=0o700)
    for name, content in data.items():
        with (output / "payload" / name).open("xb") as stream:
            stream.write(content)
    with (output / "transfer.json").open("xb") as stream:
        stream.write(encoded)
    verify(output, identity, digest(encoded), build_metadata)
    return digest(encoded)


def verify(path, identity, manifest_digest, build_metadata, artifact_id=None, artifact_digest=None):
    require(HEX.fullmatch(manifest_digest) is not None, "invalid expected transfer digest")
    if artifact_id is not None:
        require(re.fullmatch(r"[1-9][0-9]{0,19}", artifact_id) is not None, "invalid immutable artifact ID")
        require(isinstance(artifact_digest, str) and HEX.fullmatch(artifact_digest.removeprefix("sha256:")) is not None, "invalid artifact transport digest")
    path = checked_path(path)
    exact_entries(path, ["payload", "transfer.json"])
    raw = read_file(path / "transfer.json", 1 << 20)
    require(digest(raw) == manifest_digest, "transferred manifest differs from build output")
    manifest = json_object(raw)
    require(set(manifest) == {"schema_version", "source", "source_tree_sha256", "files"} and
            manifest["schema_version"] == VERSION and manifest["source"] == identity, "transfer source/ref/run identity mismatch")
    data, source_digest = payload(path / "payload", identity, build_metadata)
    expected = [{"name": name, "bytes": len(data[name]), "sha256": digest(data[name])} for name in sorted(data)]
    require(manifest["source_tree_sha256"] == source_digest and manifest["files"] == expected, "transferred payload identity mismatch")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("create", "verify"))
    for name in ("version", "repository", "commit", "ref", "run-id", "run-attempt"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--dist")
    parser.add_argument("--build-metadata", required=True)
    parser.add_argument("--output")
    parser.add_argument("--path")
    parser.add_argument("--manifest-digest")
    parser.add_argument("--artifact-id")
    parser.add_argument("--artifact-digest")
    parser.add_argument("--github-output")
    parser.add_argument("--require-tag", action="store_true")
    args = parser.parse_args()
    identity = context(args.version, args.repository, args.commit, args.ref, args.run_id, args.run_attempt, args.require_tag)
    if args.mode == "create":
        require(args.dist is not None and args.output is not None, "create requires dist and output")
        value = create(args.dist, args.output, identity, args.build_metadata)
        if args.github_output:
            with checked_path(args.github_output).open("a", encoding="utf-8", newline="\n") as stream:
                stream.write("manifest-digest=" + value + "\n")
    else:
        require(args.path is not None and args.manifest_digest is not None, "verify requires path and manifest digest")
        verify(args.path, identity, args.manifest_digest, args.build_metadata, args.artifact_id, args.artifact_digest)
    print("PASS: local public-payload identity and bytes verified; private evidence was not copied; signature and approval were not verified")


if __name__ == "__main__":
    main()
