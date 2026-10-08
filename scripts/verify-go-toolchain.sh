#!/usr/bin/env sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: scripts/verify-go-toolchain.sh PATH_TO_GO_ARCHIVE" >&2
  exit 2
fi

archive=$1
checksums=$(dirname "$0")/toolchain/go-1.27.1-checksums.txt
archive_name=$(basename "$archive")

if [ ! -f "$archive" ] || [ ! -f "$checksums" ]; then
  echo "archive or checksum pin is missing" >&2
  exit 2
fi

expected=$(awk -v name="$archive_name" '$2 == name { print $1; exit }' "$checksums")
if [ -z "$expected" ]; then
  echo "no checksum pin exists for archive: $archive_name" >&2
  exit 2
fi

if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$archive" | awk '{ print $1 }')
elif command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "$archive" | awk '{ print $1 }')
else
  echo "sha256sum or shasum is required" >&2
  exit 2
fi

if [ "$actual" != "$expected" ]; then
  echo "Go archive checksum mismatch for $archive_name" >&2
  exit 1
fi

printf '{"archive":"%s","sha256":"%s","status":"VERIFIED"}\n' "$archive_name" "$actual"
