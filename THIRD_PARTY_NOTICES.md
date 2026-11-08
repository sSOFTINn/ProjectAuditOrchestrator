# Third-party notices

PAO-authored source and documentation use Apache-2.0. Third-party files retain
their own licenses and attribution. A binary archive and a source archive have
different inventories; neither inventory is a security or legal approval.

## Binary archives

Each Windows AMD64 ZIP and Linux AMD64 tar.gz contains three PAO-owned executables:
the host PAO command and the static Linux AMD64 `pao-sandbox-linux-amd64`
supervisor and `pao-probe-linux-amd64` synthetic probe used inside the reviewed
Linux VM. All three include Go runtime and
standard-library code. The exact candidate toolchain is Go 1.27.3; each archive
preserves that toolchain's BSD-style license at `licenses/GO-LICENSE.txt`.
The host PAO also incorporates eight Go 1.27.1 `src/internal/zstd` decoder
files under those terms. Six are unchanged; PAO modifies `zstd.go` to support
windows up to 128 MiB and reject larger windows before allocation, and `bits.go`
to avoid overflow while reading wide reverse-bitstream values. The source distribution
retains [the license](internal/zstd/LICENSE), copyright headers and
[exact hashes and origin](internal/zstd/README.md). This is a runtime source
dependency for database preparation, although it is not a Go module dependency.
Public `VERSION.json`, binary build info and checksums identify the actual
payload; `BUILD-METADATA.json` is retained as separate internal evidence.

The Go core has no third-party `require` entries in `go.mod`. This does not
exclude Go runtime/stdlib from its inventory. The archive does not contain
external scanner binaries, runtime images, third-party rule packs, advisory databases,
Python wheels or cached upstream JSON schemas. It includes PAO-authored
preparation recipes and a PAO-authored Apache-2.0 sample Opengrep pack with
five rules, its license and its file manifest; external
artifacts named by recipes are obtained only by explicit online setup.
Scanner/data terms remain
separate in the [toolchain register](docs/legal/toolchain-register.md) and
[integration policy](docs/legal/third-party-integration-policy.md). PAO's license
does not grant those rights.

Online setup inputs include a digest-pinned Python/Debian base image,
three pinned Debian packages and eleven direct REUSE dependencies. These
are downloaded separately and are absent from the binary archive. The image
has multiple component licenses; the Dockerfile repository's MIT license
does not describe all software inside the image. The
[setup-input inventory](docs/legal/toolchain-register.md#inputs-downloaded-only-by-explicit-setup)
records the exact recipe versions and links to publisher terms. It is a
bounded inventory of recipe inputs, not an exhaustive license inventory of
all software embedded in upstream binaries, archives or runtime layers.

## Source-only development and validation material

The source tree includes these third-party development resources. They are
excluded from the public binary payload.

| Component | Exact identity | Terms and preserved attribution | Role |
| --- | --- | --- | --- |
| CycloneDX schemas | BOM 1.5 and referenced SPDX/JSF schemas; revision `c320fc0f0b46873864927d9d5684eea7ba439728` | Apache-2.0; [preserved license](schemas/vendor/licenses/CycloneDX-LICENSE.txt); JSF attribution to Anders Rundgren/OpenKeyStore remains in the unchanged schema | Offline format validation |
| SPDX schema | SPDX 2.3; revision `aadf3b0b8dbbabdb4d880b0fc714255fea436ff7` | CC-BY-3.0; SPDX project; [preserved license](schemas/vendor/licenses/SPDX-LICENSE.txt) | Offline format validation |
| OASIS SARIF schema | SARIF 2.1.0, OASIS Standard 2020-03-27 | OASIS Open 2020 copyright and [preserved OASIS notices](schemas/vendor/licenses/OASIS-SARIF-NOTICES.txt); not relabeled Apache-2.0 | Offline format validation |
| jsonschema | 4.17.3 | MIT; [COPYING](schemas/vendor/licenses/jsonschema-0-COPYING) | Python validator |
| attrs | 23.2.0 | MIT; [LICENSE](schemas/vendor/licenses/attrs-0-LICENSE) | Validator dependency |
| pyrsistent | 0.20.0 | MIT; [LICENSE.mit](schemas/vendor/licenses/pyrsistent-0-LICENSE.mit) | Validator dependency |
| rfc3339-validator | 0.1.4 | MIT; [LICENSE](schemas/vendor/licenses/rfc3339-validator-0-LICENSE) | Format check |
| rfc3986-validator | 0.1.1 | MIT; [LICENSE](schemas/vendor/licenses/rfc3986-validator-0-LICENSE) | Format check |
| six | 1.17.0 | MIT; [LICENSE](schemas/vendor/licenses/six-0-LICENSE) | Validator dependency |
| rfc3987-syntax | 1.1.0 | MIT; [LICENSE](schemas/vendor/licenses/rfc3987-syntax-0-LICENSE) | Format check |
| lark | 1.2.2 | MIT; [LICENSE](schemas/vendor/licenses/lark-0-LICENSE) | Format parser |

All cached upstream schemas, wheels, license texts, exact source URLs and SHA-256
are recorded in [schemas/vendor/pins.json](schemas/vendor/pins.json). The cached
schema bytes are unchanged. [The source-only schema harness](scripts/schema/README.md)
uses those exact local resources without `pip install` or network resolution.
Preserve the original copyright/license texts and pin record
with source distribution. Attribution and retained texts support human
redistribution review; final security/license approval remains open.
