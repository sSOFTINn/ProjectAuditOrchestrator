# MVP toolchain, license and redistribution register

This register describes the 0.3 preparation recipe, checked against publisher
sources on 2026-11-07. Exact artifact URLs, sizes and SHA-256 values are in
[the recipe](../../tools/public-package/recipes/manifest.json). Setup records
observed tool, database, rule and runtime digests before an explicit local
operator review. The current catalog is hash-bound JSON with recorded review
identity and expiry; it does not implement a cryptographic manifest signature.
This register grants no security, legal or redistribution approval.

## PAO build and bundled source

The reference toolchain is Go `1.27.3`. Its Windows and Linux AMD64 archive
SHA-256 values are recorded in `scripts/toolchain/go-1.27.3-checksums.txt`;
verification is offline through `scripts/verify-go-toolchain.ps1` or `.sh`.
The compiler archive is a development input, never downloaded by PAO setup.
All three PAO executables incorporate Go runtime/standard-library code under
the retained BSD-3-Clause license. The host also incorporates eight
Go 1.27.1 Zstandard decoder files: six unchanged, `zstd.go` modified to
support windows up to 128 MiB while rejecting larger windows before allocation,
and `bits.go` modified to avoid overflow while reading wide reverse-bitstream values.
Their [origin and hashes](../../internal/zstd/README.md)
and [license](../../internal/zstd/LICENSE) remain in the source tree.

The binary package includes the PAO-authored Apache-2.0 Opengrep sample pack
with five rules. This limited baseline is separate from externally downloaded
scanner software and does not establish comprehensive SAST coverage.

## Scanner contracts

All scanner binaries are downloaded separately by explicit setup and remain
`user-installed-only`; none is in the public PAO binary package. License labels
below identify the primary project software, not every embedded dependency.
The recipe links directly to the tagged upstream license or notice.

| Capability | Tool and exact version | Primary software terms | Evidence and scope |
|---|---|---|---|
| SBOM inventory | Syft 1.57.0 | Apache-2.0 | Native Syft JSON, tool digest and target snapshot; no synthetic BOM on failure |
| SBOM quality | sbomqs 2.1.1 | Apache-2.0 | Captured Syft CycloneDX input and linked JSON score; informational, no approval verdict |
| Deep SCA | Grype 0.118.0; OSV-Scanner 2.5.1 | Apache-2.0 | Native JSON and database digest/timestamp; current OSV preparation covers Go only |
| Filesystem vulnerabilities | Trivy 0.74.0 | Apache-2.0 | Native Trivy JSON; this adapter excludes IaC, image, secret and SARIF coverage |
| License/copyright | ScanCode 32.5.0 | Apache-2.0 software; CC-BY-4.0 reference data | Native JSON, exact license-data digest; [upstream NOTICE](https://raw.githubusercontent.com/aboutcode-org/scancode-toolkit/v32.5.0/NOTICE) also identifies separately licensed embedded packages |
| REUSE compliance | REUSE 6.2.0 | GPL-3.0-or-later | Native JSON/SPDX and prepared Python state; dependencies listed below |
| Secrets | Gitleaks 8.30.1 | MIT | Redacted native JSON, exact binary/configuration |
| SAST | Opengrep 1.29.0 | LGPL-2.1-only | Native JSON and runtime/state/rule digests; PAO sample rules remain Apache-2.0 |
| Workflow security | zizmor 1.29.0 | MIT | Native JSON and detector evidence; not applicable without workflow inputs |

## Inputs downloaded only by explicit setup

This is the bounded inventory of direct inputs declared in the current recipe.
It is not an exhaustive SBOM or license inventory of upstream release archives,
wheel contents or image layers. Existing upstream notices and package copyright
files must remain available for a human review of any later redistribution.

The base image is
`docker.io/library/python@sha256:05a994d2344eb364cc186910f4fc8786a38215f39f00d0acc25bff33a08f4177`.
It is a multi-license Python/Debian runtime. [Python's license record](https://docs.python.org/3.12/license.html)
includes PSF terms and incorporated-software notices; [the official image documentation](https://github.com/docker-library/docs/blob/master/python/README.md#license)
also calls out software from the base distribution and dependencies. The MIT
license of the Dockerfile repository is not an image-wide license. Debian
component terms are retained in the image's `/usr/share/doc/*/copyright` files;
the final prepared runtime requires its own inventory and review.

The recipe adds these Debian AMD64 packages, all version `14.2.0-19`:

| Package | Recorded terms/reference | Role |
|---|---|---|
| gcc-14-base | `LicenseRef-Debian-gcc-14-copyright` | Base/support documents; reference to the package copyright record, not a claim that every file has the runtime exception |
| libgcc-s1 | `GPL-3.0-or-later WITH GCC-exception-3.1` | GCC runtime library |
| libgomp1 | `GPL-3.0-or-later WITH GCC-exception-3.1` | OpenMP runtime library |

`LicenseRef-Debian-gcc-14-copyright` refers to the exact
[Debian gcc-14 14.2.0-19 copyright record](https://metadata.ftp-master.debian.org/changelogs/main/g/gcc-14/gcc-14_14.2.0-19_copyright).
It is an inventory reference to that multi-license record, not a newly granted
license. That record explicitly identifies the runtime terms for libgcc and
libgomp; it does not justify applying one exception expression to all GCC files.

The eleven direct REUSE preparation dependencies below are downloaded wheels.
Versions and license labels match the recipe and publisher release metadata;
Jinja's tagged license supplies its BSD-3-Clause terms.

| Input | Version | Declared primary terms | Publisher evidence |
|---|---|---|---|
| attrs | 26.1.0 | MIT | [Release metadata](https://pypi.org/pypi/attrs/26.1.0/json) |
| boolean.py | 5.0 | BSD-2-Clause | [Release metadata](https://pypi.org/pypi/boolean.py/5.0/json) |
| charset-normalizer | 3.5.1 | MIT | [Release metadata](https://pypi.org/pypi/charset-normalizer/3.5.1/json) |
| click | 8.5.0 | BSD-3-Clause | [Release metadata](https://pypi.org/pypi/click/8.5.0/json) |
| jinja2 | 3.1.6 | BSD-3-Clause | [Tagged license](https://raw.githubusercontent.com/pallets/jinja/3.1.6/LICENSE.txt) |
| license-expression | 30.4.4 | Apache-2.0 | [Release metadata](https://pypi.org/pypi/license-expression/30.4.4/json) |
| markupsafe | 3.0.3 | BSD-3-Clause | [Release metadata](https://pypi.org/pypi/markupsafe/3.0.3/json) |
| python-debian | 1.1.1 | GPL-2.0-or-later | [Release metadata](https://pypi.org/pypi/python-debian/1.1.1/json) |
| python-magic | 0.4.27 | MIT | [Release metadata](https://pypi.org/pypi/python-magic/0.4.27/json) |
| tomlkit | 0.15.1 | MIT | [Release metadata](https://pypi.org/pypi/tomlkit/0.15.1/json) |
| poetry-core | 2.2.1 | MIT | [Release metadata](https://pypi.org/pypi/poetry-core/2.2.1/json) |

## Advisory databases and review boundaries

Grype v6, Trivy schema 2 and the OSV Go export are separately downloaded data.
Their provider identities, content digests and actual upstream timestamps are
recorded during setup. A scanner's Apache-2.0 license does not assign the same
terms to all advisory records; provider/data terms remain a separate review.
No database is bundled with the PAO package.

No GPL/LGPL/AGPL/custom/source-available/unknown tool or dataset is approved for
redistribution merely because it runs out of process or passes a synthetic test.
Offline audits consume verified immutable local snapshots; connected preparation
is separate. Human security, legal and publication decisions remain distinct
from setup verification and from the local catalog's technical approval record.
