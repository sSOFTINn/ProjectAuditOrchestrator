# Synthetic test corpus design

Fixtures contain no real secrets, PII, credentials, customer data or copied proprietary source.

- `hostile-repos/`: prompt-injection filenames/content, traversal, symlink/junction escape, Unicode/space/long/UNC paths, archive/output bombs and malformed metadata.
- `license-corpus/`: exact SPDX distinctions, dual license, AGPL SaaS assumption, LGPL modification, custom/unknown metadata, unlicensed asset, synthetic PII dataset and model provenance gaps.
- `scanner-outputs/`: pinned success/empty/partial/error/malformed raw outputs for each adapter version.

Every fixture has an expected status, coverage assertion, target pre/post manifest and a redaction expectation. No fixture executes target code.
