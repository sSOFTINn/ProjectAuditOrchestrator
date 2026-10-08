# Security policy

Report vulnerabilities through a
[private GitHub Security Advisory](https://github.com/sSOFTINn/ProjectAuditOrchestrator/security/advisories/new).
Do not use public issues for exploit details, tokens, private paths or raw audit evidence.
Include the affected PAO version, platform, a minimal synthetic reproduction and impact.
The maintainer must confirm that private reporting is enabled before public release;
this document does not prove the repository setting. If the form is unavailable,
withhold sensitive details rather than posting them publicly.

Security fixes target the latest published stable release. Older versions are
unsupported; prereleases are evaluation candidates without a stable support promise.
No stable-release support claim is made merely by preparing a local candidate.

PAO treats audit targets as untrusted input and defaults to read-only, offline,
non-executing inspection. Scanner execution requires verified isolation and exact
run-specific approval. Missing coverage is not a clean result. PAO has no telemetry
or automatic updater; users obtain, verify and install updates manually.
A scan result is not a guarantee of absence of vulnerabilities or legal compliance.

See [threat model](docs/security/threat-model.md) for the maintained attack surface and controls.
