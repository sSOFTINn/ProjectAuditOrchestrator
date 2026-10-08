# Hostile repository corpus

These synthetic fixtures represent untrusted target properties. They are never executed.

- `instruction-injection/AGENTS.md` must be treated as file metadata only.
- `path-escape/` is exercised by unit tests that create platform-native external links; no
  committed link is required because Windows link privileges vary by runner.
- output-bomb and NUL-argument fixtures live in their trusted-core tests, where their size and
  process boundaries can be asserted without invoking an external process.
