# Windows state-directory ACL policy

PAO raw evidence, run locks and policy decisions can contain sensitive technical data. On Windows,
the state-directory owner must be the only ordinary account with write access. A service account may
be added only through documented provisioning; broad write grants to `Everyone`, `BUILTIN\Users` or
`NT AUTHORITY\Authenticated Users` are prohibited.

The rule applies to the state root and every child directory and file. The target repository is not used as a
state directory, and PAO must never compensate for missing access control with a weaker execution
mode.

`scripts/verify-state-acl.ps1` creates an isolated temporary fixture, assigns an owner-only ACL,
and verifies that the prohibited principals have no write, create, append, delete, ownership-change,
or permission-change rights. It identifies Everyone (`S-1-1-0`), Users (`S-1-5-32-545`), and
Authenticated Users (`S-1-5-11`) by SID, independently of Windows display language. Explicit and
inherited grants are checked throughout the tree; reparse points in the tree or its ancestor path
are refused before traversal. A deny entry does not cancel an unsafe allow grant for this policy check.
In CI the fixture tests the mechanism without touching a real audit state directory. During
installation, run the same script with `-StateDirectory <absolute path>` after provisioning the real
state root; it is read-only in that mode. Use `-FixtureRoot <absolute staging path>` to place the
generated fixture under a selected staging directory. `scripts/test-state-acl.ps1 -OutputBase
<absolute staging path>` exercises owner-only success, SID rejection, unsafe child directory/file
grants, and root/child/ancestor junction refusal using synthetic data.

This is a broad-write-grant check, not a complete effective-access calculation. A read-only grant
does not count as a write grant; restrictions on disclosure to readers or grants to other named
accounts must also be verified during provisioning. Run with the state tree quiescent: concurrent
changes are outside this snapshot verification and require a separate operational control.

This control verifies ACL entries, not encryption-at-rest, backup access, administrator access, or
remote sharing policy. Those controls require separate operational review before a production
release.
