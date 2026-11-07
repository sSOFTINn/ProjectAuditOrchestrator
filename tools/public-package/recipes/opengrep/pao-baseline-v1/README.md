# PAO Opengrep baseline v1

This PAO-owned Apache-2.0 rule pack provides a small, high-confidence offline baseline for common
dangerous execution and transport patterns. It is deliberately narrower than a hosted or
language-complete commercial ruleset. A successful run means that every pinned rule executed; it
does not mean that every possible vulnerability class or language was covered.

The capsule manifest binds every file before a read-only `/pao/rules` mount. Rule updates require a
new manifest digest, synthetic validation and owner review.
