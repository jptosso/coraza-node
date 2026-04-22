---
'@coraza/core': patch
'@coraza/coreruleset': patch
---

Document the two CRS 4.24.0 `920640` test cases (`920640-4`, `920640-5`) as
FTW overrides under a new `[upstream-crs]` tag. Both tests are flagged by the
CRS corpus itself as "doesn't work with HTTP/1.1" (see the test YAML's own
description) and can only pass under HTTP/2, where go-ftw can send a
data-frame-length-encoded body independent of `Content-Length`. Investigation
of the Coraza `v3.3.3 → v3.7.0` diff confirmed the engine behaves identically
on these scenarios; the rule was newly introduced in CRS 4.24.0 so there was
no previous baseline to "regress" against. Verified with a standalone Go
reproducer running the full CRS stack on both engine versions.

Also bumps the pinned upstream versions on this branch to match `main`:
`coraza=3.7.0`, `coreruleset=4.25.0`.
