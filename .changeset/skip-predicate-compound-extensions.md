---
'@coraza/core': patch
---

Document `buildSkipPredicate` / `SkipOptions` extension match semantics on the
type itself (case-insensitive, query/fragment ignored, only the trailing
basename segment matches) and add support for **compound extensions**.

Entries containing a dot (e.g. `'tar.gz'`, `'min.js'`, `'d.ts'`) now match as a
`.<ext>` suffix on the path's basename. The leading `.` is required, so
`extensions: ['min.js']` skips `/bundle.min.js` but **does not** skip a request
whose pathname is literally `/min.js` (that's the bare filename, not a
`.min.js` extension). Single-token entries (`'css'`, `'png'`) keep their
existing behavior.

Closes #28.
