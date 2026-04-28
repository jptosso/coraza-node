---
---

Docs: refresh every README + the static docs site for `0.1.0-preview.3`.
No code changes — pure docs / READMEs / HTML. Pinned versions in install
snippets, propagated the canonical "Skipping the WAF" (`ignore:`) table to
every adapter README, removed Next 14 from the @coraza/next supported
matrix and from docs site copy, dropped the `wasmSource:` workaround
(default loader is bundler-resilient since preview.2), corrected the
@coraza/express README's claim that the response phase runs by default
(`inspectResponse` defaults to `false`), bumped the docs site CRS pill
from 4.10 to 4.25, added `examples/next15-app/README.md` and
`examples/next16-app/README.md`, fixed the WS leftover line in
`examples/express-app/README.md`, refreshed the AGENTS.md "Where to
touch what" table for the `ignore.ts` move and the new matrix /
example layout, and brought `testing/matrix/README.md` in line with the
shipped 10-case set.
