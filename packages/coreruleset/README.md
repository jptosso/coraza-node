# @coraza/coreruleset

SecLang config builder for the OWASP CoreRuleSet, tuned for Node.js.
Emits the `Include` directives + tuning knobs that tell the WASM-side
Coraza engine which CRS rules to load. No file I/O — CRS itself is
embedded inside [`@coraza/core`](https://www.npmjs.com/package/@coraza/core)'s
WASM binary.

```ts
import { recommended, strict } from '@coraza/coreruleset'

const rules = recommended({ paranoia: 1 })
// Drops REQUEST-*-APPLICATION-ATTACK-PHP/JAVA/DOTNET.conf by default
// (we're a Node stack), keeps every RESPONSE-*-DATA-LEAKAGES-*.conf so
// proxied errors from upstream services still get caught.
```

> **Experimental.** Independent community project, not an official
> OWASP / Coraza release.

Docs: <https://coraza-incubator.github.io/coraza-node>
· License: Apache-2.0
