// Default resolvers for the compiled Coraza WASM and the pool worker.
//
// Both ship inside `@coraza/core`'s `dist/` tree and are normally looked up
// via `new URL('./relative.path', import.meta.url)`. That call breaks under
// bundlers that rewrite `import.meta.url` to an empty / sentinel string —
// most notably Next.js 15's middleware bundler. The URL constructor then
// throws `TypeError: Invalid URL` or `unsupported URL protocol:`.
//
// The fallback resolves the asset through `createRequire(…)`, which uses
// Node's own module resolver and therefore doesn't care what the bundler
// did to `import.meta.url`. It needs a module we know is published: we
// resolve `@coraza/core/package.json` and compute the relative path from
// there. That works because the package.json entry is whitelisted by
// `"exports"` (see packages/core/package.json).
//
// Kept in its own file so both `waf.ts` and `pool.ts` share the exact same
// logic — bundler quirks don't distinguish between the two call sites.

import { createRequire } from 'node:module'
import { dirname, resolve as pathResolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const WASM_REL = 'dist/wasm/coraza.wasm'
const WORKER_REL = 'dist/pool-worker.mjs'

// `import.meta.url` only exists in ESM. In the CJS bundle tsup emits for
// this same file, referencing `import.meta` is a build-time error. Guard
// access behind a Function constructor so esbuild can't see through it.
// Returns the ESM URL when running as ESM, and undefined under CJS —
// which is fine because the CJS build paths resolve via `require`.
function readImportMetaUrl(): string | undefined {
  try {
    const fn = new Function(
      'return typeof import.meta !== "undefined" ? import.meta.url : undefined',
    ) as () => string | undefined
    return fn()
  } catch {
    return undefined
  }
}

/**
 * The value of `import.meta.url` is considered unusable when it's missing,
 * empty, or produces a URL whose protocol isn't a real loader target. Some
 * bundlers stub it to just `":"` or a blank string; others rewrite it to a
 * synthetic protocol like `webpack-internal:` that Node can't consume.
 * We only accept `file:` URLs — createRequire itself won't take anything
 * else, and `new URL(relative, anchor)` against a non-file anchor would
 * produce a non-file URL we can't readFile from anyway.
 */
function isUsableMetaUrl(metaUrl: string | undefined): metaUrl is string {
  if (!metaUrl) return false
  try {
    return new URL(metaUrl).protocol === 'file:'
  } catch {
    return false
  }
}

function resolveViaRequire(relative: string, metaUrl: string | undefined): URL {
  // Anchor createRequire on a URL we know Node will accept. We prefer
  // import.meta.url when it looks real; otherwise a cwd-based URL is
  // always usable. The resolution itself uses `@coraza/core/package.json`
  // (allowed by `"exports"`), so the anchor only dictates which
  // node_modules tree to walk.
  const anchor = isUsableMetaUrl(metaUrl)
    ? metaUrl
    : pathToFileURL(`${process.cwd()}/`).href
  const req = createRequire(anchor)
  const pkgJsonPath = req.resolve('@coraza/core/package.json')
  const pkgDir = dirname(pkgJsonPath)
  return pathToFileURL(pathResolve(pkgDir, relative))
}

function resolveAsset(relative: string, relativeFromMeta: string, metaUrl: string | undefined): URL {
  if (isUsableMetaUrl(metaUrl)) {
    try {
      const u = new URL(relativeFromMeta, metaUrl)
      if (u.protocol === 'file:') return u
    } catch {
      /* fall through */
    }
  }
  return resolveViaRequire(relative, metaUrl)
}

/**
 * Resolve the shipped `coraza.wasm` binary. Prefers
 * `new URL('./wasm/coraza.wasm', import.meta.url)` when the runtime exposes
 * a usable `import.meta.url`, falls back to `createRequire` when a bundler
 * has rewritten it. The returned URL always has a `file:` protocol.
 */
export function defaultWasmPath(): URL {
  return resolveAsset(WASM_REL, './wasm/coraza.wasm', readImportMetaUrl())
}

/**
 * Resolve the shipped `pool-worker.mjs`. Same fallback story as
 * {@link defaultWasmPath} — Next.js middleware rewrites import.meta.url
 * to a stub and we end up trying to construct an invalid URL.
 */
export function defaultPoolWorkerPath(): URL {
  return resolveAsset(WORKER_REL, './pool-worker.mjs', readImportMetaUrl())
}

/**
 * Test-only: override `import.meta.url` to exercise the fallback branch.
 * Exposed because `import.meta` itself is readonly in ESM so tests can't
 * stub it directly.
 */
export function defaultWasmPathWithMetaUrl(metaUrl: string | undefined): URL {
  return resolveAsset(WASM_REL, './wasm/coraza.wasm', metaUrl)
}

export function defaultPoolWorkerPathWithMetaUrl(metaUrl: string | undefined): URL {
  return resolveAsset(WORKER_REL, './pool-worker.mjs', metaUrl)
}

/**
 * Convert a `file:` URL (or duck-typed equivalent) to a filesystem path.
 *
 * Prefers Node's native `fileURLToPath`. Falls back to manual decoding when
 * the URL is an instance of a bundler-duplicated `URL` class — webpack and
 * Turbopack embed a second copy of `node:url` when middleware code is
 * bundled, so the URL fails Node's native `instanceof URL` check inside
 * `fileURLToPath` with `ERR_INVALID_ARG_TYPE`.
 *
 * The manual fallback handles three URL shapes:
 *
 *   POSIX:   file:///home/user/coraza.wasm   → /home/user/coraza.wasm
 *   Windows: file:///C:/Users/me/coraza.wasm → C:/Users/me/coraza.wasm
 *   Windows UNC: file://server/share/file    → //server/share/file
 *
 * The Windows shapes are the ones a hand-written `decodeURIComponent
 * (u.pathname)` gets wrong — `pathname` is `/C:/...` and Node's `readFile`
 * / `worker_threads.Worker` constructor then both reject the path. We
 * detect a leading drive-letter pattern (`/X:/...`) and strip the leading
 * slash; UNC URLs use `host` instead of leading-component pathname so
 * we reconstruct `//host/share/...` from `u.host` + `u.pathname`.
 */
export function urlToFsPath(u: URL | { protocol: string; pathname: string; host?: string; href?: string }): string {
  try {
    return fileURLToPath(u as URL)
  } catch {
    /* fall through to manual decode */
  }
  const pathname = decodeURIComponent(u.pathname)
  const host = u.host ?? ''
  // Windows UNC: file://server/share/path → \\server\share\path. Use the
  // forward-slash form because both Node fs and the Worker constructor
  // accept it on Windows, and it sidesteps any backslash-escaping
  // ambiguity in surrounding code.
  if (host && host !== '' && host !== 'localhost') {
    return `//${host}${pathname}`
  }
  // Windows drive letter: pathname is `/C:/Users/...` — strip the leading
  // slash so it becomes `C:/Users/...` which Node's fs accepts. Match
  // explicitly on `/<letter>:/` to avoid mangling a POSIX path that
  // legitimately contains a colon later in its first segment.
  if (/^\/[a-zA-Z]:[\/\\]/.test(pathname)) {
    return pathname.slice(1)
  }
  return pathname
}
