// Shared test helpers: build a real @coraza/core WAF on top of the mock ABI.
// Keeps adapter tests focused on framework-adapter behavior, not WAF internals.

import { WAF, silentLogger, type Mode } from '@coraza/core'
import { Abi } from '@coraza/core/internal'
// The mock ABI lives in @coraza/core's test folder; we re-export through a
// relative path since it's not in the package's `exports` map.
// Vitest hoists, so relative paths from node_modules don't resolve — copy
// the mock file here if adapter tests need a different mock shape.
import { createMock, type MockOptions } from '../../core/test/mockAbi.js'

export function mockWAF(mode: Mode = 'block', opts: MockOptions = {}): {
  waf: WAF
  state: ReturnType<typeof createMock>['state']
} {
  const { exports, state } = createMock(opts)
  const abi = new Abi(exports)
  const waf = WAF.fromAbi(abi, '', mode, silentLogger)
  return { waf, state }
}
