import { Abi, WAF, silentLogger, type Mode } from '@coraza/core'
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
