import type { Logger } from './types.js'

export const consoleLogger: Logger = {
  debug: (msg, meta) => console.debug('[coraza]', msg, meta ?? ''),
  info: (msg, meta) => console.info('[coraza]', msg, meta ?? ''),
  warn: (msg, meta) => console.warn('[coraza]', msg, meta ?? ''),
  error: (msg, meta) => console.error('[coraza]', msg, meta ?? ''),
}

export const silentLogger: Logger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
}
