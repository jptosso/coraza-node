import { describe, it, expect, vi } from 'vitest'
import { consoleLogger, silentLogger } from '../src/logger.js'

describe('consoleLogger', () => {
  it('forwards to console.* with a coraza prefix', () => {
    const debug = vi.spyOn(console, 'debug').mockImplementation(() => {})
    const info = vi.spyOn(console, 'info').mockImplementation(() => {})
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})

    consoleLogger.debug('d', { a: 1 })
    consoleLogger.debug('d2') // without meta — exercise nullish branch
    consoleLogger.info('i')
    consoleLogger.info('i2', { c: 3 })
    consoleLogger.warn('w', { b: 2 })
    consoleLogger.warn('w2')
    consoleLogger.error('e')
    consoleLogger.error('e2', { d: 4 })

    expect(debug).toHaveBeenCalledWith('[coraza]', 'd', { a: 1 })
    expect(info).toHaveBeenCalledWith('[coraza]', 'i', '')
    expect(warn).toHaveBeenCalledWith('[coraza]', 'w', { b: 2 })
    expect(error).toHaveBeenCalledWith('[coraza]', 'e', '')

    debug.mockRestore()
    info.mockRestore()
    warn.mockRestore()
    error.mockRestore()
  })
})

describe('silentLogger', () => {
  it('is a noop on every level', () => {
    silentLogger.debug('x')
    silentLogger.info('x')
    silentLogger.warn('x')
    silentLogger.error('x')
  })
})
