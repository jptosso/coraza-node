import { describe, it, expect } from 'vitest'
import {
  ftwEcho,
  ftwModeEnabled,
  handlers,
  benchScenarios,
  SAMPLE_PNG,
} from '../src/index.js'

describe('example shared handlers', () => {
  it('root returns the adapter name so benchmarks can tell apps apart', () => {
    expect(handlers.root('express')).toEqual({ body: { ok: true, name: 'express' } })
    expect(handlers.root('fastify')).toEqual({ body: { ok: true, name: 'fastify' } })
  })

  it('healthz returns plain-text ok', () => {
    expect(handlers.healthz()).toEqual({ body: 'ok', contentType: 'text/plain' })
  })

  it('search echoes the query and its length, coerces undefined to empty', () => {
    expect(handlers.search('hello')).toEqual({ body: { q: 'hello', len: 5 } })
    expect(handlers.search(undefined)).toEqual({ body: { q: '', len: 0 } })
    expect(handlers.search('')).toEqual({ body: { q: '', len: 0 } })
  })

  it('echo round-trips whatever it gets, defaulting null/undefined to {}', () => {
    expect(handlers.echo({ a: 1 })).toEqual({ body: { a: 1 } })
    expect(handlers.echo(null)).toEqual({ body: {} })
    expect(handlers.echo(undefined)).toEqual({ body: {} })
    expect(handlers.echo('string')).toEqual({ body: 'string' })
  })

  it('upload reports byte count', () => {
    expect(handlers.upload(0)).toEqual({ body: { bytes: 0 } })
    expect(handlers.upload(1024)).toEqual({ body: { bytes: 1024 } })
  })

  it('image returns a valid PNG byte sequence', () => {
    const r = handlers.image()
    expect(r.status).toBe(200)
    expect(r.contentType).toBe('image/png')
    const body = r.body as Buffer
    // PNG signature: 89 50 4e 47 0d 0a 1a 0a
    expect(body[0]).toBe(0x89)
    expect(body[1]).toBe(0x50)
    expect(body[2]).toBe(0x4e)
    expect(body[3]).toBe(0x47)
    // Same bytes as the exported constant so adapters can use either.
    expect(body).toEqual(SAMPLE_PNG)
  })

  it('user echoes the id parameter', () => {
    expect(handlers.user('42')).toEqual({ body: { id: '42' } })
    expect(handlers.user('abc')).toEqual({ body: { id: 'abc' } })
  })
})

describe('bench scenarios catalogue', () => {
  it('includes one clean and one attack variant per route that takes user input', () => {
    const labels = benchScenarios.map((s) => s.label)
    expect(labels).toContain('search-clean')
    expect(labels).toContain('search-sqli')
    expect(labels).toContain('echo-json')
    expect(labels).toContain('echo-xss')
  })

  it('attack scenarios use canonical OWASP payload shapes the CRS recognises', () => {
    const sqli = benchScenarios.find((s) => s.label === 'search-sqli')!
    expect(sqli.path).toMatch(/OR\+1=1/)
    const xss = benchScenarios.find((s) => s.label === 'echo-xss')!
    expect((xss as { body: { msg: string } }).body.msg).toContain('<script>')
  })

  it('every scenario is a valid method + path', () => {
    for (const s of benchScenarios) {
      expect(['GET', 'POST']).toContain(s.method)
      expect(s.path.startsWith('/')).toBe(true)
    }
  })
})

describe('FTW mode helpers', () => {
  it('ftwModeEnabled is true only when FTW=1, not for any other truthy value', () => {
    expect(ftwModeEnabled({ FTW: '1' })).toBe(true)
    expect(ftwModeEnabled({ FTW: '0' })).toBe(false)
    expect(ftwModeEnabled({ FTW: 'true' })).toBe(false)
    expect(ftwModeEnabled({})).toBe(false)
  })

  it('ftwEcho round-trips the request shape the go-ftw corpus expects', () => {
    const r = ftwEcho({
      method: 'POST',
      url: '/attack?q=1',
      headers: { 'content-type': 'text/xml' },
      body: '<?xml version="1.0"?><x/>',
    })
    expect(r.status).toBe(200)
    expect(r.contentType).toBe('application/json')
    expect(r.body).toEqual({
      method: 'POST',
      url: '/attack?q=1',
      headers: { 'content-type': 'text/xml' },
      body: '<?xml version="1.0"?><x/>',
    })
  })
})
