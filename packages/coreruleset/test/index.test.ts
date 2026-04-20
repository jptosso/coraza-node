import { describe, it, expect } from 'vitest'
import {
  recommended,
  balanced,
  strict,
  permissive,
  excludeByTag,
  excludeCategory,
  paranoia,
} from '../src/index.js'

describe('recommended()', () => {
  it('emits CRS includes + sensible defaults', () => {
    const out = recommended()
    expect(out).toContain('Include @coraza.conf-recommended')
    expect(out).toContain('Include @crs-setup.conf.example')
    expect(out).toContain('Include @owasp_crs/*.conf')
    expect(out).toContain('setvar:tx.blocking_paranoia_level=1')
    expect(out).toContain('setvar:tx.inbound_anomaly_score_threshold=5')
    expect(out).toContain('setvar:tx.outbound_anomaly_score_threshold=4')
  })

  it('excludes php, java, dotnet by default (keeps nodejs + generic)', () => {
    const out = recommended()
    expect(out).toContain('SecRuleRemoveByTag "language-php"')
    expect(out).toContain('SecRuleRemoveByTag "language-java"')
    expect(out).toContain('SecRuleRemoveByTag "language-dotnet"')
    expect(out).not.toContain('SecRuleRemoveByTag "language-nodejs"')
  })

  it('honors custom exclusion list', () => {
    const out = recommended({ exclude: ['iis'] })
    expect(out).toContain('SecRuleRemoveByTag "language-iis"')
    expect(out).not.toContain('SecRuleRemoveByTag "language-php"')
  })

  it('honors paranoia override', () => {
    expect(recommended({ paranoia: 3 })).toContain('setvar:tx.blocking_paranoia_level=3')
  })

  it('honors anomaly score overrides', () => {
    const out = recommended({ inboundAnomalyThreshold: 8, outboundAnomalyThreshold: 6 })
    expect(out).toContain('setvar:tx.inbound_anomaly_score_threshold=8')
    expect(out).toContain('setvar:tx.outbound_anomaly_score_threshold=6')
  })

  it('disables early blocking when anomalyBlock=false', () => {
    expect(recommended({ anomalyBlock: false })).toContain('setvar:tx.early_blocking=0')
    expect(recommended({ anomalyBlock: true })).not.toContain('setvar:tx.early_blocking=0')
  })

  it('appends extra directives when provided', () => {
    const out = recommended({ extra: 'SecRule REQUEST_URI "@contains /admin" "id:1,deny,status:403"' })
    expect(out).toContain('SecRule REQUEST_URI')
    expect(out.trim().endsWith('status:403"')).toBe(true)
  })

  it('ignores extra if empty/whitespace', () => {
    const out = recommended({ extra: '   ' })
    expect(out).not.toContain('SecRule REQUEST_URI')
  })
})

describe('presets', () => {
  it('balanced is paranoia 1', () => {
    expect(balanced()).toContain('paranoia_level=1')
  })

  it('balanced respects overrides', () => {
    expect(balanced({ paranoia: 4 })).toContain('paranoia_level=4')
  })

  it('strict is paranoia 2 with inbound threshold 3', () => {
    const out = strict()
    expect(out).toContain('paranoia_level=2')
    expect(out).toContain('inbound_anomaly_score_threshold=3')
  })

  it('strict respects overrides', () => {
    expect(strict({ paranoia: 4 })).toContain('paranoia_level=4')
  })

  it('permissive raises thresholds and disables early blocking', () => {
    const out = permissive()
    expect(out).toContain('inbound_anomaly_score_threshold=10')
    expect(out).toContain('outbound_anomaly_score_threshold=8')
    expect(out).toContain('tx.early_blocking=0')
  })

  it('permissive respects overrides', () => {
    expect(permissive({ paranoia: 2 })).toContain('paranoia_level=2')
  })
})

describe('low-level helpers', () => {
  it('excludeByTag builds the expected directives', () => {
    expect(excludeByTag(['a', 'b'])).toBe(
      'SecRuleRemoveByTag "a"\nSecRuleRemoveByTag "b"',
    )
  })

  it('excludeByTag handles empty arrays', () => {
    expect(excludeByTag([])).toBe('')
  })

  it('paranoia() builds a SecAction for a specific level', () => {
    expect(paranoia(4)).toContain('paranoia_level=4')
  })

  it('excludeCategory builds SecRuleRemoveById directive for a range', () => {
    expect(excludeCategory('scanner-detection')).toBe('SecRuleRemoveById 910000-913999')
    expect(excludeCategory('dos-protection')).toBe('SecRuleRemoveById 912000-912999')
    expect(excludeCategory('outbound-data-leak')).toBe('SecRuleRemoveById 950000-950999')
  })
})

describe('recommended() with excludeCategories', () => {
  it('emits SecRuleRemoveById for each category', () => {
    const out = recommended({
      excludeCategories: ['scanner-detection', 'dos-protection'],
    })
    expect(out).toContain('SecRuleRemoveById 910000-913999')
    expect(out).toContain('SecRuleRemoveById 912000-912999')
  })

  it('omits the block when no categories specified', () => {
    const out = recommended()
    expect(out).not.toContain('SecRuleRemoveById')
  })

  it('ignores an empty category array', () => {
    const out = recommended({ excludeCategories: [] })
    expect(out).not.toContain('SecRuleRemoveById')
  })
})
