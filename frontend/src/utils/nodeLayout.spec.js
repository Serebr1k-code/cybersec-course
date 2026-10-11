import { describe, it, expect } from 'vitest'
import { nodeLines, nodeHeight, MAX_LINES, MIN_NODE_H } from './nodeLayout'

describe('utils/nodeLayout.js — variable node sizing', () => {
  it('estimates a single line for short titles', () => {
    expect(nodeLines('SQL-инъекции')).toBe(1)
    expect(nodeLines('XSS')).toBe(1)
    expect(nodeLines('')).toBe(1)
    expect(nodeLines(null)).toBe(1)
  })

  it('grows the estimate with the title length', () => {
    const short = nodeLines('Основы HTTP')
    const long = nodeLines('Архитектура веб-приложений: клиент, сервер, БД, прокси')
    expect(long).toBeGreaterThan(short)
    expect(long).toBeGreaterThanOrEqual(2)
  })

  it('caps the line estimate so a node never grows unbounded', () => {
    const huge = 'Кодирования вглубь: base16/32/64/85, ascii85, uuencode, quoted-printable и кастомные алфавиты'
    expect(nodeLines(huge)).toBe(MAX_LINES)
    expect(nodeLines('a '.repeat(400))).toBe(MAX_LINES)
  })

  it('returns a taller reserved height for longer titles', () => {
    const oneLine = nodeHeight({ title: 'XSS' })
    const twoLine = nodeHeight({ title: 'Основы HTTP и анатомия веб-запроса' })
    const manyLine = nodeHeight({ title: 'Request Smuggling advanced: TE.TE, TE.CL, CL.0, response-queue poisoning' })
    expect(oneLine).toBeLessThan(twoLine)
    expect(twoLine).toBeLessThanOrEqual(manyLine)
    // 1 line -> 65px, 2 -> 82px, 3 -> 99px, 4 -> 116px
    expect(oneLine).toBe(65)
    expect(twoLine).toBe(82)
    expect(manyLine).toBe(116)
  })

  it('never reserves less than the minimum node height', () => {
    expect(nodeHeight({ title: '' })).toBeGreaterThanOrEqual(MIN_NODE_H)
    expect(nodeHeight({})).toBeGreaterThanOrEqual(MIN_NODE_H)
    expect(nodeHeight(null)).toBeGreaterThanOrEqual(MIN_NODE_H)
  })

  it('accepts a narrower content width (the radial card wraps into more lines)', () => {
    const title = 'Продвинутая бизнес-логика: workflow bypass, currency rounding, limit-overrun'
    const wide = nodeLines(title)
    const narrow = nodeLines(title, { contentWidth: 128, maxLines: 6 })
    expect(narrow).toBeGreaterThan(wide)
  })

  it('scales character widths for a smaller font (radial card is 11.5px)', () => {
    const title = 'Request Smuggling advanced: TE.TE, TE.CL, CL.0, response-queue poisoning'
    const raw = nodeLines(title, { contentWidth: 128, maxLines: 6 })
    const scaled = nodeLines(title, { contentWidth: 128, maxLines: 6, scale: 11.5 / 13.5 })
    expect(scaled).toBeLessThanOrEqual(raw)
  })

  it('honours a raised line cap and reserves a taller node', () => {
    const huge = 'Кодирования вглубь: base16/32/64/85, ascii85, uuencode, quoted-printable и кастомные алфавиты'
    expect(nodeLines(huge, { maxLines: 6 })).toBeLessThanOrEqual(6)
    const capped4 = nodeHeight({ title: huge })
    const capped6 = nodeHeight({ title: huge }, { contentWidth: 128, maxLines: 6 })
    expect(capped6).toBeGreaterThan(capped4)
  })

  it('supports compact box metrics for the small radial card', () => {
    const opts = { contentWidth: 126, maxLines: 3, scale: 11 / 13.5, pad: 10, lineHeight: 13, metaHeight: 13, minHeight: 40 }
    // 1 line -> floor, 2 -> 49, 3 -> 62 (never the 65/82/99 of the 224px node)
    expect(nodeHeight({ title: 'XSS' }, opts)).toBe(40)
    expect(nodeHeight({ title: 'Основы веб-безопасности' }, opts)).toBe(49)
    const huge = 'Request Smuggling advanced: TE.TE, TE.CL, CL.0, response-queue poisoning and HTTP/2 downgrade'
    expect(nodeHeight({ title: huge }, opts)).toBe(62)
    // defaults are untouched
    expect(nodeHeight({ title: 'XSS' })).toBe(65)
  })
})
