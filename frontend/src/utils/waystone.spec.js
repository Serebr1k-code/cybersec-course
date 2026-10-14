import { describe, it, expect } from 'vitest'
import {
  isWaystone,
  gateTasks,
  gateTotal,
  gateSolved,
  isGateUnlocked,
  isGateLocked,
  gatedIds,
  hasLockedGate
} from './waystone'

// A tiny tree: gate "g" (waystone, tasks t1..t3) with child "c" which itself has
// child "d". Task lessons t1/t2/t3 are siblings of the gate, outside its subtree.
const NODES = [
  { id: 'root', parent: null },
  { id: 'g', parent: 'root', waystone: true, waystone_tasks: ['t1', 't2', 't3'] },
  { id: 'c', parent: 'g' },
  { id: 'd', parent: 'c' },
  { id: 't1', parent: 'root' },
  { id: 't2', parent: 'root' },
  { id: 't3', parent: 'root' }
]

const completed = (...ids) => (id) => ids.includes(id)

describe('utils/waystone — gate primitives', () => {
  it('detects a waystone node', () => {
    expect(isWaystone({ waystone: true })).toBe(true)
    expect(isWaystone({ waystone: false })).toBe(false)
    expect(isWaystone({})).toBe(false)
    expect(isWaystone(null)).toBe(false)
  })

  it('reads the task list and N', () => {
    const g = { waystone: true, waystone_tasks: ['a', 'b', 'c'] }
    expect(gateTasks(g)).toEqual(['a', 'b', 'c'])
    expect(gateTotal(g)).toBe(3)
    expect(gateTotal({})).toBe(0)
    // non-string / empty entries are dropped
    expect(gateTasks({ waystone_tasks: ['a', '', null, 3, 'b'] })).toEqual(['a', 'b'])
  })

  it('counts solved tasks', () => {
    const g = { waystone: true, waystone_tasks: ['a', 'b', 'c'] }
    expect(gateSolved(g, completed())).toBe(0)
    expect(gateSolved(g, completed('a'))).toBe(1)
    expect(gateSolved(g, completed('a', 'c'))).toBe(2)
    expect(gateSolved(g, completed('a', 'b', 'c'))).toBe(3)
  })

  it('is unlocked only when EVERY task is completed', () => {
    const g = { waystone: true, waystone_tasks: ['a', 'b'] }
    expect(isGateUnlocked(g, completed('a'))).toBe(false)
    expect(isGateUnlocked(g, completed('a', 'b'))).toBe(true)
    expect(isGateLocked(g, completed('a'))).toBe(true)
    expect(isGateLocked(g, completed('a', 'b'))).toBe(false)
  })

  it('treats a waystone with no tasks as inert (never locks)', () => {
    const g = { waystone: true, waystone_tasks: [] }
    expect(isGateUnlocked(g, completed())).toBe(true)
    expect(isGateLocked(g, completed())).toBe(false)
    // a non-waystone is never locked either
    expect(isGateLocked({ id: 'x' }, completed())).toBe(false)
  })
})

describe('utils/waystone — gatedIds (the hidden subtree)', () => {
  it('hides the whole descendant subtree of a locked waystone', () => {
    const gated = gatedIds(NODES, completed())
    expect([...gated].sort()).toEqual(['c', 'd'])
    // the gate node itself stays visible (it carries the indicator)
    expect(gated.has('g')).toBe(false)
  })

  it('reveals the subtree once every task is solved', () => {
    expect(gatedIds(NODES, completed('t1', 't2', 't3')).size).toBe(0)
  })

  it('keeps hiding while the gate is only partly solved', () => {
    expect([...gatedIds(NODES, completed('t1', 't2'))].sort()).toEqual(['c', 'd'])
  })

  it('ignores an inert gate (no tasks)', () => {
    const nodes = [{ id: 'g', parent: null, waystone: true, waystone_tasks: [] }, { id: 'c', parent: 'g' }]
    expect(gatedIds(nodes, completed()).size).toBe(0)
  })

  it('supports nested waystones (an inner gate inside a locked outer one)', () => {
    const nodes = [
      { id: 'outer', parent: null, waystone: true, waystone_tasks: ['x'] },
      { id: 'mid', parent: 'outer' },
      { id: 'inner', parent: 'mid', waystone: true, waystone_tasks: ['y'] },
      { id: 'deep', parent: 'inner' },
      { id: 'x', parent: null },
      { id: 'y', parent: null }
    ]
    // outer locked -> mid/inner/deep hidden
    expect([...gatedIds(nodes, completed())].sort()).toEqual(['deep', 'inner', 'mid'])
    // outer open, inner locked -> only inner's subtree hidden
    expect([...gatedIds(nodes, completed('x'))].sort()).toEqual(['deep'])
    // both open -> nothing hidden
    expect(gatedIds(nodes, completed('x', 'y')).size).toBe(0)
  })

  it('treats a node with a missing parent as a root', () => {
    const nodes = [{ id: 'g', parent: 'ghost', waystone: true, waystone_tasks: ['t'] }, { id: 'c', parent: 'g' }]
    expect([...gatedIds(nodes, completed())].sort()).toEqual(['c'])
  })
})

describe('utils/waystone — hasLockedGate', () => {
  it('reports whether any waystone is currently locked', () => {
    expect(hasLockedGate(NODES, completed())).toBe(true)
    expect(hasLockedGate(NODES, completed('t1', 't2', 't3'))).toBe(false)
    expect(hasLockedGate([{ id: 'x' }], completed())).toBe(false)
  })
})
