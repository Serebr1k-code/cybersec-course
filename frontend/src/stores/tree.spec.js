import { describe, it, expect, beforeEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useTreeStore } from './tree'
import { api } from '../api/client'

vi.mock('../api/client', () => ({
  api: { tree: vi.fn() }
}))

const NODES = [
  { id: 'a', title: 'A', category: 'web', parent: '', order: 1, sections: 2 },
  { id: 'b', title: 'B', category: 'web', parent: 'a', order: 2, sections: 3 },
  { id: 'c', title: 'C', category: 'web', parent: 'a', order: 1, sections: 1 },
  { id: 'd', title: 'D', category: 'net', parent: 'missing-parent', order: 1, sections: 1 }
]
const TREE = { categories: ['web', 'net'], nodes: NODES, total: 4 }

describe('stores/tree', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
    api.tree.mockResolvedValue(TREE)
  })

  it('load() populates categories, nodes, total, byId and loaded', async () => {
    const s = useTreeStore()
    await s.load()
    expect(api.tree).toHaveBeenCalledTimes(1)
    expect(s.categories).toEqual(['web', 'net'])
    expect(s.nodes.length).toBe(4)
    expect(s.total).toBe(4)
    expect(s.loaded).toBe(true)
    expect(s.loading).toBe(false)
    expect(s.error).toBeNull()
    expect(s.byId.a.title).toBe('A')
    expect(Object.keys(s.byId).sort()).toEqual(['a', 'b', 'c', 'd'])
  })

  it('node(id) getter returns the node or null', async () => {
    const s = useTreeStore()
    await s.load()
    expect(s.node('a').title).toBe('A')
    expect(s.node('nope')).toBeNull()
  })

  it('roots getter keeps orphans and parent-less nodes only', async () => {
    const s = useTreeStore()
    await s.load()
    const ids = s.roots.map((n) => n.id).sort()
    expect(ids).toEqual(['a', 'd'])
  })

  it('childrenOf() filters by parent and sorts by order then title', async () => {
    const s = useTreeStore()
    await s.load()
    expect(s.childrenOf('a').map((n) => n.id)).toEqual(['c', 'b'])
    expect(s.childrenOf('nope')).toEqual([])
  })

  it('nodesByCategory getter groups nodes per category', async () => {
    const s = useTreeStore()
    await s.load()
    const m = s.nodesByCategory
    expect(m.web.map((n) => n.id).sort()).toEqual(['a', 'b', 'c'])
    expect(m.net.map((n) => n.id)).toEqual(['d'])
  })

  it('load() is a no-op when already loaded (cache)', async () => {
    const s = useTreeStore()
    await s.load()
    await s.load()
    expect(api.tree).toHaveBeenCalledTimes(1)
  })

  it('load(true) forces a re-fetch', async () => {
    const s = useTreeStore()
    await s.load()
    await s.load(true)
    expect(api.tree).toHaveBeenCalledTimes(2)
  })

  it('sets error and clears loading when the API fails', async () => {
    const s = useTreeStore()
    api.tree.mockRejectedValueOnce(new Error('boom'))
    await s.load()
    expect(s.error).toBe('boom')
    expect(s.loading).toBe(false)
    expect(s.loaded).toBe(false)
  })

  it('tolerates a partial response (missing arrays)', async () => {
    const s = useTreeStore()
    api.tree.mockResolvedValueOnce({})
    await s.load()
    expect(s.categories).toEqual([])
    expect(s.nodes).toEqual([])
    expect(s.total).toBe(0)
    expect(s.loaded).toBe(true)
  })
})
