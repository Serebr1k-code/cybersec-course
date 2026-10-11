import { defineStore } from 'pinia'
import { api } from '../api/client'

export const useTreeStore = defineStore('tree', {
  state: () => ({
    categories: [],
    nodes: [],
    total: 0,
    loaded: false,
    loading: false,
    error: null,
    byId: {}
  }),
  getters: {
    node: (s) => (id) => s.byId[id] || null,
    childrenOf: (s) => (id) => s.nodes.filter((n) => n.parent === id).sort((a, b) => (a.order - b.order) || a.title.localeCompare(b.title)),
    nodesByCategory: (s) => {
      const m = {}
      for (const n of s.nodes) (m[n.category] ||= []).push(n)
      return m
    },
    roots: (s) => s.nodes.filter((n) => !n.parent || !s.byId[n.parent])
  },
  actions: {
    async load(force = false) {
      if (this.loaded && !force) return
      this.loading = true
      try {
        const t = await api.tree()
        this.categories = t.categories || []
        this.nodes = t.nodes || []
        this.total = t.total || 0
        this.byId = Object.fromEntries(this.nodes.map((n) => [n.id, n]))
        this.loaded = true
        this.error = null
      } catch (e) {
        this.error = e.message
      } finally {
        this.loading = false
      }
    }
  }
})
