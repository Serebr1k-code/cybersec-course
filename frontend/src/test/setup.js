// Vitest global setup.
//
// Node 25 exposes its own (non-functional without --localstorage-file) `localStorage`
// global, which shadows jsdom's Storage and makes `localStorage.getItem` undefined.
// The app (src/stores/progress.js) uses the bare global, so we install a small
// in-memory Storage on both `globalThis` and `window` to give tests a real store.

class MemoryStorage {
  constructor() {
    this._m = new Map()
  }
  get length() {
    return this._m.size
  }
  key(i) {
    return Array.from(this._m.keys())[i] ?? null
  }
  getItem(k) {
    const key = String(k)
    return this._m.has(key) ? this._m.get(key) : null
  }
  setItem(k, v) {
    this._m.set(String(k), String(v))
  }
  removeItem(k) {
    this._m.delete(String(k))
  }
  clear() {
    this._m.clear()
  }
}

function installStorage(name) {
  const store = new MemoryStorage()
  for (const target of [globalThis, typeof window !== 'undefined' ? window : null]) {
    if (!target) continue
    try {
      Object.defineProperty(target, name, {
        value: store,
        configurable: true,
        writable: true,
        enumerable: true
      })
    } catch {
      /* ignore read-only globals */
    }
  }
}

installStorage('localStorage')
installStorage('sessionStorage')
