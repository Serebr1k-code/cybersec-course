/* CTF Learning Tree service worker.
 *
 * Hand-written (no build dependency).  The `PRECACHE` list and `VERSION` are
 * injected at build time by the small Vite plugin in vite.config.js, which
 * walks dist/ after the bundle is written.  Strategies:
 *
 *   /api/*        -> network-first (content stays fresh; cached copy offline)
 *   navigations   -> network-first, fall back to the precached app shell
 *   other assets  -> cache-first (Vite emits content-hashed, immutable files)
 *
 * The precache holds the app shell (index.html + hashed JS/CSS) so the app
 * loads offline.  The Go server serves sw.js / index.html with `no-cache`, so
 * a new deploy is always picked up on the next visit.
 */

const VERSION = '__SW_VERSION__'
const CACHE = 'ctf-learning-tree-' + VERSION
const API_CACHE = 'ctf-learning-tree-api'
const PRECACHE = /* __PRECACHE_MANIFEST__ */[]

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches
      .open(CACHE)
      .then((cache) => cache.addAll(PRECACHE))
      .then(() => self.skipWaiting())
  )
})

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(
          keys
            .filter((key) => key !== CACHE && key !== API_CACHE)
            .map((key) => caches.delete(key))
        )
      )
      .then(() => self.clients.claim())
  )
})

self.addEventListener('fetch', (event) => {
  const req = event.request
  if (req.method !== 'GET') return

  const url = new URL(req.url)
  if (url.origin !== self.location.origin) return

  if (url.pathname.startsWith('/api/')) {
    event.respondWith(networkFirst(req, API_CACHE))
    return
  }

  if (req.mode === 'navigate') {
    event.respondWith(navigationHandler(req))
    return
  }

  event.respondWith(cacheFirst(req))
})

// Network-first with a cached fallback so offline still works.
async function networkFirst(req, cacheName) {
  const cache = await caches.open(cacheName)
  try {
    const res = await fetch(req)
    if (res && res.ok) cache.put(req, res.clone())
    return res
  } catch (err) {
    const cached = await cache.match(req)
    if (cached) return cached
    throw err
  }
}

// Keep the app shell fresh when online; serve the precached shell offline.
async function navigationHandler(req) {
  try {
    const res = await fetch(req)
    if (res && res.ok) {
      const cache = await caches.open(CACHE)
      cache.put('/index.html', res.clone())
    }
    return res
  } catch (err) {
    const shell = await caches.match('/index.html')
    if (shell) return shell
    throw err
  }
}

// Hashed build assets are immutable: serve from cache, populate on miss.
async function cacheFirst(req) {
  const cache = await caches.open(CACHE)
  const cached = await cache.match(req)
  if (cached) return cached
  try {
    const res = await fetch(req)
    if (res && res.ok) cache.put(req, res.clone())
    return res
  } catch (err) {
    const shell = await caches.match('/index.html')
    if (shell) return shell
    throw err
  }
}
