import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs'
import { join, relative, sep } from 'node:path'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// PWA build step: after the bundle is written, walk dist/ and inject the
// concrete precache manifest + a cache-busting version into dist/sw.js (the
// template lives in public/sw.js).  Keeps the SW dependency-free and tiny.
function pwaServiceWorker() {
  let outDir = 'dist'
  return {
    name: 'ctf-learning-tree-pwa',
    apply: 'build',
    configResolved(config) {
      outDir = config.build.outDir
    },
    closeBundle() {
      const dist = join(process.cwd(), outDir)
      const files = []
      const walk = (dir) => {
        for (const name of readdirSync(dir)) {
          const full = join(dir, name)
          if (statSync(full).isDirectory()) walk(full)
          else files.push('/' + relative(dist, full).split(sep).join('/'))
        }
      }
      walk(dist)

      // Never precache the worker itself; it is fetched fresh on every update.
      const precache = files.filter((f) => f !== '/sw.js').sort()
      const version = Date.now().toString(36)

      const swPath = join(dist, 'sw.js')
      let sw = readFileSync(swPath, 'utf8')
      sw = sw
        .replace('/* __PRECACHE_MANIFEST__ */[]', JSON.stringify(precache, null, 2))
        .replace('__SW_VERSION__', version)
      writeFileSync(swPath, sw)
      this.warn(`PWA: precached ${precache.length} files into dist/sw.js (v${version})`)
    }
  }
}

export default defineConfig({
  plugins: [vue(), pwaServiceWorker()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8090',
        changeOrigin: true
      }
    }
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true
  }
})
