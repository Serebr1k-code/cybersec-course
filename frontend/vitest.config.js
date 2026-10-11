import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  test: {
    environment: 'jsdom',
    globals: true,
    include: ['src/**/*.{test,spec}.{js,mjs}'],
    setupFiles: ['src/test/setup.js'],
    // Pinia/localStorage need a DOM; jsdom provides it.
    restoreMocks: true
  }
})
