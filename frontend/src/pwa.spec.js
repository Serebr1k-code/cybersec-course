import { describe, it, expect, vi } from 'vitest'
import { registerServiceWorker } from './pwa'

function fakeNav() {
  const register = vi.fn(() => Promise.resolve({ scope: '/' }))
  return { nav: { serviceWorker: { register } }, register }
}

describe('pwa/registerServiceWorker', () => {
  it('registers /sw.js with scope / in a production build', () => {
    const { nav, register } = fakeNav()
    const result = registerServiceWorker(nav, true)
    expect(register).toHaveBeenCalledTimes(1)
    expect(register).toHaveBeenCalledWith('/sw.js', { scope: '/' })
    expect(result).toBeTruthy()
  })

  it('does nothing outside a production build', () => {
    const { nav, register } = fakeNav()
    expect(registerServiceWorker(nav, false)).toBeNull()
    expect(register).not.toHaveBeenCalled()
  })

  it('does nothing when the browser has no service worker support', () => {
    expect(registerServiceWorker({}, true)).toBeNull()
    expect(registerServiceWorker(undefined, true)).toBeNull()
  })
})
