import { describe, it, expect, beforeEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useAuthStore } from './auth'
import { api, setToken } from '../api/client'

vi.mock('../api/client', () => ({
  api: {
    authMe: vi.fn(),
    register: vi.fn(),
    login: vi.fn(),
    logout: vi.fn()
  },
  setToken: vi.fn()
}))

describe('stores/auth', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
  })

  it('starts logged out', () => {
    const s = useAuthStore()
    expect(s.isLoggedIn).toBe(false)
    expect(s.username).toBe('')
  })

  it('load() restores a session from the server', async () => {
    api.authMe.mockResolvedValue({ user: { id: 'u1', username: 'dave' } })
    const s = useAuthStore()
    await s.load()
    expect(s.user.username).toBe('dave')
    expect(s.isLoggedIn).toBe(true)
    expect(s.ready).toBe(true)
  })

  it('load() falls back to anonymous on error', async () => {
    api.authMe.mockRejectedValue(new Error('nope'))
    const s = useAuthStore()
    await s.load()
    expect(s.user).toBeNull()
    expect(s.ready).toBe(true)
  })

  it('login() stores the token and user', async () => {
    api.login.mockResolvedValue({ user: { id: 'u1', username: 'dave' }, token: 'tok-1' })
    const s = useAuthStore()
    await s.login('dave', 'hunter2!')
    expect(api.login).toHaveBeenCalledWith('dave', 'hunter2!')
    expect(setToken).toHaveBeenCalledWith('tok-1')
    expect(s.username).toBe('dave')
  })

  it('register() stores the token and user', async () => {
    api.register.mockResolvedValue({ user: { id: 'u2', username: 'eve' }, token: 'tok-2' })
    const s = useAuthStore()
    await s.register('eve', 'hunter2!')
    expect(setToken).toHaveBeenCalledWith('tok-2')
    expect(s.username).toBe('eve')
  })

  it('logout() clears the token and user even if the request fails', async () => {
    api.logout.mockRejectedValue(new Error('offline'))
    const s = useAuthStore()
    s.user = { id: 'u1', username: 'dave' }
    await s.logout()
    expect(setToken).toHaveBeenCalledWith(null)
    expect(s.user).toBeNull()
    expect(s.isLoggedIn).toBe(false)
  })
})
