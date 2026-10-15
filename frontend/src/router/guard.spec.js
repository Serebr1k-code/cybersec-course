import { describe, it, expect, beforeEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { authGuard, isPublicRoute } from './guard'
import { useAuthStore } from '../stores/auth'
import { api } from '../api/client'

vi.mock('../api/client', () => ({
  api: { authMe: vi.fn() },
  setToken: vi.fn()
}))

// Минимальная заглушка маршрута — охраннику нужны только name/fullPath/meta.
function route(name, fullPath, meta = {}) {
  return { name, fullPath, meta }
}

describe('router/authGuard', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
  })

  it('redirects an anonymous visitor from / to /login', async () => {
    api.authMe.mockResolvedValue({ user: null }) // backend: 200 {user:null}
    const res = await authGuard(route('tree', '/'))
    expect(res).toEqual({ name: 'login', query: {}, replace: true })
  })

  it('treats a 401 from /api/auth/me as unauthenticated and redirects', async () => {
    const err = new Error('unauthorized')
    err.status = 401
    api.authMe.mockRejectedValue(err)
    const res = await authGuard(route('tree', '/'))
    expect(res).toEqual({ name: 'login', query: {}, replace: true })
  })

  it('preserves the intended deep link in ?redirect=', async () => {
    api.authMe.mockResolvedValue({ user: null })
    const res = await authGuard(route('lesson', '/lesson/web-sqli'))
    expect(res).toEqual({ name: 'login', query: { redirect: '/lesson/web-sqli' }, replace: true })
  })

  it('lets an authenticated user reach the tree', async () => {
    api.authMe.mockResolvedValue({ user: { id: 'u1', username: 'dave' } })
    const res = await authGuard(route('tree', '/'))
    expect(res).toBe(true)
  })

  it('always allows the public login route (even when anonymous)', async () => {
    api.authMe.mockResolvedValue({ user: null })
    const res = await authGuard(route('login', '/login', { public: true }))
    expect(res).toBe(true)
    expect(isPublicRoute(route('login', '/login'))).toBe(true)
  })

  it('resolves the session before deciding, and only once', async () => {
    api.authMe.mockResolvedValue({ user: { id: 'u1', username: 'dave' } })
    const auth = useAuthStore()
    expect(auth.ready).toBe(false)

    await authGuard(route('tree', '/'))
    expect(api.authMe).toHaveBeenCalledTimes(1)
    expect(auth.ready).toBe(true)

    // Второй переход не должен повторно дёргать сервер.
    await authGuard(route('stats', '/stats'))
    expect(api.authMe).toHaveBeenCalledTimes(1)
  })
})
