import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { setActivePinia, createPinia } from 'pinia'
import AuthView from './AuthView.vue'
import { useAuthStore } from '../stores/auth'
import { api } from '../api/client'

const { push, route } = vi.hoisted(() => ({ push: vi.fn(), route: { query: {} } }))
vi.mock('vue-router', () => ({
  useRouter: () => ({ push }),
  useRoute: () => route
}))
vi.mock('../api/client', () => ({
  api: {
    authMe: vi.fn(),
    register: vi.fn(),
    login: vi.fn(),
    logout: vi.fn(),
    progress: vi.fn()
  },
  setToken: vi.fn()
}))

const emptyProgress = { user: { lessons: {}, activity: {} }, xp: 0, streak: 0, achievements: [], stats: null }

function mountView() {
  return mount(AuthView, { global: { stubs: { RouterLink: true } } })
}

describe('views/AuthView', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
    route.query = {}
    api.progress.mockResolvedValue(emptyProgress)
  })

  it('renders the login form by default', () => {
    const w = mountView()
    expect(w.find('h1').text()).toBe('Вход')
    expect(w.find('button[type="submit"]').text()).toContain('Войти')
  })

  it('switches to the registration form', async () => {
    const w = mountView()
    await w.findAll('.tab')[1].trigger('click')
    expect(w.find('h1').text()).toBe('Регистрация')
    expect(w.find('button[type="submit"]').text()).toContain('Создать')
  })

  it('submits credentials, reloads progress and redirects', async () => {
    api.login.mockResolvedValue({ user: { id: 'u1', username: 'dave' }, token: 'tok' })
    const w = mountView()
    await w.find('input[type="text"]').setValue('dave')
    await w.find('input[type="password"]').setValue('hunter2!')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(api.login).toHaveBeenCalledWith('dave', 'hunter2!')
    expect(api.progress).toHaveBeenCalled()
    expect(push).toHaveBeenCalledWith('/')
  })

  it('routes to the intended page from ?redirect= after login', async () => {
    route.query = { redirect: '/lesson/web-sqli' }
    api.login.mockResolvedValue({ user: { id: 'u1', username: 'dave' }, token: 'tok' })
    const w = mountView()
    await w.find('input[type="text"]').setValue('dave')
    await w.find('input[type="password"]').setValue('hunter2!')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(push).toHaveBeenCalledWith('/lesson/web-sqli')
  })

  it('ignores an external/unsafe ?redirect= and falls back to /', async () => {
    route.query = { redirect: '//evil.example.com' }
    api.login.mockResolvedValue({ user: { id: 'u1', username: 'dave' }, token: 'tok' })
    const w = mountView()
    await w.find('input[type="text"]').setValue('dave')
    await w.find('input[type="password"]').setValue('hunter2!')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(push).toHaveBeenCalledWith('/')
  })

  it('shows an error when the server rejects the credentials', async () => {
    api.login.mockRejectedValue(new Error('invalid username or password'))
    const w = mountView()
    await w.find('input[type="text"]').setValue('dave')
    await w.find('input[type="password"]').setValue('bad')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(w.find('.err').text()).toContain('invalid username or password')
    expect(push).not.toHaveBeenCalled()
  })

  it('shows the account + logout when already logged in', async () => {
    const auth = useAuthStore()
    auth.user = { id: 'u1', username: 'dave' }
    api.logout.mockResolvedValue({ ok: true })
    const w = mountView()
    expect(w.text()).toContain('dave')
    expect(w.find('.actions .btn').text()).toContain('Выйти')
    await w.find('.actions .btn').trigger('click')
    await flushPromises()
    expect(api.logout).toHaveBeenCalled()
    expect(auth.isLoggedIn).toBe(false)
    expect(push).toHaveBeenCalledWith('/login')
  })
})
