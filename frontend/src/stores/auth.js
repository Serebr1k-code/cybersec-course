import { defineStore } from 'pinia'
import { api, setToken } from '../api/client'

// Аккаунт пользователя: регистрация/вход/выход и восстановление сессии.
// Когда пользователь не авторизован, приложение продолжает работать в
// анонимном режиме (прогресс привязан к cookie lt_uid) — ничего не ломается.
export const useAuthStore = defineStore('auth', {
  state: () => ({
    user: null, // { id, username, created_at } | null
    ready: false, // сессия проверена на сервере
    error: ''
  }),
  getters: {
    isLoggedIn: (s) => !!s.user,
    username: (s) => s.user?.username || ''
  },
  actions: {
    // Восстанавливает сессию по cookie/токену при загрузке приложения.
    async load() {
      try {
        const r = await api.authMe()
        this.user = r.user || null
      } catch (e) {
        this.user = null
      } finally {
        this.ready = true
      }
      return this.user
    },
    async register(username, password) {
      this.error = ''
      const r = await api.register(username, password)
      setToken(r.token)
      this.user = r.user
      this.ready = true
      return this.user
    },
    async login(username, password) {
      this.error = ''
      const r = await api.login(username, password)
      setToken(r.token)
      this.user = r.user
      this.ready = true
      return this.user
    },
    async logout() {
      try { await api.logout() } catch (e) { /* сеть могла отвалиться — всё равно чистим локально */ }
      setToken(null)
      this.user = null
    }
  }
})
