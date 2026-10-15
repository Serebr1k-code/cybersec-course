import { defineStore } from 'pinia'
import { api, setToken } from '../api/client'

// Один общий запрос /api/auth/me: boot-фаза, навигационный охранник и App.vue
// могут дёрнуть load() одновременно — сеть не должна ходить дважды.
let inflight = null

// Аккаунт пользователя: регистрация/вход/выход и восстановление сессии.
// Приложение закрыто для анонимов (см. src/router/guard.js): без входа любой
// маршрут, кроме /login, уводит на экран входа.
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
    // Идемпотентно: повторный вызов после готовности не ходит на сервер.
    async load() {
      if (this.ready) return this.user
      if (inflight) return inflight
      inflight = (async () => {
        try {
          const r = await api.authMe()
          this.user = r.user || null
        } catch (e) {
          // 401/сеть/любая ошибка → считаем посетителя анонимным.
          this.user = null
        } finally {
          this.ready = true
          inflight = null
        }
        return this.user
      })()
      return inflight
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
