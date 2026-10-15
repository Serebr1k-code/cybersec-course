import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import router from './router'
import { useAuthStore } from './stores/auth'
import { registerServiceWorker } from './pwa'
import './styles/main.css'
import 'highlight.js/styles/github-dark.css'

const app = createApp(App)
const pinia = createPinia()
app.use(pinia)
app.use(router)

// Тренажёр закрыт для анонимов. Разрешаем сессию (GET /api/auth/me) и ждём
// первый переход роутера ДО монтирования — иначе на мгновение мигнул бы
// защищённый контент, а посетитель без аккаунта должен сразу попасть на /login.
async function boot() {
  const auth = useAuthStore(pinia)
  await auth.load()
  await router.isReady()
  app.mount('#app')
}
boot()

// PWA: enable offline app shell + fresh /api/* in production builds only.
registerServiceWorker()
