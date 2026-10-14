import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import router from './router'
import { registerServiceWorker } from './pwa'
import './styles/main.css'
import 'highlight.js/styles/github-dark.css'

const app = createApp(App)
app.use(createPinia())
app.use(router)
app.mount('#app')

// PWA: enable offline app shell + fresh /api/* in production builds only.
registerServiceWorker()
