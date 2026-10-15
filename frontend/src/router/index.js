import { createRouter, createWebHistory } from 'vue-router'
import TreeView from '../views/TreeView.vue'
import LessonView from '../views/LessonView.vue'
import StatsView from '../views/StatsView.vue'
import AboutView from '../views/AboutView.vue'
import AuthView from '../views/AuthView.vue'
import { authGuard } from './guard'

const routes = [
  { path: '/', name: 'tree', component: TreeView },
  { path: '/lesson/:id', name: 'lesson', component: LessonView, props: true },
  { path: '/stats', name: 'stats', component: StatsView },
  // Единственный публичный маршрут: вход/регистрация.
  { path: '/login', name: 'login', component: AuthView, meta: { public: true } },
  { path: '/about', name: 'about', component: AboutView },
  { path: '/:pathMatch(.*)*', redirect: '/' }
]

const router = createRouter({
  history: createWebHistory(),
  routes,
  scrollBehavior(to, from, saved) {
    if (saved) return saved
    return { top: 0 }
  }
})

// Тренажёр закрыт для анонимов: любой приватный маршрут требует сессии.
router.beforeEach(authGuard)

export default router
