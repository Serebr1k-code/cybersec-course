import { createRouter, createWebHistory } from 'vue-router'
import TreeView from '../views/TreeView.vue'
import LessonView from '../views/LessonView.vue'
import StatsView from '../views/StatsView.vue'
import AboutView from '../views/AboutView.vue'

const routes = [
  { path: '/', name: 'tree', component: TreeView },
  { path: '/lesson/:id', name: 'lesson', component: LessonView, props: true },
  { path: '/stats', name: 'stats', component: StatsView },
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

export default router
