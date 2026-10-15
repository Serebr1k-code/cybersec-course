import { useAuthStore } from '../stores/auth'

// Маршруты, открытые без входа. Всё остальное (дерево, уроки, статистика,
// «о проекте») требует аккаунта — тренажёр закрыт для анонимов.
export function isPublicRoute(to) {
  return !!(to && (to.meta?.public || to.name === 'login'))
}

// Навигационный охранник. Перед каждым переходом убеждаемся, что сессия
// разрешена (GET /api/auth/me), и уводим неавторизованного посетителя на
// /login, сохраняя исходный адрес в ?redirect=, чтобы вернуть его после входа.
export async function authGuard(to) {
  const auth = useAuthStore()

  // На первом переходе сессия ещё не проверена — ждём ответ сервера,
  // чтобы не мигнуть защищённым контентом. load() идемпотентен.
  if (!auth.ready) {
    await auth.load()
  }

  if (isPublicRoute(to)) return true

  // isLoggedIn ложен и при 401, и при 200 {user:null} — обе ветки закрыты.
  if (!auth.isLoggedIn) {
    const query = to.fullPath && to.fullPath !== '/' ? { redirect: to.fullPath } : {}
    return { name: 'login', query, replace: true }
  }

  return true
}
