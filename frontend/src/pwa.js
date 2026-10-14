// PWA service-worker registration.
//
// Registered only in a production build and only when the browser supports
// service workers.  Factored out of main.js so it can be unit-tested without a
// real navigator.

export function registerServiceWorker(
  nav = typeof navigator !== 'undefined' ? navigator : undefined,
  isProd = import.meta.env.PROD
) {
  if (!isProd) return null
  if (!nav || !('serviceWorker' in nav)) return null
  return nav.serviceWorker.register('/sw.js', { scope: '/' })
}
