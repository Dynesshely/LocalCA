import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { i18n } from '@/i18n'

/**
 * Routes mirror the old server-side URLs so existing bookmarks keep working.
 * `meta.requiresAuth` gates pages; the guard below sends guests to /login with
 * a `next` query so they land where they intended.
 *
 * `meta.titleKey` names the heading in the i18n catalogues, so the top bar and
 * the document title read in the language the reader picked.
 */
const routes = [
  {
    path: '/',
    name: 'home',
    component: () => import('@/views/HomeView.vue'),
    meta: { titleKey: 'common.nav.home' },
  },
  {
    path: '/create/ca',
    name: 'create-ca',
    component: () => import('@/views/CreateCaView.vue'),
    meta: { requiresAuth: true, titleKey: 'common.nav.createCa' },
  },
  {
    path: '/create/leaf',
    name: 'create-leaf',
    component: () => import('@/views/CreateLeafView.vue'),
    meta: { requiresAuth: true, titleKey: 'common.nav.createLeaf' },
  },
  {
    path: '/import',
    name: 'import',
    component: () => import('@/views/ImportView.vue'),
    meta: { requiresAuth: true, titleKey: 'common.nav.import' },
  },
  {
    // Kept for compatibility with the old template URL.
    path: '/create_intermediate',
    redirect: { name: 'create-ca' },
  },
  {
    path: '/login',
    name: 'login',
    component: () => import('@/views/LoginView.vue'),
    meta: { titleKey: 'auth.login.title' },
  },
  {
    path: '/change-password',
    name: 'change-password',
    component: () => import('@/views/ChangePasswordView.vue'),
    meta: { requiresAuth: true, titleKey: 'common.nav.changePassword' },
  },
  {
    path: '/audit',
    name: 'audit',
    component: () => import('@/views/AuditView.vue'),
    meta: { requiresAuth: true, requiresStaff: true, titleKey: 'common.nav.audit' },
  },
  {
    path: '/:pathMatch(.*)*',
    name: 'not-found',
    component: () => import('@/views/NotFoundView.vue'),
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
  scrollBehavior: () => ({ top: 0 }),
})

router.beforeEach(async (to) => {
  const auth = useAuthStore()

  // Resolve the session once per page load, before the first gated navigation.
  if (!auth.ready) {
    await auth.load()
  }

  if (to.meta.requiresAuth && !auth.isAuthenticated) {
    return { name: 'login', query: { next: to.fullPath } }
  }
  if (to.meta.requiresStaff && !auth.isStaff) {
    return { name: 'home' }
  }
  // A signed-in user has no reason to see the login form.
  if (to.name === 'login' && auth.isAuthenticated) {
    return { name: 'home' }
  }
  return true
})

// `titleKey` is an i18n key, not prose: the title has to follow the language,
// and resolving it here keeps it correct on a page load that lands directly on
// a deep route (AppShell's watcher only fires when the locale *changes*).
router.afterEach((to) => {
  const { t } = i18n.global
  const title = to.meta?.titleKey ? t(to.meta.titleKey) : ''
  document.title = title ? `${title} - ${t('common.app.name')}` : t('common.app.name')
})

export default router
