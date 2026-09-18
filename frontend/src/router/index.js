import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

/**
 * Routes mirror the old server-side URLs so existing bookmarks keep working.
 * `meta.requiresAuth` gates pages; the guard below sends guests to /login with
 * a `next` query so they land where they intended.
 */
const routes = [
  {
    path: '/',
    name: 'home',
    component: () => import('@/views/HomeView.vue'),
    meta: { title: 'Certificate Hierarchy' },
  },
  {
    path: '/create/ca',
    name: 'create-ca',
    component: () => import('@/views/CreateCaView.vue'),
    meta: { requiresAuth: true, title: 'Create CA' },
  },
  {
    path: '/create/leaf',
    name: 'create-leaf',
    component: () => import('@/views/CreateLeafView.vue'),
    meta: { requiresAuth: true, title: 'Create Leaf Certificate' },
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
    meta: { title: 'Login' },
  },
  {
    path: '/change-password',
    name: 'change-password',
    component: () => import('@/views/ChangePasswordView.vue'),
    meta: { requiresAuth: true, title: 'Change Password' },
  },
  {
    path: '/audit',
    name: 'audit',
    component: () => import('@/views/AuditView.vue'),
    meta: { requiresAuth: true, requiresStaff: true, title: 'Audit Log' },
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

router.afterEach((to) => {
  const title = to.meta?.title
  document.title = title ? `${title} - Local CA` : 'Local CA'
})

export default router
