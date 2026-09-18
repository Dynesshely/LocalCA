<script setup>
/**
 * Page chrome: navigation, feedback messages, theme toggle, footer.
 */
import { computed } from 'vue'
import { RouterLink, useRoute, useRouter } from 'vue-router'
import ThemeToggle from '@/components/ThemeToggle.vue'
import FeedbackMessages from '@/components/FeedbackMessages.vue'
import { useAuthStore } from '@/stores/auth'
import { useToastStore } from '@/stores/toasts'

const auth = useAuthStore()
const toasts = useToastStore()
const route = useRoute()
const router = useRouter()

const navItems = computed(() => {
  const items = [{ name: 'home', label: 'Home', icon: 'home' }]
  if (auth.isAuthenticated) {
    items.push({ name: 'create-ca', label: 'Create CA', icon: 'plus' })
    items.push({ name: 'create-leaf', label: 'Create Leaf', icon: 'plus' })
  }
  if (auth.isStaff) {
    items.push({ name: 'audit', label: 'Audit Log', icon: 'list' })
  }
  return items
})

function isActive(name) {
  return route.name === name
}

async function signOut() {
  await auth.logout()
  toasts.info('You have been logged out.')
  router.push({ name: 'login' })
}
</script>

<template>
  <div class="flex min-h-full flex-col">
    <header
      class="bg-brand-800 text-white shadow-sm dark:bg-brand-900"
      style="background-color: var(--color-brand-800)"
    >
      <nav class="mx-auto flex w-full max-w-[1400px] flex-wrap items-center gap-x-6 gap-y-2 px-4 py-3 sm:px-6">
        <RouterLink :to="{ name: 'home' }" class="flex flex-col leading-none">
          <span class="text-xl font-medium">Local CA</span>
          <span class="hidden text-xs font-light italic opacity-90 sm:block">
            Your own internal certificate authority
          </span>
        </RouterLink>

        <ul class="flex flex-1 flex-wrap items-center gap-1">
          <li v-for="item in navItems" :key="item.name">
            <RouterLink
              :to="{ name: item.name }"
              class="block rounded px-3 py-2 text-sm transition"
              :class="isActive(item.name)
                ? 'bg-white/15 font-medium text-white'
                : 'text-white/85 hover:bg-white/10 hover:text-white'"
            >
              {{ item.label }}
            </RouterLink>
          </li>
        </ul>

        <div class="flex items-center gap-2">
          <template v-if="auth.isAuthenticated">
            <RouterLink
              :to="{ name: 'change-password' }"
              class="rounded px-3 py-2 text-sm text-white/85 transition hover:bg-white/10 hover:text-white"
            >
              Change Password
            </RouterLink>
            <button
              type="button"
              class="rounded px-3 py-2 text-sm text-white/85 transition hover:bg-white/10 hover:text-white"
              @click="signOut"
            >
              Logout
            </button>
            <span class="rounded px-3 py-2 text-sm text-white/80">{{ auth.user.username }}</span>
          </template>
          <RouterLink
            v-else
            :to="{ name: 'login' }"
            class="rounded px-3 py-2 text-sm text-white/85 transition hover:bg-white/10 hover:text-white"
          >
            Login
          </RouterLink>

          <ThemeToggle />
        </div>
      </nav>
    </header>

    <main class="mx-auto w-full max-w-[1400px] flex-1 px-4 py-6 sm:px-6">
      <FeedbackMessages />
      <RouterView v-slot="{ Component }">
        <component :is="Component" />
      </RouterView>
    </main>

    <footer
      class="border-t px-4 py-4 text-center text-xs sm:px-6"
      :style="{ borderColor: 'var(--border-subtle)', color: 'var(--text-secondary)' }"
    >
      Local CA &copy; {{ new Date().getFullYear() }}
    </footer>
  </div>
</template>
