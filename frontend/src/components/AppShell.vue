<script setup>
/**
 * Application chrome.
 *
 * Layout: a fixed-width sidebar on the left, and to its right a column holding
 * the top bar and the scrolling content area. Only the content area scrolls --
 * the sidebar and the top bar stay put, which is what makes a long certificate
 * hierarchy comfortable to read.
 *
 * Below `lg` the sidebar becomes an off-canvas drawer, because 16rem of chrome
 * on a phone leaves no room for the tables this application is made of.
 */
import { computed, ref, watch } from 'vue'
import { RouterLink, RouterView, useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import ThemeToggle from '@/components/ThemeToggle.vue'
import LanguageSwitcher from '@/components/LanguageSwitcher.vue'
import BrandMark from '@/components/BrandMark.vue'
import AppIcon from '@/components/AppIcon.vue'
import FeedbackMessages from '@/components/FeedbackMessages.vue'
import { useAuthStore } from '@/stores/auth'
import { useToastStore } from '@/stores/toasts'

const { t, locale } = useI18n()
const auth = useAuthStore()
const toasts = useToastStore()
const route = useRoute()
const router = useRouter()

const drawerOpen = ref(false)

/** Navigation, grouped: everyday work first, administration below a rule. */
const navGroups = computed(() => {
  const certificates = [{ name: 'home', labelKey: 'common.nav.home', icon: 'home' }]
  if (auth.isAuthenticated) {
    certificates.push(
      { name: 'create-ca', labelKey: 'common.nav.createCa', icon: 'certificate' },
      { name: 'create-leaf', labelKey: 'common.nav.createLeaf', icon: 'key' },
      { name: 'import', labelKey: 'common.nav.import', icon: 'upload' },
    )
  }
  const groups = [{ key: 'certificates', labelKey: 'common.nav.sectionCertificates', items: certificates }]

  const administration = []
  if (auth.isStaff) {
    administration.push({ name: 'audit', labelKey: 'common.nav.audit', icon: 'list' })
  }
  if (auth.isAuthenticated) {
    administration.push({
      name: 'change-password',
      labelKey: 'common.nav.changePassword',
      icon: 'user',
    })
  }
  if (administration.length) {
    groups.push({ key: 'administration', labelKey: 'common.nav.sectionAdministration', items: administration })
  }
  return groups
})

/** The route's own heading, for the top bar. */
const pageTitle = computed(() => (route.meta?.titleKey ? t(route.meta.titleKey) : ''))

function isActive(name) {
  return route.name === name
}

async function signOut() {
  await auth.logout()
  toasts.info(t('common.nav.signedOut'))
  router.push({ name: 'login' })
}

// Leaving the page is what the reader meant by tapping a link in the drawer.
watch(() => route.fullPath, () => {
  drawerOpen.value = false
})

// The document title is part of the interface, so it follows the language.
watch(locale, () => {
  const title = route.meta?.titleKey ? t(route.meta.titleKey) : ''
  document.title = title ? `${title} - ${t('common.app.name')}` : t('common.app.name')
})
</script>

<template>
  <div class="flex h-full min-h-0">
    <!-- ------------------------------------------------------------------
         Sidebar: the same list renders in the desktop rail and in the mobile
         drawer, so there is one place to change what navigation contains.
         ------------------------------------------------------------------ -->
    <aside
      class="hidden w-64 shrink-0 flex-col bg-brand-800 text-brand-100 lg:flex"
    >
      <RouterLink
        :to="{ name: 'home' }"
        class="flex h-16 flex-none items-center gap-3 px-5 text-white"
      >
        <BrandMark :size="30" />
        <span class="flex min-w-0 flex-col leading-tight">
          <span class="truncate text-base font-semibold">{{ t('common.app.name') }}</span>
          <!-- The tagline wraps to two lines rather than truncating: it is
               the only place the product explains itself, and "Your own
               internal certificate ..." explains nothing. -->
          <span class="text-[11px] leading-tight font-light text-brand-300">
            {{ t('common.app.tagline') }}
          </span>
        </span>
      </RouterLink>

      <nav class="flex-1 overflow-y-auto px-3 py-2">
        <template v-for="group in navGroups" :key="group.key">
          <p class="px-3 pt-4 pb-1.5 text-[11px] font-semibold uppercase tracking-wider text-brand-400">
            {{ t(group.labelKey) }}
          </p>
          <RouterLink
            v-for="item in group.items"
            :key="item.name"
            :to="{ name: item.name }"
            class="mb-0.5 flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition"
            :class="isActive(item.name)
              ? 'bg-white/12 font-medium text-white'
              : 'text-brand-200 hover:bg-white/8 hover:text-white'"
            :aria-current="isActive(item.name) ? 'page' : undefined"
          >
            <AppIcon :name="item.icon" class="size-4.5" />
            <span class="truncate">{{ t(item.labelKey) }}</span>
          </RouterLink>
        </template>
      </nav>

      <div class="flex-none border-t border-white/10 p-3">
        <template v-if="auth.isAuthenticated">
          <div class="mb-2 flex items-center gap-2 px-2 py-1">
            <AppIcon name="user" class="size-4 text-brand-300" />
            <span class="min-w-0 truncate text-sm text-brand-100">{{ auth.user.username }}</span>
          </div>
          <button
            type="button"
            class="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm text-brand-200 transition hover:bg-white/8 hover:text-white"
            data-testid="logout"
            @click="signOut"
          >
            <AppIcon name="logout" class="size-4.5" />
            {{ t('common.nav.logout') }}
          </button>
        </template>
        <RouterLink
          v-else
          :to="{ name: 'login' }"
          class="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm text-brand-200 transition hover:bg-white/8 hover:text-white"
        >
          <AppIcon name="user" class="size-4.5" />
          {{ t('common.nav.login') }}
        </RouterLink>
      </div>
    </aside>

    <!-- Mobile drawer -->
    <Transition
      enter-active-class="transition-opacity duration-200"
      leave-active-class="transition-opacity duration-150"
      enter-from-class="opacity-0"
      leave-to-class="opacity-0"
    >
      <div
        v-if="drawerOpen"
        class="fixed inset-0 z-40 bg-slate-900/60 lg:hidden"
        @click="drawerOpen = false"
      />
    </Transition>
    <Transition
      enter-active-class="transition-transform duration-200"
      leave-active-class="transition-transform duration-150"
      enter-from-class="-translate-x-full"
      leave-to-class="-translate-x-full"
    >
      <aside
        v-if="drawerOpen"
        class="fixed inset-y-0 left-0 z-50 flex w-72 flex-col bg-brand-800 text-brand-100 lg:hidden"
      >
        <div class="flex h-16 flex-none items-center gap-3 px-4 text-white">
          <BrandMark :size="28" />
          <span class="min-w-0 flex-1 truncate text-base font-semibold">{{ t('common.app.name') }}</span>
          <button
            type="button"
            class="rounded-lg p-2 text-brand-200 transition hover:bg-white/10 hover:text-white"
            :aria-label="t('common.nav.closeMenu')"
            data-testid="close-drawer"
            @click="drawerOpen = false"
          >
            <AppIcon name="close" />
          </button>
        </div>
        <nav class="flex-1 overflow-y-auto px-3 py-2">
          <template v-for="group in navGroups" :key="group.key">
            <p class="px-3 pt-4 pb-1.5 text-[11px] font-semibold uppercase tracking-wider text-brand-400">
              {{ t(group.labelKey) }}
            </p>
            <RouterLink
              v-for="item in group.items"
              :key="item.name"
              :to="{ name: item.name }"
              class="mb-0.5 flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition"
              :class="isActive(item.name)
                ? 'bg-white/12 font-medium text-white'
                : 'text-brand-200 hover:bg-white/8 hover:text-white'"
              @click="drawerOpen = false"
            >
              <AppIcon :name="item.icon" class="size-4.5" />
              <span class="truncate">{{ t(item.labelKey) }}</span>
            </RouterLink>
          </template>
        </nav>
        <div class="flex-none border-t border-white/10 p-3">
          <div v-if="auth.isAuthenticated" class="mb-2 flex items-center gap-2 px-2 py-1">
            <AppIcon name="user" class="size-4 text-brand-300" />
            <span class="min-w-0 truncate text-sm">{{ auth.user.username }}</span>
          </div>
          <button
            v-if="auth.isAuthenticated"
            type="button"
            class="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm text-brand-200 transition hover:bg-white/8 hover:text-white"
            @click="signOut"
          >
            <AppIcon name="logout" class="size-4.5" />
            {{ t('common.nav.logout') }}
          </button>
          <RouterLink
            v-else
            :to="{ name: 'login' }"
            class="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm text-brand-200 transition hover:bg-white/8 hover:text-white"
          >
            <AppIcon name="user" class="size-4.5" />
            {{ t('common.nav.login') }}
          </RouterLink>
        </div>
      </aside>
    </Transition>

    <!-- ------------------------------------------------------------------
         Top bar + content
         ------------------------------------------------------------------ -->
    <div class="flex min-w-0 flex-1 flex-col">
      <header
        class="flex h-16 flex-none items-center gap-3 border-b border-slate-200 bg-white px-4 sm:px-6 dark:border-slate-800 dark:bg-slate-900"
      >
        <button
          type="button"
          class="rounded-lg p-2 text-slate-500 transition hover:bg-slate-100 hover:text-slate-900 lg:hidden dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-white"
          :aria-label="t('common.nav.openMenu')"
          data-testid="open-drawer"
          @click="drawerOpen = true"
        >
          <AppIcon name="menu" />
        </button>

        <h1 class="min-w-0 truncate text-lg font-semibold text-slate-900 dark:text-slate-100">
          {{ pageTitle }}
        </h1>

        <div class="ml-auto flex flex-none items-center gap-2">
          <LanguageSwitcher />
          <ThemeToggle />
        </div>
      </header>

      <main class="min-h-0 flex-1 overflow-y-auto px-4 py-6 sm:px-6">
        <FeedbackMessages />
        <RouterView v-slot="{ Component }">
          <component :is="Component" />
        </RouterView>

        <footer class="mt-10 pt-4 text-center text-xs text-slate-400 dark:text-slate-500">
          {{ t('common.footer.rights', { year: new Date().getFullYear() }) }}
        </footer>
      </main>
    </div>
  </div>
</template>
