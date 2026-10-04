<script setup>
/**
 * Sign in. Uses the session API; on success the router returns the user to
 * wherever they were headed (the guard records it as ?next=).
 *
 * The page heading lives in the shell's top bar (`auth.login.title`), so the
 * card holds nothing but the form.
 */
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
import FormField from '@/components/FormField.vue'
import { useAuthStore } from '@/stores/auth'
import { useToastStore } from '@/stores/toasts'
import { ApiError } from '@/api/client'

const { t } = useI18n()
const auth = useAuthStore()
const toasts = useToastStore()
const route = useRoute()
const router = useRouter()

const username = ref('')
const password = ref('')
const busy = ref(false)
const error = ref('')

// Submitting an empty form is always a mistake, so prevent it outright rather
// than round-tripping to the API for an error message.
const canSubmit = computed(() => username.value.trim() !== '' && password.value !== '')

async function submit() {
  error.value = ''
  busy.value = true
  try {
    const user = await auth.login(username.value, password.value)
    toasts.success(t('common.nav.signedInAs', { username: user.username }))
    const next = typeof route.query.next === 'string' ? route.query.next : '/'
    router.push(next)
  } catch (err) {
    error.value = err instanceof ApiError ? err.message : String(err)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="mx-auto flex min-h-full w-full max-w-[1400px] items-center justify-center py-10">
    <div
      class="w-full max-w-md overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900"
    >
      <form class="space-y-4 px-5 py-5" @submit.prevent="submit">
        <p
          v-if="error"
          class="rounded-lg border-l-4 border-red-500 bg-red-50 px-3 py-2 text-sm text-red-900 dark:bg-red-950/40 dark:text-red-200"
          role="alert"
        >
          {{ error }}
        </p>

        <FormField
          id="id_username"
          v-model="username"
          :label="t('auth.login.username')"
          required
          autocomplete="username"
          autofocus
        />
        <FormField
          id="id_password"
          v-model="password"
          :label="t('auth.login.password')"
          type="password"
          required
          autocomplete="current-password"
        />

        <button
          type="submit"
          class="w-full rounded-lg bg-moss-600 px-4 py-2.5 text-sm font-medium text-white shadow-sm transition hover:bg-moss-500 disabled:cursor-not-allowed disabled:opacity-60"
          :disabled="busy || !canSubmit"
          data-testid="login-submit"
        >
          {{ busy ? t('auth.login.submitting') : t('auth.login.submit') }}
        </button>
      </form>
    </div>
  </div>
</template>
