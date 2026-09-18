<script setup>
/**
 * Sign in. Uses the session API; on success the router returns the user to
 * wherever they were headed (the guard records it as ?next=).
 */
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import FormField from '@/components/FormField.vue'
import { useAuthStore } from '@/stores/auth'
import { useToastStore } from '@/stores/toasts'
import { ApiError } from '@/api/client'

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
    toasts.success(`Signed in as ${user.username}.`)
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
  <div class="mx-auto max-w-md">
    <div class="rounded-xl border shadow-sm" :style="{ backgroundColor: 'var(--surface-card)', borderColor: 'var(--border-subtle)' }">
      <h1 class="rounded-t-xl px-4 py-3 text-base font-semibold text-white" :style="{ backgroundColor: 'var(--color-brand-800)' }">
        Login
      </h1>
      <form class="space-y-4 px-4 py-5" @submit.prevent="submit">
        <p
          v-if="error"
          class="rounded border-l-4 border-red-500 bg-red-50 px-3 py-2 text-sm text-red-900 dark:bg-red-950/50 dark:text-red-200"
          role="alert"
        >
          {{ error }}
        </p>

        <FormField
          id="id_username"
          v-model="username"
          label="Username"
          required
          autocomplete="username"
          autofocus
        />
        <FormField
          id="id_password"
          v-model="password"
          label="Password"
          type="password"
          required
          autocomplete="current-password"
        />

        <button
          type="submit"
          class="w-full rounded px-4 py-2 text-sm font-medium text-white transition disabled:opacity-60"
          :style="{ backgroundColor: 'var(--color-brand-700)' }"
          :disabled="busy || !canSubmit"
          data-testid="login-submit"
        >
          {{ busy ? 'Signing in...' : 'Login' }}
        </button>
      </form>
    </div>
  </div>
</template>
