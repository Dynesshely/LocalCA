<script setup>
/**
 * Change the signed-in user's password. Django's PasswordChangeForm validates
 * server side and the API re-issues the session, so the user stays logged in.
 */
import { computed, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import FormField from '@/components/FormField.vue'
import { useAuthStore } from '@/stores/auth'
import { useToastStore } from '@/stores/toasts'
import { ApiError } from '@/api/client'

const auth = useAuthStore()
const toasts = useToastStore()
const router = useRouter()

const form = reactive({ old_password: '', new_password1: '', new_password2: '' })
const busy = ref(false)
const errors = ref([])

const generalErrors = computed(() => errors.value.filter((e) => !e.includes(': ')))
const fieldError = (label) => {
  const hit = errors.value.find((e) => e.toLowerCase().startsWith(label.toLowerCase() + ': '))
  return hit ? hit.slice(hit.indexOf(':') + 1).trim() : ''
}

async function submit() {
  errors.value = []
  busy.value = true
  try {
    await auth.changePassword({ ...form })
    toasts.success('Your password was successfully updated.')
    router.push({ name: 'home' })
  } catch (err) {
    errors.value = err instanceof ApiError ? err.errors : [String(err)]
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="mx-auto max-w-lg">
    <h1 class="mb-4 text-2xl font-semibold">Change Password</h1>

    <div class="rounded-xl border shadow-sm" :style="{ backgroundColor: 'var(--surface-card)', borderColor: 'var(--border-subtle)' }">
      <form class="space-y-4 px-4 py-5" @submit.prevent="submit">
        <div
          v-if="generalErrors.length"
          class="rounded border-l-4 border-red-500 bg-red-50 px-3 py-2 text-sm text-red-900 dark:bg-red-950/50 dark:text-red-200"
          role="alert"
        >
          <p v-for="(message, i) in generalErrors" :key="i">{{ message }}</p>
        </div>

        <FormField
          id="id_old_password"
          v-model="form.old_password"
          label="Current password"
          type="password"
          required
          autocomplete="current-password"
          :error="fieldError('Old password')"
        />
        <FormField
          id="id_new_password1"
          v-model="form.new_password1"
          label="New password"
          type="password"
          required
          autocomplete="new-password"
          help="At least 8 characters, not entirely numeric, and not a common password."
          :error="fieldError('New password')"
        />
        <FormField
          id="id_new_password2"
          v-model="form.new_password2"
          label="Confirm new password"
          type="password"
          required
          autocomplete="new-password"
          :error="fieldError('New password confirmation')"
        />

        <div class="flex gap-2">
          <button
            type="submit"
            class="rounded px-4 py-2 text-sm font-medium text-white transition disabled:opacity-60"
            :style="{ backgroundColor: 'var(--color-brand-700)' }"
            :disabled="busy"
            data-testid="change-password"
          >
            {{ busy ? 'Saving...' : 'Change Password' }}
          </button>
          <RouterLink
            :to="{ name: 'home' }"
            class="rounded border px-4 py-2 text-sm transition"
            :style="{ borderColor: 'var(--border-strong)', color: 'var(--text-primary)' }"
          >
            Cancel
          </RouterLink>
        </div>
      </form>
    </div>
  </div>
</template>
