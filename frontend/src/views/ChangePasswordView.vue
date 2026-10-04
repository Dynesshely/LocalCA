<script setup>
/**
 * Change the signed-in user's password. Django's PasswordChangeForm validates
 * server side and the API re-issues the session, so the user stays logged in.
 *
 * Validation messages arrive two ways: the flat `errors` list is for reading,
 * and `field_errors` is keyed by *field name*, which is how a message is
 * attached to the input it came from without depending on its wording.
 *
 * The page heading lives in the shell's top bar (`common.nav.changePassword`).
 */
import { computed, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import FormField from '@/components/FormField.vue'
import { useAuthStore } from '@/stores/auth'
import { useToastStore } from '@/stores/toasts'
import { ApiError } from '@/api/client'

const { t } = useI18n()
const auth = useAuthStore()
const toasts = useToastStore()
const router = useRouter()

const form = reactive({ old_password: '', new_password1: '', new_password2: '' })
const busy = ref(false)
const errors = ref([])
const fieldErrors = ref({})

/** Messages that belong to no single field: Django's `__all__` errors. */
const generalErrors = computed(() => errors.value.filter((e) => !e.includes(': ')))
const fieldError = (name) => (fieldErrors.value[name] || [])[0] || ''

async function submit() {
  errors.value = []
  fieldErrors.value = {}
  busy.value = true
  try {
    await auth.changePassword({ ...form })
    toasts.success(t('auth.changePassword.success'))
    router.push({ name: 'home' })
  } catch (err) {
    errors.value = err instanceof ApiError ? err.errors : [String(err)]
    fieldErrors.value = err instanceof ApiError ? err.fieldErrors : {}
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="mx-auto w-full max-w-[1400px]">
    <div
      class="mx-auto w-full max-w-lg overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900"
    >
      <form class="space-y-4 px-5 py-5" @submit.prevent="submit">
        <div
          v-if="generalErrors.length"
          class="rounded-lg border-l-4 border-red-500 bg-red-50 px-3 py-2 text-sm text-red-900 dark:bg-red-950/40 dark:text-red-200"
          role="alert"
        >
          <p v-for="(message, i) in generalErrors" :key="i">{{ message }}</p>
        </div>

        <FormField
          id="id_old_password"
          v-model="form.old_password"
          :label="t('auth.changePassword.current')"
          type="password"
          required
          autocomplete="current-password"
          :error="fieldError('old_password')"
        />
        <FormField
          id="id_new_password1"
          v-model="form.new_password1"
          :label="t('auth.changePassword.new')"
          type="password"
          required
          autocomplete="new-password"
          :help="t('auth.changePassword.help')"
          :error="fieldError('new_password1')"
        />
        <FormField
          id="id_new_password2"
          v-model="form.new_password2"
          :label="t('auth.changePassword.confirm')"
          type="password"
          required
          autocomplete="new-password"
          :error="fieldError('new_password2')"
        />

        <div class="flex gap-2">
          <button
            type="submit"
            class="rounded-lg bg-moss-600 px-4 py-2.5 text-sm font-medium text-white shadow-sm transition hover:bg-moss-500 disabled:cursor-not-allowed disabled:opacity-60"
            :disabled="busy"
            data-testid="change-password"
          >
            {{ busy ? t('auth.changePassword.saving') : t('auth.changePassword.submit') }}
          </button>
          <RouterLink
            :to="{ name: 'home' }"
            class="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-medium text-slate-700 transition hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700"
          >
            {{ t('common.action.cancel') }}
          </RouterLink>
        </div>
      </form>
    </div>
  </div>
</template>
