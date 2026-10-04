<script setup>
/**
 * PKCS12 export dialog. The password is optional; the warning about it being
 * unrecoverable is kept from the original UI because the bundle cannot be
 * re-opened without it.
 */
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import AppModal from '@/components/AppModal.vue'

const props = defineProps({
  open: { type: Boolean, default: false },
  certificate: { type: Object, default: null },
  busy: { type: Boolean, default: false },
})

const emit = defineEmits(['close', 'export'])

const { t } = useI18n()

const password = ref('')
const showPassword = ref(false)

watch(
  () => [props.open, props.certificate?.id],
  ([isOpen]) => {
    if (isOpen) {
      password.value = ''
      showPassword.value = false
    }
  },
)
</script>

<template>
  <AppModal
    :open="open"
    :title="t('dialog.p12.title')"
    :close-on-backdrop="false"
    @close="emit('close')"
  >
    <i18n-t keypath="dialog.p12.intro" tag="p" class="text-sm text-slate-600 dark:text-slate-300">
      <template #name>
        <strong class="font-semibold text-slate-900 dark:text-slate-100">{{ certificate?.name }}</strong>
      </template>
      <template #extension>
        <span class="font-mono">.p12</span>
      </template>
    </i18n-t>

    <p
      class="mt-3 rounded-lg border-l-4 border-amber-500 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:bg-amber-950/40 dark:text-amber-200"
    >
      <i18n-t keypath="dialog.p12.warning" tag="span">
        <template #lead>
          <strong class="font-semibold">{{ t('dialog.p12.importantLead') }}</strong>
        </template>
      </i18n-t>
    </p>

    <p class="mt-2 text-xs text-slate-500 dark:text-slate-400">
      {{ t('dialog.p12.passwordNote') }}
    </p>

    <div class="mt-4">
      <label for="p12-password" class="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-200">
        {{ t('dialog.p12.passwordLabel') }}
      </label>
      <div class="flex gap-2">
        <input
          id="p12-password"
          v-model="password"
          :type="showPassword ? 'text' : 'password'"
          autocomplete="new-password"
          :placeholder="t('dialog.p12.passwordPlaceholder')"
          data-testid="p12-password"
          class="flex-1 rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 shadow-sm transition placeholder:text-slate-400 focus:border-brand-500 focus:ring-2 focus:ring-brand-500/25 focus:outline-none dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100 dark:placeholder:text-slate-500"
        />
        <button
          type="button"
          class="rounded-lg border border-slate-300 bg-white px-3 py-2 text-xs font-medium text-slate-700 transition hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700"
          @click="showPassword = !showPassword"
        >
          {{ showPassword ? t('dialog.p12.hide') : t('dialog.p12.show') }}
        </button>
      </div>
      <p v-if="password && password.length < 8" class="mt-1.5 text-xs text-red-600 dark:text-red-400">
        {{ t('dialog.p12.passwordTooShort') }}
      </p>
    </div>

    <template #footer>
      <button
        type="button"
        class="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-medium text-slate-700 transition hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700"
        :disabled="busy"
        @click="emit('close')"
      >
        {{ t('common.action.cancel') }}
      </button>
      <button
        type="button"
        class="rounded-lg bg-brand-700 px-3 py-2 text-sm font-medium text-white shadow-sm transition hover:bg-brand-600 disabled:cursor-not-allowed disabled:opacity-60"
        :disabled="busy || !password || password.length < 8"
        data-testid="p12-export"
        @click="emit('export', password)"
      >
        {{ busy ? t('dialog.p12.preparing') : t('dialog.p12.download') }}
      </button>
    </template>
  </AppModal>
</template>
