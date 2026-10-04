<script setup>
/**
 * Transient feedback messages, replacing Django's messages framework.
 */
import { useI18n } from 'vue-i18n'
import { useToastStore } from '@/stores/toasts'

const { t } = useI18n()
const toasts = useToastStore()

const styles = {
  success: 'border-l-4 border-emerald-500 bg-emerald-50 text-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-200',
  error: 'border-l-4 border-red-500 bg-red-50 text-red-900 dark:bg-red-950/40 dark:text-red-200',
  warning: 'border-l-4 border-amber-500 bg-amber-50 text-amber-900 dark:bg-amber-950/40 dark:text-amber-100',
  info: 'border-l-4 border-sky-500 bg-sky-50 text-sky-900 dark:bg-sky-950/40 dark:text-sky-200',
}
</script>

<template>
  <div
    v-if="toasts.items.length"
    class="mb-4 space-y-2"
    role="status"
    aria-live="polite"
    data-testid="feedback"
  >
    <div
      v-for="toast in toasts.items"
      :key="toast.id"
      class="flex items-start justify-between gap-4 rounded-lg px-4 py-3 text-sm shadow-sm"
      :class="styles[toast.type] || styles.info"
    >
      <span class="whitespace-pre-line">{{ toast.message }}</span>
      <button
        type="button"
        class="shrink-0 rounded text-lg leading-none opacity-60 transition hover:opacity-100"
        :aria-label="t('dialog.dismiss')"
        @click="toasts.dismiss(toast.id)"
      >
        &times;
      </button>
    </div>
  </div>
</template>
