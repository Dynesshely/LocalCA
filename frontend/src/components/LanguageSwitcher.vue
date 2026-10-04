<script setup>
/**
 * Language switch, as a two-option segmented control.
 *
 * A segmented control rather than a dropdown because there are exactly two
 * locales: one click instead of two, and the current language is visible without
 * opening anything. Each option is labelled in its own language, which is the
 * only label a reader who cannot read the current interface language can act on.
 */
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { SUPPORTED_LOCALES, setLocale } from '@/i18n'
import { useToastStore } from '@/stores/toasts'
import AppIcon from '@/components/AppIcon.vue'

const { t, locale } = useI18n()
const toasts = useToastStore()

const current = computed(() => locale.value)

function choose(code) {
  if (code === current.value) {
    return
  }
  setLocale(code)
  toasts.info(t('common.language.switched', { language: t(`common.language.name.${code}`) }))
}
</script>

<template>
  <div
    class="flex items-center gap-0.5 rounded-lg bg-slate-100 p-0.5 dark:bg-slate-800"
    role="group"
    :aria-label="t('common.language.label')"
    data-testid="language-switcher"
  >
    <AppIcon name="globe" class="ml-1 size-4 text-slate-400 dark:text-slate-500" />
    <button
      v-for="option in SUPPORTED_LOCALES"
      :key="option.code"
      type="button"
      class="rounded-md px-2.5 py-1 text-xs font-medium transition"
      :class="option.code === current
        ? 'bg-white text-brand-700 shadow-sm dark:bg-slate-700 dark:text-white'
        : 'text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100'"
      :aria-pressed="option.code === current"
      :lang="option.htmlLang"
      :data-testid="`locale-${option.code}`"
      @click="choose(option.code)"
    >
      {{ option.label }}
    </button>
  </div>
</template>
