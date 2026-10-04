<script setup>
/**
 * Language switch, as a styled combo box.
 *
 * A native `<select>` rather than a custom popup: it is reachable by keyboard,
 * announced correctly, and its popup is drawn by the platform, which is the
 * behaviour a reader switching language expects. The globe stays in front of it
 * because a bare two-letter word does not say "this changes the language".
 *
 * Each option carries `lang` so it is rendered in its own script, which is the
 * only label a reader who cannot read the current interface can act on.
 */
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { SUPPORTED_LOCALES, setLocale } from '@/i18n'
import { useToastStore } from '@/stores/toasts'
import AppIcon from '@/components/AppIcon.vue'

const { t, locale } = useI18n()
const toasts = useToastStore()

const current = computed({
  get: () => locale.value,
  set: (code) => {
    if (code === locale.value) {
      return
    }
    setLocale(code)
    toasts.info(t('common.language.switched', { language: t(`common.language.name.${code}`) }))
  },
})
</script>

<template>
  <div
    class="relative flex items-center rounded-lg border border-slate-200 bg-white text-slate-600 transition focus-within:border-brand-400 hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300 dark:hover:bg-slate-700"
  >
    <AppIcon
      name="globe"
      class="pointer-events-none absolute left-2.5 size-4 text-slate-400 dark:text-slate-500"
    />
    <select
      v-model="current"
      :aria-label="t('common.language.label')"
      class="w-full cursor-pointer appearance-none rounded-lg bg-transparent py-2 pr-8 pl-8 text-sm font-medium focus:outline-none"
      data-testid="language-switcher"
    >
      <option
        v-for="option in SUPPORTED_LOCALES"
        :key="option.code"
        :value="option.code"
        :lang="option.htmlLang"
        class="bg-white text-slate-700 dark:bg-slate-800 dark:text-slate-100"
      >
        {{ option.label }}
      </option>
    </select>
    <!-- The select's own arrow is hidden by `appearance-none`, so draw one that
         matches the rest of the chrome. -->
    <AppIcon
      name="chevronDown"
      class="pointer-events-none absolute right-2 size-4 text-slate-400 dark:text-slate-500"
    />
  </div>
</template>
