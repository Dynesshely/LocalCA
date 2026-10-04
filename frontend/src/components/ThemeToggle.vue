<script setup>
/**
 * Light/dark switch. The theme is applied as a `.dark` class on <html>, which
 * Tailwind's custom variant keys off, and persisted in localStorage. The
 * pre-paint script in index.html reads the same key, so there is no flash.
 */
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import AppIcon from '@/components/AppIcon.vue'

const { t } = useI18n()
const isDark = ref(false)

onMounted(() => {
  isDark.value = document.documentElement.classList.contains('dark')
})

function toggle() {
  isDark.value = !isDark.value
  document.documentElement.classList.toggle('dark', isDark.value)
  document.documentElement.dataset.theme = isDark.value ? 'dark' : 'light'
  try {
    localStorage.setItem('theme', isDark.value ? 'dark' : 'light')
  } catch (err) {
    /* storage disabled: the toggle still works for this page view */
  }
}
</script>

<template>
  <button
    type="button"
    class="rounded-lg border border-slate-200 bg-white p-2 text-slate-500 transition hover:bg-slate-100 hover:text-slate-900 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300 dark:hover:bg-slate-700 dark:hover:text-white"
    :title="isDark ? t('common.theme.switchToLight') : t('common.theme.switchToDark')"
    :aria-label="isDark ? t('common.theme.switchToLight') : t('common.theme.switchToDark')"
    :aria-pressed="isDark"
    data-testid="theme-toggle"
    @click="toggle"
  >
    <AppIcon :name="isDark ? 'sun' : 'moon'" />
  </button>
</template>
