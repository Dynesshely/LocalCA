<script setup>
/**
 * Light/dark switch. The theme is applied as a `.dark` class on <html>, which
 * Tailwind's custom variant keys off, and persisted in localStorage. The
 * pre-paint script in index.html reads the same key, so there is no flash.
 */
import { ref, onMounted } from 'vue'

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
    class="rounded px-3 py-2 text-sm text-white/85 transition hover:bg-white/10 hover:text-white"
    :title="isDark ? 'Switch to light mode' : 'Switch to dark mode'"
    :aria-label="isDark ? 'Switch to light mode' : 'Switch to dark mode'"
    :aria-pressed="isDark"
    data-testid="theme-toggle"
    @click="toggle"
  >
    <span v-if="isDark" aria-hidden="true">&#9788;</span>
    <span v-else aria-hidden="true">&#9789;</span>
  </button>
</template>
