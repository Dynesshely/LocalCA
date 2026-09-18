<script setup>
import { useRoute } from 'vue-router'

const route = useRoute()
</script>

<template>
  <div class="mx-auto max-w-lg py-16 text-center">
    <h1 class="text-3xl font-semibold">Page not found</h1>
    <p class="mt-2 text-sm" :style="{ color: 'var(--text-secondary)' }">
      Nothing is routed at <span class="font-mono">{{ route.fullPath }}</span>.
    </p>
    <RouterLink
      :to="{ name: 'home' }"
      class="mt-6 inline-block rounded px-4 py-2 text-sm font-medium text-white"
      :style="{ backgroundColor: 'var(--color-brand-700)' }"
    >
      Back to certificates
    </RouterLink>
  </div>
</template>
