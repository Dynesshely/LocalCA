<script setup>
import { onMounted } from 'vue'
import AppShell from '@/components/AppShell.vue'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()

onMounted(() => {
  // Static metadata (revocation reasons, validity bounds) is fetched once.
  auth.loadMeta()
})
</script>

<template>
  <!-- AppShell owns the layout and renders the active route. -->
  <AppShell />
</template>
