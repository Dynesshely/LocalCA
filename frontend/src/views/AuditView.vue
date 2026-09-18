<script setup>
/**
 * Audit log. Staff only: it reveals other users' activity.
 */
import { onMounted, ref } from 'vue'
import { audit } from '@/api'
import { useToastStore } from '@/stores/toasts'

const toasts = useToastStore()
const entries = ref([])
const loading = ref(true)
const limit = ref(100)

const ACTION_TONES = {
  CREATE: 'bg-emerald-600',
  REVOKE: 'bg-amber-600',
  DELETE: 'bg-danger',
  DOWNLOAD_PUBLIC_KEY: 'bg-sky-600',
  DOWNLOAD_PRIVATE_KEY: 'bg-danger-strong',
  DOWNLOAD_PKCS12: 'bg-brand-600',
  ACCESS: 'bg-brand-500',
}

async function load() {
  loading.value = true
  try {
    const payload = await audit.list(limit.value)
    entries.value = payload.entries || []
  } catch (err) {
    toasts.error(`Could not load the audit log: ${err.message}`)
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<template>
  <div>
    <div class="mb-4 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 class="text-2xl font-semibold">Audit Log</h1>
        <p class="mt-1 text-sm" :style="{ color: 'var(--text-secondary)' }">
          Most recent {{ entries.length }} entries.
        </p>
      </div>
      <div class="flex items-center gap-2">
        <label for="audit-limit" class="text-sm">Show</label>
        <select
          id="audit-limit"
          v-model.number="limit"
          class="rounded border px-2 py-1 text-sm"
          :style="{ backgroundColor: 'var(--surface-sunken)', borderColor: 'var(--border-subtle)', color: 'var(--text-primary)' }"
          @change="load"
        >
          <option :value="50">50</option>
          <option :value="100">100</option>
          <option :value="250">250</option>
          <option :value="500">500</option>
        </select>
        <button
          type="button"
          class="rounded border px-3 py-2 text-sm transition"
          :style="{ borderColor: 'var(--border-strong)', color: 'var(--text-primary)' }"
          @click="load"
        >
          Refresh
        </button>
      </div>
    </div>

    <div v-if="loading" class="py-8 text-center text-sm" :style="{ color: 'var(--text-secondary)' }">
      Loading...
    </div>
    <div v-else-if="!entries.length" class="rounded border px-4 py-8 text-center text-sm"
         :style="{ borderColor: 'var(--border-subtle)', color: 'var(--text-secondary)' }">
      No audit entries.
    </div>
    <div v-else class="overflow-x-auto rounded-xl border shadow-sm"
         :style="{ backgroundColor: 'var(--surface-card)', borderColor: 'var(--border-subtle)' }">
      <table class="w-full text-left text-sm">
        <thead :style="{ backgroundColor: 'var(--surface-sunken)' }">
          <tr>
            <th class="px-3 py-2 font-medium">When</th>
            <th class="px-3 py-2 font-medium">Action</th>
            <th class="px-3 py-2 font-medium">By</th>
            <th class="px-3 py-2 font-medium">Details</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="entry in entries" :key="entry.id" class="border-t" :style="{ borderColor: 'var(--border-subtle)' }">
            <td class="whitespace-nowrap px-3 py-2">{{ new Date(entry.timestamp).toLocaleString() }}</td>
            <td class="px-3 py-2">
              <span class="rounded px-2 py-0.5 text-xs text-white" :class="ACTION_TONES[entry.action] || 'bg-gray-500'">
                {{ entry.action }}
              </span>
            </td>
            <td class="px-3 py-2">{{ entry.performed_by || '(anonymous)' }}</td>
            <td class="px-3 py-2">{{ entry.details }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
