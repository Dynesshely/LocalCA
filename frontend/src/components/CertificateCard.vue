<script setup>
/**
 * A single certificate in the hierarchy, with its metadata and the actions this
 * user is allowed to take on it.
 */
import { computed } from 'vue'

const props = defineProps({
  certificate: { type: Object, required: true },
  /** 0 for roots, 1 for intermediates, 2 for leaves - drives the indent. */
  depth: { type: Number, default: 0 },
})

const emit = defineEmits(['download-public', 'download-private', 'export-pkcs12', 'revoke', 'delete'])

const kindLabel = computed(() => ({
  root: 'Root',
  intermediate: 'Intermediate',
  leaf: 'Leaf',
})[props.certificate.kind] || 'Certificate')

const headerTone = computed(() => {
  const cert = props.certificate
  if (cert.revocation) {
    return 'bg-danger/15 text-danger-strong dark:bg-danger/25 dark:text-red-200'
  }
  if (props.depth === 0) {
    return 'bg-brand-800 text-white'
  }
  if (props.depth === 1) {
    return cert.is_owner
      ? 'bg-brand-100 text-brand-800 dark:bg-brand-700/50 dark:text-brand-50'
      : 'bg-brand-700 text-white'
  }
  return 'bg-sunken'
})

const isExpiringSoon = computed(() => {
  const days = props.certificate.expires_in_days
  return typeof days === 'number' && days >= 0 && days <= 30
})

const isExpired = computed(() => {
  const days = props.certificate.expires_in_days
  return typeof days === 'number' && days < 0
})

function formatDate(value) {
  if (!value) return '-'
  return new Date(value).toLocaleString()
}

function formatExpiry() {
  const days = props.certificate.expires_in_days
  if (typeof days !== 'number') return '-'
  if (days < 0) return `expired ${Math.abs(days)} day(s) ago`
  return `in ${days} day(s)`
}
</script>

<template>
  <div
    class="rounded-lg border shadow-sm"
    :class="{ 'ms-6': depth === 1, 'ms-6 mt-2': depth === 2 }"
    :style="{ backgroundColor: 'var(--surface-card)', borderColor: 'var(--border-subtle)' }"
    :data-cert-kind="certificate.kind"
    :data-cert-id="certificate.id"
    :data-cert-name="certificate.name"
    :data-revoked="certificate.revocation ? 'true' : 'false'"
  >
    <div class="flex flex-wrap items-center gap-x-4 gap-y-2 rounded-t-lg px-4 py-3" :class="headerTone">
      <div class="min-w-0 flex-1">
        <h3 class="truncate text-sm font-semibold" :class="{ 'line-through opacity-80': certificate.revocation }">
          {{ kindLabel }}: {{ certificate.name }}
        </h3>
        <div class="mt-1 flex flex-wrap items-center gap-2 text-xs opacity-90">
          <span v-if="certificate.revocation" class="rounded bg-danger px-2 py-0.5 font-medium text-white">
            Revoked
          </span>
          <span v-if="certificate.is_owner" class="rounded bg-white/85 px-2 py-0.5 font-medium text-gray-900">
            Created by you
          </span>
          <span v-if="!certificate.is_owner && certificate.owner" class="opacity-80">
            owner: {{ certificate.owner }}
          </span>
        </div>
      </div>

      <div class="flex flex-wrap items-center gap-2">
        <button
          type="button"
          class="rounded border border-current/30 bg-white/85 px-2.5 py-1 text-xs font-medium text-gray-900 transition hover:bg-white"
          @click="emit('download-public', certificate)"
        >
          Public {{ certificate.kind === 'leaf' ? 'chain' : 'key' }}
        </button>

        <template v-if="certificate.is_owner">
          <button
            type="button"
            class="rounded bg-amber-400/90 px-2.5 py-1 text-xs font-medium text-gray-900 transition hover:bg-amber-300"
            @click="emit('download-private', certificate)"
          >
            Private key
          </button>
          <button
            type="button"
            class="rounded bg-sky-500/90 px-2.5 py-1 text-xs font-medium text-white transition hover:bg-sky-400"
            @click="emit('export-pkcs12', certificate)"
          >
            PKCS12
          </button>
        </template>

        <template v-if="certificate.can_manage">
          <button
            v-if="!certificate.revocation"
            type="button"
            class="rounded border border-red-500/60 px-2.5 py-1 text-xs font-medium text-red-700 transition hover:bg-red-500/10 dark:text-red-200"
            :data-testid="`revoke-${certificate.kind}-${certificate.id}`"
            @click="emit('revoke', certificate)"
          >
            Revoke
          </button>
          <button
            type="button"
            class="rounded bg-danger px-2.5 py-1 text-xs font-medium text-white transition hover:opacity-90"
            :data-testid="`delete-${certificate.kind}-${certificate.id}`"
            @click="emit('delete', certificate)"
          >
            Delete
          </button>
        </template>
      </div>
    </div>

    <div class="space-y-1 px-4 py-3 text-xs" :style="{ color: 'var(--text-secondary)' }">
      <div class="flex flex-wrap gap-x-4 gap-y-1">
        <span>Serial: <span class="font-mono">{{ certificate.serial_number }}</span></span>
        <span>Created: {{ formatDate(certificate.created_at) }}</span>
        <span>
          Expires: {{ formatDate(certificate.valid_until) }}
          <span
            class="ms-1 rounded px-1.5 py-0.5"
            :class="isExpired
              ? 'bg-danger/20 text-danger-strong dark:text-red-200'
              : (isExpiringSoon ? 'bg-amber-500/20 text-amber-800 dark:text-amber-200' : '')"
          >({{ formatExpiry() }})</span>
        </span>
      </div>

      <div v-if="certificate.signed_by" class="flex flex-wrap gap-x-4">
        <span>Signed by: {{ certificate.signed_by.name }}</span>
      </div>

      <div v-if="certificate.sans && certificate.sans.length" class="break-words">
        SAN: {{ certificate.sans.join(', ') }}
      </div>

      <div v-if="certificate.revocation" class="rounded px-2 py-1" :style="{ backgroundColor: 'var(--surface-danger)' }">
        <strong>Revoked {{ formatDate(certificate.revocation.revoked_at) }}</strong>
        ({{ certificate.revocation.reason_label }}<template v-if="certificate.revocation.comment">:
          {{ certificate.revocation.comment }}</template>)
      </div>
    </div>
  </div>
</template>
