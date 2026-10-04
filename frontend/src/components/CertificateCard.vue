<script setup>
/**
 * A single certificate in the hierarchy, with its metadata and the actions this
 * user is allowed to take on it.
 *
 * Nested levels are told apart by two things only: the card is indented, and it
 * carries a coloured left rule. Both come from the class recipe below rather
 * than a stylesheet, so the two themes sit side by side in the markup.
 */
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import DownloadMenu from '@/components/DownloadMenu.vue'

const props = defineProps({
  certificate: { type: Object, required: true },
  /** 0 for roots, 1 for intermediates, 2 for leaves - drives the indent. */
  depth: { type: Number, default: 0 },
})

// `download` carries `{ certificate, format }`: which format exists, and what
// each one requires, is the server's table, not this component's business.
const emit = defineEmits(['download', 'revoke', 'delete'])

const { t, d } = useI18n()

const KIND_KEYS = {
  root: 'home.kind.root',
  intermediate: 'home.kind.intermediate',
  leaf: 'home.kind.leaf',
}

const kindLabel = computed(() => t(KIND_KEYS[props.certificate.kind] || 'home.kind.certificate'))

/**
 * One card, three depths. The root is a plain white card; every level below it
 * steps in and gains a left rule, so the hierarchy reads as a hierarchy without
 * a nested box inside a nested box.
 */
const CARD_BASE = 'overflow-hidden rounded-xl shadow-sm'

const cardClass = computed(() => {
  if (props.depth === 0) {
    return `${CARD_BASE} border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900`
  }
  if (props.depth === 1) {
    return [
      CARD_BASE, 'ms-6',
      'border-y border-e border-s-4 border-y-slate-200 border-e-slate-200 border-s-brand-400',
      'bg-white dark:border-y-slate-800 dark:border-e-slate-800 dark:border-s-brand-500 dark:bg-slate-900',
    ].join(' ')
  }
  return [
    CARD_BASE, 'ms-12 mt-2',
    'border-y border-e border-s-4 border-y-slate-200 border-e-slate-200 border-s-slate-300',
    'bg-white dark:border-y-slate-800 dark:border-e-slate-800 dark:border-s-slate-600 dark:bg-slate-900',
  ].join(' ')
})

const headerTone = computed(() => {
  const cert = props.certificate
  if (cert.revocation) {
    return 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-200'
  }
  if (props.depth === 0) {
    return 'bg-brand-800 text-white'
  }
  if (props.depth === 1) {
    return cert.is_owner
      ? 'bg-brand-100 text-brand-800 dark:bg-brand-700/50 dark:text-brand-50'
      : 'bg-brand-700 text-white'
  }
  return 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-200'
})

const isExpiringSoon = computed(() => {
  const days = props.certificate.expires_in_days
  return typeof days === 'number' && days >= 0 && days <= 30
})

const isExpired = computed(() => {
  const days = props.certificate.expires_in_days
  return typeof days === 'number' && days < 0
})

/** Short date in the reader's locale, not the browser's default formatting. */
function formatDate(value) {
  if (!value) return '-'
  return d(new Date(value), 'short')
}

function formatExpiry() {
  const days = props.certificate.expires_in_days
  if (typeof days !== 'number') return '-'
  if (days < 0) return t('home.expiry.expiredAgo', Math.abs(days))
  return t('home.expiry.inDays', days)
}
</script>

<template>
  <div
    :class="cardClass"
    :data-cert-kind="certificate.kind"
    :data-cert-id="certificate.id"
    :data-cert-name="certificate.name"
    :data-revoked="certificate.revocation ? 'true' : 'false'"
  >
    <div class="flex flex-wrap items-center gap-x-4 gap-y-2 rounded-t-xl px-4 py-3" :class="headerTone">
      <div class="min-w-0 flex-1">
        <h3 class="truncate text-sm font-semibold" :class="{ 'line-through opacity-80': certificate.revocation }">
          {{ kindLabel }}: {{ certificate.name }}
        </h3>
        <div class="mt-1 flex flex-wrap items-center gap-2 text-xs opacity-90">
          <span
            v-if="certificate.revocation"
            class="inline-block whitespace-nowrap rounded-full bg-red-100 px-2 py-0.5 text-xs font-medium text-red-800 dark:bg-red-900/40 dark:text-red-200"
          >
            {{ t('common.status.revoked') }}
          </span>
          <span
            v-if="certificate.is_owner"
            class="inline-block whitespace-nowrap rounded-full bg-white/85 px-2 py-0.5 text-xs font-medium text-slate-900 dark:bg-white/15 dark:text-slate-100"
          >
            {{ t('home.badge.createdByYou') }}
          </span>
          <span
            v-if="certificate.has_key === false"
            class="inline-block whitespace-nowrap rounded-full bg-slate-500/80 px-2 py-0.5 text-xs font-medium text-white"
            :title="t('home.badge.noPrivateKeyTitle')"
          >
            {{ t('home.badge.noPrivateKey') }}
          </span>
          <span v-if="!certificate.is_owner && certificate.owner" class="opacity-80">
            {{ t('home.badge.owner', { owner: certificate.owner }) }}
          </span>
        </div>
      </div>

      <div class="flex flex-wrap items-center gap-2">
        <DownloadMenu
          :certificate="certificate"
          :has-key="certificate.has_key !== false"
          @choose="(format) => emit('download', { certificate, format })"
        />

        <span
          v-if="certificate.has_key !== false && !certificate.protected"
          class="inline-block whitespace-nowrap rounded-full bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-800 dark:bg-amber-900/40 dark:text-amber-200"
          :title="t('home.badge.keyNotEncryptedTitle')"
        >
          {{ t('home.badge.keyNotEncrypted') }}
        </span>

        <template v-if="certificate.can_manage">
          <button
            v-if="!certificate.revocation"
            type="button"
            class="rounded-lg border border-red-300 bg-white px-2 py-1 text-xs font-medium text-red-700 transition hover:bg-red-50 dark:border-red-800 dark:bg-slate-900 dark:text-red-300 dark:hover:bg-red-950/40"
            :data-testid="`revoke-${certificate.kind}-${certificate.id}`"
            @click="emit('revoke', certificate)"
          >
            {{ t('common.action.revoke') }}
          </button>
          <button
            type="button"
            class="rounded-lg bg-red-600 px-2 py-1 text-xs font-medium text-white transition hover:bg-red-500"
            :data-testid="`delete-${certificate.kind}-${certificate.id}`"
            @click="emit('delete', certificate)"
          >
            {{ t('common.action.delete') }}
          </button>
        </template>
      </div>
    </div>

    <div class="space-y-1 px-4 py-3 text-xs text-slate-600 dark:text-slate-300">
      <div class="flex flex-wrap gap-x-4 gap-y-1">
        <span>{{ t('home.field.serial') }} <span class="font-mono">{{ certificate.serial_number }}</span></span>
        <span>{{ t('home.field.created') }} {{ formatDate(certificate.created_at) }}</span>
        <span>
          {{ t('home.field.expires') }} {{ formatDate(certificate.valid_until) }}
          <span
            class="ms-1 rounded px-1.5 py-0.5"
            :class="isExpired
              ? 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-200'
              : (isExpiringSoon ? 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-200' : '')"
          >{{ formatExpiry() }}</span>
        </span>
      </div>

      <div v-if="certificate.signed_by" class="flex flex-wrap gap-x-4">
        <span>{{ t('home.field.signedBy') }} {{ certificate.signed_by.name }}</span>
      </div>

      <div v-if="certificate.sans && certificate.sans.length" class="break-words">
        {{ t('common.field.sanLabel') }} {{ certificate.sans.join(', ') }}
      </div>

      <div
        v-if="certificate.revocation"
        class="rounded-lg border-l-4 border-red-500 bg-red-50 px-2 py-1 text-red-900 dark:bg-red-950/40 dark:text-red-200"
      >
        <strong>{{ t('home.revokedAt', { date: formatDate(certificate.revocation.revoked_at) }) }}</strong>
        ({{ certificate.revocation.reason_label }}<template v-if="certificate.revocation.comment">:
          {{ certificate.revocation.comment }}</template>)
      </div>
    </div>
  </div>
</template>
