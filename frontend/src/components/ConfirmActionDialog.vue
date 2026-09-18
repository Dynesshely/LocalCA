<script setup>
/**
 * Confirmation dialog for the destructive certificate actions.
 *
 * Revoking offers an RFC 5280 reason, a comment, and (for CAs) the option to
 * cascade to the certificates it signed. Deleting states the exact number of
 * certificates that will be removed with it and is irreversible.
 */
import { computed, ref, watch } from 'vue'
import AppModal from '@/components/AppModal.vue'
import { useAuthStore } from '@/stores/auth'

const props = defineProps({
  open: { type: Boolean, default: false },
  /** 'revoke' | 'delete' */
  action: { type: String, default: 'revoke' },
  /** The certificate being acted on. */
  certificate: { type: Object, default: null },
  busy: { type: Boolean, default: false },
})

const emit = defineEmits(['close', 'confirm'])

const auth = useAuthStore()

const reason = ref('unspecified')
const comment = ref('')
const cascade = ref(false)

const isRevoke = computed(() => props.action === 'revoke')
const isCa = computed(() =>
  props.certificate ? ['root', 'intermediate'].includes(props.certificate.kind) : false)
const kindLabel = computed(() => {
  switch (props.certificate?.kind) {
    case 'root': return 'root CA'
    case 'intermediate': return 'intermediate CA'
    case 'leaf': return 'leaf certificate'
    default: return 'certificate'
  }
})
const name = computed(() => props.certificate?.name || '')
const descendants = computed(() => props.certificate?.descendants || 0)

// Reset the form whenever a new target is opened, so a previous comment or
// cascade choice cannot leak into the next action.
watch(
  () => [props.open, props.certificate?.kind, props.certificate?.id],
  ([isOpen]) => {
    if (isOpen) {
      reason.value = auth.revocationReasons[0]?.value || 'unspecified'
      comment.value = ''
      cascade.value = false
    }
  },
)

function confirm() {
  emit('confirm', {
    reason: reason.value,
    comment: comment.value,
    cascade: cascade.value,
  })
}
</script>

<template>
  <AppModal
    :open="open"
    :tone="isRevoke ? 'warning' : 'danger'"
    :title="isRevoke ? 'Revoke certificate' : 'Delete certificate'"
    :close-on-backdrop="false"
    @close="emit('close')"
  >
    <p class="text-sm">
      {{ isRevoke ? 'Revoke the' : 'Permanently delete the' }}
      {{ kindLabel }}
      <strong class="font-semibold">{{ name }}</strong>?
    </p>

    <!-- revoke: reason, comment, optional cascade -->
    <template v-if="isRevoke">
      <div class="mt-4">
        <label for="revoke-reason" class="mb-1 block text-sm font-medium">Revocation reason</label>
        <select
          id="revoke-reason"
          v-model="reason"
          data-testid="revoke-reason"
          class="w-full rounded border px-3 py-2 text-sm"
          :style="{ backgroundColor: 'var(--surface-sunken)', borderColor: 'var(--border-subtle)', color: 'var(--text-primary)' }"
        >
          <option v-for="option in auth.revocationReasons" :key="option.value" :value="option.value">
            {{ option.label }}
          </option>
        </select>
        <p class="mt-1 text-xs" :style="{ color: 'var(--text-secondary)' }">
          RFC 5280 CRL reason. Recorded in the audit log.
        </p>
      </div>

      <div class="mt-4">
        <label for="revoke-comment" class="mb-1 block text-sm font-medium">
          Comment <span :style="{ color: 'var(--text-secondary)' }">(optional)</span>
        </label>
        <input
          id="revoke-comment"
          v-model="comment"
          type="text"
          maxlength="500"
          placeholder="e.g. laptop stolen, key rotated"
          data-testid="revoke-comment"
          class="w-full rounded border px-3 py-2 text-sm"
          :style="{ backgroundColor: 'var(--surface-sunken)', borderColor: 'var(--border-subtle)', color: 'var(--text-primary)' }"
        />
      </div>

      <label
        v-if="isCa"
        class="mt-4 flex items-start gap-2 text-sm"
      >
        <input
          v-model="cascade"
          type="checkbox"
          class="mt-0.5"
          data-testid="revoke-cascade"
        />
        <span>
          Also revoke the {{ descendants }} certificate(s) signed by this one
        </span>
      </label>

      <p
        class="mt-4 rounded px-3 py-2 text-xs"
        :style="{ backgroundColor: 'var(--surface-warn)', color: 'var(--text-primary)' }"
      >
        <template v-if="isCa">
          Revocation is recorded in this application only. It does not remove the
          certificate from any trust store, and there is no CRL or OCSP endpoint
          to publish it yet &mdash; clients will keep trusting this CA until the
          certificate expires or is removed from the trust store manually.
        </template>
        <template v-else>
          Revocation is recorded in this application only. This app publishes no
          CRL or OCSP endpoint yet, so already-distributed certificates keep
          working until they expire &mdash; pair it with removing the certificate
          from the relying systems.
        </template>
      </p>
    </template>

    <!-- delete: state the cascade, it cannot be undone -->
    <p
      v-else
      class="mt-4 rounded px-3 py-2 text-xs"
      :style="{ backgroundColor: 'var(--surface-danger)', color: 'var(--text-primary)' }"
    >
      <template v-if="descendants > 0">
        This deletes the private key material and {{ descendants }} certificate(s)
        signed by it, immediately and irreversibly. If you only need to invalidate
        it, revoke instead.
      </template>
      <template v-else>
        This deletes the private key material immediately and irreversibly. This
        cannot be undone.
      </template>
    </p>

    <template #footer>
      <button
        type="button"
        class="rounded border px-3 py-2 text-sm transition"
        :style="{ borderColor: 'var(--border-strong)', color: 'var(--text-primary)' }"
        :disabled="busy"
        @click="emit('close')"
      >
        Cancel
      </button>
      <button
        type="button"
        class="rounded px-3 py-2 text-sm font-medium text-white transition disabled:opacity-60"
        :style="{ backgroundColor: isRevoke ? 'var(--color-danger)' : 'var(--color-danger-strong)' }"
        :disabled="busy"
        data-testid="confirm-action"
        @click="confirm"
      >
        {{ busy ? 'Working...' : (isRevoke ? 'Revoke' : 'Delete permanently') }}
      </button>
    </template>
  </AppModal>
</template>
