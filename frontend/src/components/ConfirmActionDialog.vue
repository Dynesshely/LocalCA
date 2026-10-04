<script setup>
/**
 * Confirmation dialog for the destructive certificate actions.
 *
 * Revoking offers an RFC 5280 reason, a comment, and (for CAs) the option to
 * cascade to the certificates it signed. Deleting states the exact number of
 * certificates that will be removed with it and is irreversible.
 */
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
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
const { t } = useI18n()

const reason = ref('unspecified')
const comment = ref('')
const cascade = ref(false)

const isRevoke = computed(() => props.action === 'revoke')
const isCa = computed(() =>
  props.certificate ? ['root', 'intermediate'].includes(props.certificate.kind) : false)
/** The kind of thing being acted on, as a translated noun phrase. */
const kindLabel = computed(() => {
  switch (props.certificate?.kind) {
    case 'root': return t('dialog.kind.root')
    case 'intermediate': return t('dialog.kind.intermediate')
    case 'leaf': return t('dialog.kind.leaf')
    default: return t('dialog.kind.certificate')
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
    :title="isRevoke ? t('dialog.revoke.title') : t('dialog.delete.title')"
    :close-on-backdrop="false"
    @close="emit('close')"
  >
    <i18n-t
      :keypath="isRevoke ? 'dialog.revoke.prompt' : 'dialog.delete.prompt'"
      tag="p"
      class="text-sm text-slate-600 dark:text-slate-300"
    >
      <template #kind>{{ kindLabel }}</template>
      <template #name>
        <strong class="font-semibold text-slate-900 dark:text-slate-100">{{ name }}</strong>
      </template>
    </i18n-t>

    <!-- revoke: reason, comment, optional cascade -->
    <template v-if="isRevoke">
      <div class="mt-4">
        <label for="revoke-reason" class="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-200">
          {{ t('dialog.revoke.reasonLabel') }}
        </label>
        <select
          id="revoke-reason"
          v-model="reason"
          data-testid="revoke-reason"
          class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 shadow-sm transition focus:border-brand-500 focus:ring-2 focus:ring-brand-500/25 focus:outline-none dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
        >
          <option v-for="option in auth.revocationReasons" :key="option.value" :value="option.value">
            {{ option.label }}
          </option>
        </select>
        <p class="mt-1.5 text-xs text-slate-500 dark:text-slate-400">
          {{ t('dialog.revoke.reasonHelp') }}
        </p>
      </div>

      <div class="mt-4">
        <label for="revoke-comment" class="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-200">
          {{ t('dialog.revoke.commentLabel') }}
          <span class="font-normal text-slate-400 dark:text-slate-500">
            ({{ t('common.state.optional') }})
          </span>
        </label>
        <input
          id="revoke-comment"
          v-model="comment"
          type="text"
          maxlength="500"
          :placeholder="t('dialog.revoke.commentPlaceholder')"
          data-testid="revoke-comment"
          class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 shadow-sm transition placeholder:text-slate-400 focus:border-brand-500 focus:ring-2 focus:ring-brand-500/25 focus:outline-none dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100 dark:placeholder:text-slate-500"
        />
      </div>

      <label
        v-if="isCa"
        class="mt-4 flex items-start gap-2 text-sm text-slate-600 dark:text-slate-300"
      >
        <input
          v-model="cascade"
          type="checkbox"
          class="mt-0.5"
          data-testid="revoke-cascade"
        />
        <span>
          {{ t('dialog.revoke.cascade', { count: descendants }) }}
        </span>
      </label>

      <p class="mt-4 rounded-lg border-l-4 border-amber-500 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:bg-amber-950/40 dark:text-amber-200">
        {{ isCa ? t('dialog.revoke.warningCa') : t('dialog.revoke.warningLeaf') }}
      </p>
    </template>

    <!-- delete: state the cascade, it cannot be undone -->
    <p
      v-else
      class="mt-4 rounded-lg border-l-4 border-red-500 bg-red-50 px-3 py-2 text-sm text-red-900 dark:bg-red-950/40 dark:text-red-200"
    >
      {{ descendants > 0 ? t('dialog.delete.warningCascade', { count: descendants }) : t('dialog.delete.warning') }}
    </p>

    <template #footer>
      <button
        type="button"
        class="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-medium text-slate-700 transition hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700"
        :disabled="busy"
        @click="emit('close')"
      >
        {{ t('common.action.cancel') }}
      </button>
      <button
        type="button"
        class="rounded-lg px-3 py-2 text-sm font-medium text-white transition disabled:cursor-not-allowed disabled:opacity-60"
        :class="isRevoke ? 'bg-red-600 hover:bg-red-500' : 'bg-red-700 hover:bg-red-600'"
        :disabled="busy"
        data-testid="confirm-action"
        @click="confirm"
      >
        {{ busy ? t('common.state.working') : (isRevoke ? t('common.action.revoke') : t('dialog.delete.confirm')) }}
      </button>
    </template>
  </AppModal>
</template>
