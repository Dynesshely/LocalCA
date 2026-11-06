<script setup>
/**
 * Renew a leaf: edit the names it answers to, get a new certificate.
 *
 * Only the SAN list (and the validity) are editable. The common name and the
 * signing intermediate are inherited — changing either is issuing a *different*
 * certificate, which is what Create Leaf is for.
 *
 * Self-contained: a host only says which certificate. A locked signing credential
 * goes through the usual open-then-retry flow rather than being rendered as an
 * error.
 */
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import AppModal from '@/components/AppModal.vue'
import FormField from '@/components/FormField.vue'
import { certificates } from '@/api'
import { ApiError } from '@/api/client'
import { useKeystoreStore } from '@/stores/keystore'
import { useToastStore } from '@/stores/toasts'

const props = defineProps({
  open: { type: Boolean, default: false },
  /** The leaf being replaced: needs id, name, sans, valid_until. */
  certificate: { type: Object, default: null },
})

const emit = defineEmits(['close', 'renewed'])

const { t } = useI18n()
const keystore = useKeystoreStore()
const toasts = useToastStore()

const san = ref('')
const validityDays = ref(365)
const busy = ref(false)
const errors = ref([])
const fieldErrors = ref({})

const name = computed(() => props.certificate?.name || '')

/** The lifetime the certificate was issued for, clamped to the leaf maximum. */
const suggestedValidity = computed(() => {
  const leaf = props.certificate
  if (!leaf?.valid_until || !leaf.created_at) {
    return 365
  }
  const issued = (new Date(leaf.valid_until) - new Date(leaf.created_at)) / 86400000
  return Math.max(1, Math.min(Math.round(issued), 825))
})

watch(
  () => [props.open, props.certificate?.id],
  ([isOpen]) => {
    if (!isOpen) {
      return
    }
    san.value = (props.certificate?.sans || []).join('\n')
    validityDays.value = suggestedValidity.value
    errors.value = []
    fieldErrors.value = {}
  },
  { immediate: true },
)

/**
 * Send one attempt.
 *
 * Split out from `submit` because the retry after opening a credential has to run
 * the same request again without the dialog on screen -- by which point the host
 * has already cleared `certificate`. The target id and name are therefore passed
 * in rather than read again from the props.
 */
async function run(payload, targetId = props.certificate?.id,
                   targetName = props.certificate?.name || '') {
  busy.value = true
  errors.value = []
  fieldErrors.value = {}
  try {
    const result = await certificates.renew(targetId, payload)
    toasts.success(t('renew.success', {
      name: result.certificate.name,
      serial: result.certificate.serial_number,
    }))
    emit('renewed', result)
    emit('close')
  } catch (err) {
    if (err instanceof ApiError && err.vaultLocked) {
      // The signing CA's credential (or the one the new key would be stored
      // under) is closed. Close this dialog first -- two stacked dialogs is a
      // worse question than one -- and let the shell ask, then retry this exact
      // request.
      //
      // `name` is a computed ref: inside `<script setup>` it is *not* unwrapped,
      // so passing it to `t()` would hand vue-i18n a Vue object and the
      // interpolator would throw before the unlock was ever requested.
      const reason = t('renew.unlockReason', { name: targetName })
      emit('close')
      keystore.requestUnlock({
        reason,
        credentialId: err.credentialId,
        retry: () => run(payload, targetId, targetName),
      })
      return
    }
    if (err instanceof ApiError) {
      errors.value = err.errors
      fieldErrors.value = err.fieldErrors
    } else {
      errors.value = [String(err)]
    }
  } finally {
    busy.value = false
  }
}

function submit() {
  run({ san: san.value, validity_days: String(validityDays.value) })
}
</script>

<template>
  <AppModal
    :open="open"
    :title="t('renew.title', { name })"
    :close-on-backdrop="false"
    @close="emit('close')"
  >
    <p class="text-sm text-slate-600 dark:text-slate-300">{{ t('renew.intro') }}</p>

    <dl class="mt-3 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm">
      <dt class="text-slate-500 dark:text-slate-400">{{ t('renew.commonName') }}</dt>
      <dd class="font-mono text-slate-900 dark:text-slate-100">{{ name }}</dd>
      <dt class="text-slate-500 dark:text-slate-400">{{ t('renew.issuer') }}</dt>
      <dd class="text-slate-900 dark:text-slate-100">
        {{ certificate?.signed_by?.name || t('renew.none') }}
      </dd>
    </dl>
    <p class="mt-1 text-xs text-slate-500 dark:text-slate-400">
      {{ t('renew.commonNameHelp') }}
    </p>

    <form class="mt-4 space-y-3" @submit.prevent="submit">
      <FormField
        id="renew-san"
        v-model="san"
        type="textarea"
        :rows="6"
        :label="t('renew.san')"
        :help="t('renew.sanHelp')"
        :error="fieldErrors.san ? fieldErrors.san[0] : ''"
      />

      <FormField
        id="renew-validity"
        v-model="validityDays"
        type="number"
        :min="1"
        :max="825"
        :label="t('renew.validity')"
        :help="t('renew.validityHelp')"
        :error="fieldErrors.validity_days ? fieldErrors.validity_days[0] : ''"
        required
      />

      <p
        v-if="errors.length"
        class="rounded-lg border-l-4 border-red-500 bg-red-50 px-3 py-2 text-sm text-red-900 dark:bg-red-950/40 dark:text-red-200"
        role="alert"
        data-testid="renew-error"
      >
        {{ errors.join(' ') }}
      </p>

      <div class="flex justify-end gap-2">
        <button
          type="button"
          class="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-medium text-slate-700 transition hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700"
          :disabled="busy"
          @click="emit('close')"
        >
          {{ t('common.action.cancel') }}
        </button>
        <button
          type="submit"
          class="rounded-lg bg-brand-700 px-3 py-2 text-sm font-medium text-white shadow-sm transition hover:bg-brand-600 disabled:cursor-not-allowed disabled:opacity-60"
          :disabled="busy"
          data-testid="renew-submit"
        >
          {{ busy ? t('renew.submitting') : t('renew.submit') }}
        </button>
      </div>
    </form>
  </AppModal>
</template>
