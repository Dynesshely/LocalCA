<script setup>
/**
 * The dialog a private-key download has to pass through.
 *
 * Two shapes, driven by what the format requires:
 *
 *   password -- an export password, so the key is not written unprotected. The
 *               bundle or key cannot be opened afterwards without it, which is
 *               why the warning is worded as "there is no recovery".
 *   confirm  -- the opposite: the file *is* unprotected, and the operator has to
 *               tick a box that says so before the button unlocks. A mistake
 *               here puts a CA key on disk in the clear.
 */
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import AppModal from '@/components/AppModal.vue'

const props = defineProps({
  open: { type: Boolean, default: false },
  certificate: { type: Object, default: null },
  /** The format id being downloaded, e.g. 'key-plain'. */
  format: { type: String, default: '' },
  /** 'password' | 'confirm' */
  requires: { type: String, default: 'password' },
  busy: { type: Boolean, default: false },
})

const emit = defineEmits(['close', 'confirm'])

const { t } = useI18n()

const password = ref('')
const showPassword = ref(false)
const acknowledged = ref(false)

watch(
  () => [props.open, props.certificate?.id, props.format],
  ([isOpen]) => {
    if (isOpen) {
      password.value = ''
      showPassword.value = false
      acknowledged.value = false
    }
  },
)

const name = computed(
  () => props.certificate?.name || props.certificate?.common_name || '')

const passwordOk = computed(() => password.value.length >= 8)
const ready = computed(() => (props.requires === 'password'
  ? passwordOk.value
  : acknowledged.value))

function submit() {
  if (!ready.value) {
    return
  }
  emit('confirm', props.requires === 'password'
    ? { key_password: password.value, p12_password: password.value }
    : { confirm: 'true' })
}
</script>

<template>
  <AppModal
    :open="open"
    :title="t(`dialog.export.title.${requires === 'password' ? 'protected' : 'unprotected'}`)"
    :close-on-backdrop="false"
    @close="emit('close')"
  >
    <i18n-t
      keypath="dialog.export.intro"
      tag="p"
      class="text-sm text-slate-600 dark:text-slate-300"
    >
      <template #name>
        <strong class="font-semibold text-slate-900 dark:text-slate-100">{{ name }}</strong>
      </template>
      <template #format>
        <span class="font-mono">{{ t(`home.download.format.${format}`) }}</span>
      </template>
    </i18n-t>

    <!-- password: the file is protected, and the password cannot be recovered -->
    <template v-if="requires === 'password'">
      <p
        class="mt-3 rounded-lg border-l-4 border-amber-500 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:bg-amber-950/40 dark:text-amber-200"
      >
        <i18n-t keypath="dialog.export.passwordWarning" tag="span">
          <template #lead>
            <strong class="font-semibold">{{ t('dialog.export.importantLead') }}</strong>
          </template>
        </i18n-t>
      </p>

      <div class="mt-4">
        <label
          for="export-password"
          class="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-200"
        >
          {{ t('dialog.export.passwordLabel') }}
        </label>
        <div class="flex gap-2">
          <input
            id="export-password"
            v-model="password"
            :type="showPassword ? 'text' : 'password'"
            autocomplete="new-password"
            :placeholder="t('dialog.export.passwordPlaceholder')"
            data-testid="export-password"
            class="flex-1 rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 shadow-sm transition placeholder:text-slate-400 focus:border-brand-500 focus:ring-2 focus:ring-brand-500/25 focus:outline-none dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100 dark:placeholder:text-slate-500"
          />
          <button
            type="button"
            class="rounded-lg border border-slate-300 bg-white px-3 py-2 text-xs font-medium text-slate-700 transition hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700"
            @click="showPassword = !showPassword"
          >
            {{ showPassword ? t('dialog.export.hide') : t('dialog.export.show') }}
          </button>
        </div>
        <p
          v-if="password && !passwordOk"
          class="mt-1.5 text-xs text-red-600 dark:text-red-400"
        >
          {{ t('dialog.export.passwordTooShort') }}
        </p>
      </div>
    </template>

    <!-- confirm: the file is NOT protected, and that has to be meant -->
    <template v-else>
      <p
        class="mt-3 rounded-lg border-l-4 border-red-500 bg-red-50 px-3 py-2 text-sm text-red-900 dark:bg-red-950/40 dark:text-red-200"
      >
        <i18n-t keypath="dialog.export.unprotectedWarning" tag="span">
          <template #lead>
            <strong class="font-semibold">{{ t('dialog.export.unprotectedLead') }}</strong>
          </template>
        </i18n-t>
      </p>

      <label class="mt-4 flex items-start gap-2 text-sm text-slate-700 dark:text-slate-200">
        <input
          v-model="acknowledged"
          type="checkbox"
          data-testid="export-acknowledge"
          class="mt-0.5 size-4 flex-none rounded border-slate-300 text-brand-600 focus:ring-brand-500 dark:border-slate-600 dark:bg-slate-900"
        />
        <span>{{ t('dialog.export.unprotectedConfirm') }}</span>
      </label>
    </template>

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
        class="rounded-lg bg-brand-700 px-3 py-2 text-sm font-medium text-white shadow-sm transition hover:bg-brand-600 disabled:cursor-not-allowed disabled:opacity-60"
        :disabled="busy || !ready"
        data-testid="export-confirm"
        @click="submit"
      >
        {{ busy
          ? t('dialog.export.preparing')
          : t(`dialog.export.submit.${requires === 'password' ? 'protected' : 'unprotected'}`) }}
      </button>
    </template>
  </AppModal>
</template>
