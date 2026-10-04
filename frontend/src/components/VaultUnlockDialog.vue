<script setup>
/**
 * Unlock dialog for the private key vault.
 *
 * Shown when an action needs a private key and the vault is closed. Password
 * managers are guided to offer the account password, since the same value is
 * used for both by default.
 */
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import AppModal from '@/components/AppModal.vue'
import { useVaultStore } from '@/stores/vault'

const props = defineProps({
  open: { type: Boolean, default: false },
  busy: { type: Boolean, default: false },
  /** Why the dialog opened, shown to orient the user. */
  reason: { type: String, default: '' },
})

const emit = defineEmits(['close', 'unlocked'])

const vault = useVaultStore()
const { t } = useI18n()
const password = ref('')
const localError = ref('')

const isFirstTime = computed(() => vault.needsPasswordSetup)
const canSubmit = computed(() => password.value.length >= 8)

watch(
  () => props.open,
  (isOpen) => {
    if (isOpen) {
      password.value = ''
      localError.value = ''
      vault.load()
    }
  },
)

async function submit() {
  localError.value = ''
  try {
    await vault.unseal(password.value)
    password.value = ''
    emit('unlocked')
  } catch (err) {
    localError.value = vault.error || t('dialog.vault.error')
  }
}
</script>

<template>
  <AppModal
    :open="open"
    :title="t('dialog.vault.title')"
    :close-on-backdrop="false"
    @close="emit('close')"
  >
    <i18n-t
      v-if="isFirstTime"
      keypath="dialog.vault.firstTimeIntro"
      tag="p"
      class="text-sm text-slate-600 dark:text-slate-300"
    >
      <template #password>
        <strong class="font-semibold text-slate-900 dark:text-slate-100">
          {{ t('dialog.vault.password') }}
        </strong>
      </template>
    </i18n-t>
    <p v-else class="text-sm text-slate-600 dark:text-slate-300">
      {{ t('dialog.vault.intro') }}
    </p>

    <p v-if="reason" class="mt-2 text-xs text-slate-500 dark:text-slate-400">
      {{ reason }}
    </p>

    <p
      v-if="isFirstTime"
      class="mt-3 rounded-lg border-l-4 border-amber-500 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:bg-amber-950/40 dark:text-amber-200"
    >
      <i18n-t keypath="dialog.vault.noRecoveryWarning" tag="span">
        <template #lead>
          <strong class="font-semibold">{{ t('dialog.vault.noRecovery') }}</strong>
        </template>
      </i18n-t>
    </p>

    <form class="mt-4 space-y-3" @submit.prevent="submit">
      <div>
        <label for="vault-password" class="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-200">
          {{ isFirstTime ? t('dialog.vault.choosePassword') : t('dialog.vault.password') }}
        </label>
        <input
          id="vault-password"
          v-model="password"
          type="password"
          autocomplete="current-password"
          data-testid="vault-password"
          class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 shadow-sm transition placeholder:text-slate-400 focus:border-brand-500 focus:ring-2 focus:ring-brand-500/25 focus:outline-none dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100 dark:placeholder:text-slate-500"
          :placeholder="isFirstTime ? t('dialog.vault.passwordPlaceholder') : ''"
        />
        <p v-if="isFirstTime" class="mt-1.5 text-xs text-slate-500 dark:text-slate-400">
          {{ t('dialog.vault.passwordHelp') }}
        </p>
      </div>

      <p
        v-if="localError"
        class="rounded-lg border-l-4 border-red-500 bg-red-50 px-3 py-2 text-sm text-red-900 dark:bg-red-950/40 dark:text-red-200"
        role="alert"
        data-testid="vault-error"
      >
        {{ localError }}
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
          :disabled="busy || !canSubmit"
          data-testid="vault-unseal"
        >
          {{ isFirstTime ? t('dialog.vault.submitFirstTime') : t('dialog.vault.submit') }}
        </button>
      </div>
    </form>
  </AppModal>
</template>
