<script setup>
/**
 * The dialog a locked credential raises.
 *
 * Two shapes, decided by what the server said when it refused:
 *
 *   open   -- the key belongs to a known credential, so this asks for *that*
 *             credential's password. An account may hold several, and the name is
 *             shown so it is clear which secret is being asked for.
 *   create -- the account has no credential at all, so there is nothing to open.
 *             This asks for a name and a password, and offers to encrypt the
 *             cleartext keys the account already has while it is here.
 *
 * Either way the answer is never stored: the password unwraps the credential's
 * root key on the server, which keeps it in memory for an idle timeout only.
 */
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import AppModal from '@/components/AppModal.vue'
import FormField from '@/components/FormField.vue'
import { useKeystoreStore } from '@/stores/keystore'

const props = defineProps({
  open: { type: Boolean, default: false },
  busy: { type: Boolean, default: false },
  /** Why the dialog opened, shown to orient the reader. */
  reason: { type: String, default: '' },
  /** The credential to open, or null to create the account's first one. */
  credentialId: { type: [Number, String], default: null },
})

const emit = defineEmits(['close', 'unlocked'])

const keystore = useKeystoreStore()
const { t } = useI18n()

const password = ref('')
const name = ref('')
const encryptExisting = ref(true)
const localError = ref('')

const mode = computed(() => (props.credentialId ? 'open' : 'create'))
const credential = computed(
  () => keystore.credentials.find((entry) => entry.id === props.credentialId) || null)
/** Cleartext keys this account still has: what the create mode would encrypt. */
const cleartextCount = computed(() => keystore.counts.plaintext || 0)
const canSubmit = computed(() => password.value.length >= 8
  && (mode.value === 'open' || name.value.trim().length > 0))

/** A name the operator does not have to invent, and that stays unique. */
function suggestedName() {
  return t('dialog.keystore.defaultName', { count: keystore.credentials.length + 1 })
}

watch(
  () => props.open,
  async (isOpen) => {
    if (!isOpen) {
      name.value = ''
      return
    }
    password.value = ''
    localError.value = ''
    encryptExisting.value = true
    // Suggest a name straight away, and only ever fill a field that is still
    // empty: this dialog must not overwrite what is being typed into it.
    if (mode.value === 'create' && !name.value) {
      name.value = suggestedName()
    }
    if (!keystore.credentials.length) {
      await keystore.load()
      if (mode.value === 'create' && !name.value) {
        name.value = suggestedName()
      }
    }
  },
)

async function submit() {
  localError.value = ''
  try {
    if (mode.value === 'create') {
      await keystore.create(name.value.trim(), password.value)
    } else {
      await keystore.unlock(props.credentialId, password.value)
    }
    password.value = ''
    emit('unlocked')
  } catch (err) {
    localError.value = keystore.error || t('dialog.keystore.error')
  }
}
</script>

<template>
  <AppModal
    :open="open"
    :title="t(`dialog.keystore.title.${mode}`)"
    :close-on-backdrop="false"
    layer="top"
    @close="emit('close')"
  >
    <p class="text-sm text-slate-600 dark:text-slate-300">
      <template v-if="mode === 'open'">
        {{ t('dialog.keystore.openIntro', { name: credential?.name || '' }) }}
      </template>
      <template v-else>
        {{ t('dialog.keystore.createIntro') }}
      </template>
    </p>

    <p v-if="reason" class="mt-2 text-xs text-slate-500 dark:text-slate-400">
      {{ reason }}
    </p>

    <p
      class="mt-3 rounded-lg border-l-4 border-amber-500 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:bg-amber-950/40 dark:text-amber-200"
    >
      <i18n-t keypath="dialog.keystore.noRecoveryWarning" tag="span">
        <template #lead>
          <strong class="font-semibold">{{ t('dialog.keystore.noRecovery') }}</strong>
        </template>
      </i18n-t>
    </p>

    <form class="mt-4 space-y-3" @submit.prevent="submit">
      <FormField
        v-if="mode === 'create'"
        id="credential-name"
        v-model="name"
        :label="t('dialog.keystore.nameLabel')"
        :help="t('dialog.keystore.nameHelp')"
        required
      />

      <FormField
        id="vault-password"
        v-model="password"
        type="password"
        data-testid="vault-password"
        autocomplete="current-password"
        :label="mode === 'create'
          ? t('dialog.keystore.choosePassword')
          : t('dialog.keystore.password')"
        :placeholder="mode === 'create' ? t('dialog.keystore.passwordPlaceholder') : ''"
        :help="mode === 'create' ? t('dialog.keystore.passwordHelp') : ''"
        required
      />

      <label
        v-if="mode === 'create' && cleartextCount > 0"
        class="flex items-start gap-2 text-sm text-slate-700 dark:text-slate-200"
      >
        <input
          v-model="encryptExisting"
          type="checkbox"
          data-testid="keystore-encrypt-existing"
          class="mt-0.5 size-4 flex-none rounded border-slate-300 text-brand-600 focus:ring-brand-500 dark:border-slate-600 dark:bg-slate-900"
        />
        <span>{{ t('dialog.keystore.encryptExisting', { count: cleartextCount }) }}</span>
      </label>

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
          {{ mode === 'create'
            ? t('dialog.keystore.submitCreate')
            : t('dialog.keystore.submitOpen') }}
        </button>
      </div>
    </form>
  </AppModal>
</template>
