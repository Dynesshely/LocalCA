<script setup>
/**
 * Unlock dialog for the private key vault.
 *
 * Shown when an action needs a private key and the vault is closed. Password
 * managers are guided to offer the account password, since the same value is
 * used for both by default.
 */
import { computed, ref, watch } from 'vue'
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
    localError.value = vault.error || 'Could not open the vault.'
  }
}
</script>

<template>
  <AppModal
    :open="open"
    title="Unlock private keys"
    :close-on-backdrop="false"
    @close="emit('close')"
  >
    <p class="text-sm">
      <template v-if="isFirstTime">
        Certificate private keys are stored encrypted. Choose a <strong>vault
        password</strong> to protect them — this becomes the password you enter
        whenever LocalCA needs to sign or export a key.
      </template>
      <template v-else>
        Private keys are encrypted at rest. Enter your vault password to use them
        for signing and export.
      </template>
    </p>

    <p v-if="reason" class="mt-2 text-xs" :style="{ color: 'var(--text-secondary)' }">
      {{ reason }}
    </p>

    <p
      v-if="isFirstTime"
      class="mt-3 rounded px-3 py-2 text-xs"
      :style="{ backgroundColor: 'var(--surface-warn)', color: 'var(--text-primary)' }"
    >
      <strong>There is no recovery.</strong> If you forget this password, every
      private key under this account becomes permanently unreadable — including
      any CA key. Nobody, including an administrator, can reset it.
    </p>

    <form class="mt-4 space-y-3" @submit.prevent="submit">
      <div>
        <label for="vault-password" class="mb-1 block text-sm font-medium">
          {{ isFirstTime ? 'Choose a vault password' : 'Vault password' }}
        </label>
        <input
          id="vault-password"
          v-model="password"
          type="password"
          autocomplete="current-password"
          data-testid="vault-password"
          class="w-full rounded border px-3 py-2 text-sm"
          :style="{ backgroundColor: 'var(--surface-sunken)', borderColor: 'var(--border-subtle)', color: 'var(--text-primary)' }"
          :placeholder="isFirstTime ? 'At least 8 characters' : ''"
        />
        <p v-if="isFirstTime" class="mt-1 text-xs" :style="{ color: 'var(--text-secondary)' }">
          At least 8 characters. Longer is better; this guards your CA keys offline.
        </p>
      </div>

      <p
        v-if="localError"
        class="rounded border-l-4 border-red-500 bg-red-50 px-3 py-2 text-sm text-red-900 dark:bg-red-950/50 dark:text-red-200"
        role="alert"
        data-testid="vault-error"
      >
        {{ localError }}
      </p>

      <div class="flex justify-end gap-2">
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
          type="submit"
          class="rounded px-3 py-2 text-sm font-medium text-white transition disabled:opacity-60"
          :style="{ backgroundColor: 'var(--color-brand-700)' }"
          :disabled="busy || !canSubmit"
          data-testid="vault-unseal"
        >
          {{ isFirstTime ? 'Set password and unlock' : 'Unlock' }}
        </button>
      </div>
    </form>
  </AppModal>
</template>
