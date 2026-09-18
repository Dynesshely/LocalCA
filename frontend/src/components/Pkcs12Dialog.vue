<script setup>
/**
 * PKCS12 export dialog. The password is optional; the warning about it being
 * unrecoverable is kept from the original UI because the bundle cannot be
 * re-opened without it.
 */
import { ref, watch } from 'vue'
import AppModal from '@/components/AppModal.vue'

const props = defineProps({
  open: { type: Boolean, default: false },
  certificate: { type: Object, default: null },
  busy: { type: Boolean, default: false },
})

const emit = defineEmits(['close', 'export'])

const password = ref('')
const showPassword = ref(false)

watch(
  () => [props.open, props.certificate?.id],
  ([isOpen]) => {
    if (isOpen) {
      password.value = ''
      showPassword.value = false
    }
  },
)
</script>

<template>
  <AppModal
    :open="open"
    title="Download PKCS12"
    :close-on-backdrop="false"
    @close="emit('close')"
  >
    <p class="text-sm">
      Export <strong class="font-semibold">{{ certificate?.name }}</strong>
      and its private key as a single <span class="font-mono">.p12</span> bundle.
    </p>

    <p
      class="mt-3 rounded px-3 py-2 text-xs"
      :style="{ backgroundColor: 'var(--surface-warn)', color: 'var(--text-primary)' }"
    >
      <strong>Important:</strong> note the password down. It cannot be recovered;
      if you forget it you will have to export the bundle again.
    </p>

    <div class="mt-4">
      <label for="p12-password" class="mb-1 block text-sm font-medium">
        Export password <span :style="{ color: 'var(--text-secondary)' }">(optional)</span>
      </label>
      <div class="flex gap-2">
        <input
          id="p12-password"
          v-model="password"
          :type="showPassword ? 'text' : 'password'"
          autocomplete="new-password"
          placeholder="Leave empty for an unencrypted bundle"
          data-testid="p12-password"
          class="flex-1 rounded border px-3 py-2 text-sm"
          :style="{ backgroundColor: 'var(--surface-sunken)', borderColor: 'var(--border-subtle)', color: 'var(--text-primary)' }"
        />
        <button
          type="button"
          class="rounded border px-3 py-2 text-xs transition"
          :style="{ borderColor: 'var(--border-strong)', color: 'var(--text-primary)' }"
          @click="showPassword = !showPassword"
        >
          {{ showPassword ? 'Hide' : 'Show' }}
        </button>
      </div>
      <p v-if="!password" class="mt-1 text-xs" :style="{ color: 'var(--text-secondary)' }">
        With no password the bundle is written unencrypted.
      </p>
    </div>

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
        :style="{ backgroundColor: 'var(--color-brand-700)' }"
        :disabled="busy"
        data-testid="p12-export"
        @click="emit('export', password)"
      >
        {{ busy ? 'Preparing...' : 'Download' }}
      </button>
    </template>
  </AppModal>
</template>
