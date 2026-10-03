import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { vault as vaultApi } from '@/api'
import { ApiError } from '@/api/client'

/**
 * Vault state: whether this account's private keys are encrypted, and whether
 * they are currently usable.
 *
 * The password is never stored here. The server keeps the unsealed key in its
 * own memory for an idle timeout, so "unsealed" is a server-side fact that this
 * store mirrors; reloading the page re-reads it rather than restoring anything.
 */
export const useVaultStore = defineStore('vault', () => {
  const status = ref({
    has_root_key: false,
    unsealed: false,
    unseal_remaining_seconds: 0,
    wrapped: 0,
    plaintext: 0,
    orphaned: 0,
    by_kind: {},
  })
  const loading = ref(false)
  const error = ref('')

  /** True when encrypted keys exist but the vault is closed. */
  const needsUnlock = computed(
    () => status.value.wrapped > 0 && !status.value.unsealed)

  /** True when some keys are still cleartext and therefore not protected. */
  const hasUnprotectedKeys = computed(
    () => status.value.plaintext > 0 || status.value.orphaned > 0)

  /** Only relevant before the first unlock, when no password exists yet. */
  const needsPasswordSetup = computed(() => !status.value.has_root_key)

  function apply(payload) {
    status.value = { ...status.value, ...payload }
  }

  async function load() {
    loading.value = true
    error.value = ''
    try {
      apply(await vaultApi.status())
    } catch (err) {
      error.value = err instanceof ApiError ? err.message : String(err)
    } finally {
      loading.value = false
    }
  }

  async function unseal(password) {
    loading.value = true
    error.value = ''
    try {
      apply(await vaultApi.unseal(password))
      return true
    } catch (err) {
      error.value = err instanceof ApiError ? err.message : String(err)
      throw err
    } finally {
      loading.value = false
    }
  }

  async function lock() {
    apply(await vaultApi.lock())
  }

  async function rotate(oldPassword, newPassword) {
    await vaultApi.rotate(oldPassword, newPassword)
    await load()
  }

  return {
    status, loading, error,
    needsUnlock, hasUnprotectedKeys, needsPasswordSetup,
    load, unseal, lock, rotate,
  }
})
