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

  /**
   * A pending "unlock so this can continue" request.
   *
   * Any operation that needs a private key can hit a locked vault, and the answer
   * is always the same: ask for the password, then do the thing. Keeping the
   * request here means one dialog in the shell serves every caller, instead of
   * each page carrying its own copy of the open/retry bookkeeping.
   *
   * `{ reason, retry }` while waiting, `null` otherwise.
   */
  const unlockRequest = ref(null)

  function requestUnlock(reason, retry) {
    unlockRequest.value = { reason, retry: retry || null }
  }

  /** The password was accepted: run the operation that was refused. */
  async function resolveUnlock() {
    const request = unlockRequest.value
    unlockRequest.value = null
    await load()
    if (request?.retry) {
      await request.retry()
    }
  }

  function clearUnlock() {
    unlockRequest.value = null
  }

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
    status, loading, error, unlockRequest,
    needsUnlock, hasUnprotectedKeys, needsPasswordSetup,
    load, unseal, lock, rotate,
    requestUnlock, resolveUnlock, clearUnlock,
  }
})
