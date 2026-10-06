import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import { keystore as keystoreApi } from '@/api'
import { ApiError } from '@/api/client'

/**
 * Keystore state: the account's credentials, and the keys they wrap.
 *
 * A *credential* is a name plus a password wrapping one root key. An account can
 * hold several, each is opened on its own with its own password, and every stored
 * private key names the one that wraps it -- so this store is a list, not a
 * single boolean, and every operation is about one credential.
 *
 * Passwords are never stored here. The server keeps each opened root key in its
 * own memory for an idle timeout, so "unlocked" is a server-side fact this store
 * mirrors; reloading the page re-reads it rather than restoring anything.
 */
export const useKeystoreStore = defineStore('keystore', () => {
  const credentials = ref([])
  const keys = ref([])
  const counts = ref({
    total: 0, unlocked: 0, locked: 0, plaintext: 0, orphaned: 0,
    unwrappable: 0, no_key: 0,
  })
  const loading = ref(false)
  const error = ref('')

  /**
   * A pending "open this credential so the action can continue" request.
   *
   * Any operation that needs a private key can hit a locked credential, and the
   * answer is always the same: ask for that credential's password, then do the
   * thing. Keeping the request here means one dialog in the shell serves every
   * caller, instead of each page carrying its own open/retry bookkeeping.
   *
   * `{ reason, credentialId, retry }` while waiting, `null` otherwise.
   */
  const unlockRequest = ref(null)

  function apply(payload) {
    credentials.value = payload.credentials || []
    keys.value = payload.keys || []
    counts.value = { ...counts.value, ...(payload.counts || {}) }
  }

  const defaultCredential = computed(
    () => credentials.value.find((entry) => entry.is_default) || credentials.value[0] || null)

  /** True when the account has no credential at all: nothing can be encrypted. */
  const isEmpty = computed(() => credentials.value.length === 0)

  /** True when at least one key is encrypted under a credential that is closed. */
  const hasLockedKeys = computed(() => counts.value.locked > 0)

  /** True when some keys are still cleartext: on this account, or ownerless. */
  const hasUnprotectedKeys = computed(
    () => counts.value.plaintext > 0 || counts.value.orphaned > 0)

  async function load() {
    loading.value = true
    error.value = ''
    try {
      apply(await keystoreApi.get())
    } catch (err) {
      error.value = err instanceof ApiError ? err.message : String(err)
    } finally {
      loading.value = false
    }
  }

  /** Wrap the call, refresh the inventory, and let the caller show the error. */
  async function run(action) {
    loading.value = true
    error.value = ''
    try {
      const result = await action()
      await load()
      return result
    } finally {
      loading.value = false
    }
  }

  const create = (name, password) => run(() => keystoreApi.create(name, password))
  const unlock = (id, password) => run(() => keystoreApi.unlock(id, password))
  const lock = (id) => run(() => keystoreApi.lock(id))
  const lockAll = () => run(() => keystoreApi.lockAll())
  const changePassword = (id, oldPassword, newPassword) =>
    run(() => keystoreApi.changePassword(id, oldPassword, newPassword))
  const rename = (id, name) => run(() => keystoreApi.rename(id, name))
  const setDefault = (id) => run(() => keystoreApi.setDefault(id))
  const remove = (id) => run(() => keystoreApi.remove(id))
  const assign = (id, kind, certId) => run(() => keystoreApi.assign(id, kind, certId))

  /**
   * Ask for a credential's password before retrying an operation.
   *
   * `credentialId` comes from the server's 409 (`credential_id`), which is the
   * only component that knows *which* credential the refused key belongs to. A
   * null id means the account has none yet, and the dialog offers to create one.
   */
  function requestUnlock({ reason, credentialId = null, retry = null } = {}) {
    unlockRequest.value = { reason, credentialId, retry }
  }

  function clearUnlock() {
    unlockRequest.value = null
  }

  /** The password was accepted (or a credential was created): run the retry. */
  async function resolveUnlock() {
    const request = unlockRequest.value
    unlockRequest.value = null
    await load()
    if (request?.retry) {
      await request.retry()
    }
  }

  return {
    credentials, keys, counts, loading, error, unlockRequest,
    defaultCredential, isEmpty, hasLockedKeys, hasUnprotectedKeys,
    load, create, unlock, lock, lockAll, changePassword, rename, setDefault,
    remove, assign, requestUnlock, resolveUnlock, clearUnlock,
  }
})
