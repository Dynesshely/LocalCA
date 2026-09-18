import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { session as sessionApi, meta as metaApi } from '@/api'

/**
 * Session state: who is signed in, and the static metadata the forms need
 * (revocation reasons, validity bounds).
 */
export const useAuthStore = defineStore('auth', () => {
  const user = ref(null)
  const loading = ref(false)
  const ready = ref(false)
  const revocationReasons = ref([])
  const maxValidityDays = ref({ root: 7300, intermediate: 7300, leaf: 825 })

  const isAuthenticated = computed(() => !!user.value)
  const isStaff = computed(() => !!user.value?.is_staff)

  /** Load the current session. Safe to call on every app start. */
  async function load() {
    loading.value = true
    try {
      const payload = await sessionApi.get()
      user.value = payload.user || null
    } catch (err) {
      user.value = null
    } finally {
      loading.value = false
      ready.value = true
    }
  }

  async function loadMeta() {
    try {
      const payload = await metaApi.get()
      revocationReasons.value = payload.revocation_reasons || []
      if (payload.max_validity_days) {
        maxValidityDays.value = payload.max_validity_days
      }
    } catch (err) {
      // Metadata is a nicety; the forms fall back to their own defaults.
    }
  }

  async function login(username, password) {
    const payload = await sessionApi.login(username, password)
    user.value = payload.user
    return payload.user
  }

  async function logout() {
    try {
      await sessionApi.logout()
    } finally {
      user.value = null
    }
  }

  /**
   * Change the password. Django rotates the session hash on save and the API
   * re-issues the session, so the current session stays valid.
   */
  async function changePassword(form) {
    return sessionApi.changePassword(form)
  }

  return {
    user, loading, ready, revocationReasons, maxValidityDays,
    isAuthenticated, isStaff,
    load, loadMeta, login, logout, changePassword,
  }
})
