import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import { tokens as tokensApi } from '@/api'
import { ApiError } from '@/api/client'

// Personal access tokens: the server-side credentials external clients use
// instead of a browser session.
//
// The plaintext value never enters this store: it only exists in the response
// to create, and the page holds it just long enough to show it once.
export const useTokensStore = defineStore('tokens', () => {
  const items = ref([])
  const loading = ref(false)
  const error = ref('')

  const isEmpty = computed(() => items.value.length === 0)

  async function load() {
    loading.value = true
    error.value = ''
    try {
      const payload = await tokensApi.get()
      items.value = payload.tokens || []
    } catch (err) {
      error.value = err instanceof ApiError ? err.message : String(err)
      items.value = []
    } finally {
      loading.value = false
    }
  }

  /** Run an action, then reload so the list never disagrees with the server. */
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

  const create = (name) => run(() => tokensApi.create(name))
  const revoke = (id) => run(() => tokensApi.revoke(id))

  return { items, loading, error, isEmpty, load, create, revoke }
})
