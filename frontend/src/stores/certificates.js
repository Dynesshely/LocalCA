import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { certificates as certApi } from '@/api'
import { ApiError } from '@/api/client'

/** Certificate hierarchy plus the actions that mutate it. */
export const useCertificatesStore = defineStore('certificates', () => {
  const tree = ref([])
  const issuers = ref({ roots: [], intermediates: [] })
  const loading = ref(false)
  const error = ref(null)

  const isEmpty = computed(() => tree.value.length === 0)

  /** Flat list of every certificate, for lookups by kind and id. */
  const flat = computed(() => {
    const out = []
    for (const node of tree.value) {
      out.push(node.certificate)
      for (const branch of node.intermediates) {
        out.push(branch.certificate)
        out.push(...branch.leaves)
      }
    }
    return out
  })

  function find(kind, id) {
    return flat.value.find((c) => c.kind === kind && c.id === Number(id)) || null
  }

  async function load() {
    loading.value = true
    error.value = null
    try {
      const payload = await certApi.tree()
      tree.value = payload.tree || []
    } catch (err) {
      error.value = err instanceof ApiError ? err.message : String(err)
      tree.value = []
      throw err
    } finally {
      loading.value = false
    }
  }

  /** CAs the signed-in user may sign with (their own only). */
  async function loadIssuers() {
    const payload = await certApi.issuers()
    issuers.value = {
      roots: payload.roots || [],
      intermediates: payload.intermediates || [],
    }
    return issuers.value
  }

  async function create(kind, form) {
    const payload = await certApi.create(kind, form)
    await load()
    return payload.certificate
  }

  async function revoke(kind, id, options) {
    const payload = await certApi.revoke(kind, id, options)
    await load()
    return payload
  }

  async function remove(kind, id) {
    const payload = await certApi.remove(kind, id)
    await load()
    return payload
  }

  return {
    tree, issuers, loading, error, isEmpty, flat,
    find, load, loadIssuers, create, revoke, remove,
  }
})
