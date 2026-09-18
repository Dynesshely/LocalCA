import { defineStore } from 'pinia'
import { ref } from 'vue'

/**
 * Transient user feedback (replacing Django's messages framework).
 *
 * Messages are rendered by AppShell and auto-dismiss.
 */
export const useToastStore = defineStore('toasts', () => {
  const items = ref([])
  let nextId = 1

  function push(message, type = 'info', timeout = 6000) {
    const id = nextId++
    items.value.push({ id, message, type })
    if (timeout > 0) {
      setTimeout(() => dismiss(id), timeout)
    }
    return id
  }

  function dismiss(id) {
    items.value = items.value.filter((t) => t.id !== id)
  }

  const success = (message) => push(message, 'success')
  const error = (message) => push(message, 'error', 9000)
  const warning = (message) => push(message, 'warning')
  const info = (message) => push(message, 'info')

  return { items, push, dismiss, success, error, warning, info }
})
