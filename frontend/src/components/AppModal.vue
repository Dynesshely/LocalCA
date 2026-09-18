<script setup>
/**
 * Accessible modal dialog.
 *
 * Closes on Escape and on backdrop click, traps focus while open, and restores
 * focus to the previously active element on close.
 */
import { onBeforeUnmount, onMounted, ref, watch, nextTick } from 'vue'

const props = defineProps({
  open: { type: Boolean, default: false },
  title: { type: String, default: '' },
  /** 'neutral' | 'warning' | 'danger' - tints the header bar. */
  tone: { type: String, default: 'neutral' },
  /** Set false to require an explicit action (used by destructive dialogs). */
  closeOnBackdrop: { type: Boolean, default: true },
})

const emit = defineEmits(['close'])

const panel = ref(null)
let lastFocused = null

const toneClasses = {
  neutral: 'bg-brand-800 text-white',
  warning: 'bg-amber-100 text-amber-900 dark:bg-amber-900/60 dark:text-amber-50',
  danger: 'bg-danger text-white',
}

function onKeydown(event) {
  if (event.key === 'Escape') {
    emit('close')
    return
  }
  // Focus trap: keep Tab cycling inside the dialog.
  if (event.key === 'Tab' && panel.value) {
    const focusable = panel.value.querySelectorAll(
      'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
    )
    if (!focusable.length) return
    const first = focusable[0]
    const last = focusable[focusable.length - 1]
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault()
      last.focus()
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault()
      first.focus()
    }
  }
}

watch(
  () => props.open,
  async (isOpen) => {
    if (isOpen) {
      lastFocused = document.activeElement
      await nextTick()
      const target = panel.value?.querySelector(
        'input, select, textarea, button:not([data-modal-dismiss])',
      )
      target?.focus()
    } else if (lastFocused instanceof HTMLElement) {
      lastFocused.focus()
    }
  },
)

onMounted(() => document.addEventListener('keydown', onKeydown))
onBeforeUnmount(() => document.removeEventListener('keydown', onKeydown))
</script>

<template>
  <Teleport to="body">
    <div
      v-if="open"
      class="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/50 p-4 sm:items-center"
      role="presentation"
      @click.self="closeOnBackdrop && emit('close')"
    >
      <div
        ref="panel"
        class="w-full max-w-lg rounded-lg shadow-xl"
        role="dialog"
        aria-modal="true"
        :aria-label="title"
        :style="{ backgroundColor: 'var(--surface-card)', borderColor: 'var(--border-subtle)' }"
        style="border-width: 1px"
      >
        <div
          class="flex items-start justify-between gap-4 rounded-t-lg px-4 py-3"
          :class="toneClasses[tone] || toneClasses.neutral"
        >
          <h2 class="text-base font-semibold">{{ title }}</h2>
          <button
            type="button"
            data-modal-dismiss
            class="shrink-0 rounded text-lg leading-none opacity-70 transition hover:opacity-100"
            aria-label="Close dialog"
            @click="emit('close')"
          >
            &times;
          </button>
        </div>

        <div class="px-4 py-4">
          <slot />
        </div>

        <div
          v-if="$slots.footer"
          class="flex flex-wrap justify-end gap-2 rounded-b-lg border-t px-4 py-3"
          :style="{ borderColor: 'var(--border-subtle)' }"
        >
          <slot name="footer" />
        </div>
      </div>
    </div>
  </Teleport>
</template>
