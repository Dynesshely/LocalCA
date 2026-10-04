<script setup>
/**
 * Accessible modal dialog.
 *
 * Closes on Escape and on backdrop click, traps focus while open, and restores
 * focus to the previously active element on close.
 */
import { onBeforeUnmount, onMounted, ref, watch, nextTick } from 'vue'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const props = defineProps({
  open: { type: Boolean, default: false },
  title: { type: String, default: '' },
  /** 'neutral' | 'warning' | 'danger' - tints the header bar. */
  tone: { type: String, default: 'neutral' },
  /** Set false to require an explicit action (used by destructive dialogs). */
  closeOnBackdrop: { type: Boolean, default: true },
  /**
   * 'base' for a dialog the operator opened; 'top' for one the application
   * raises *on top of* another -- the vault unlock, which answers a refusal
   * from whatever asked for a private key.
   *
   * Stated explicitly because every modal is teleported into <body> as a
   * sibling, so without it the order is whatever happened to mount first.
   */
  layer: { type: String, default: 'base' },
})

/** Both layers in one place, so a new dialog cannot invent its own. */
const layerClasses = { base: 'z-50', top: 'z-[60]' }

const emit = defineEmits(['close'])

const panel = ref(null)
let lastFocused = null

const toneClasses = {
  neutral: 'bg-brand-800 text-white',
  warning: 'bg-amber-100 text-amber-900 dark:bg-amber-900/60 dark:text-amber-50',
  danger: 'bg-red-600 text-white',
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
      class="fixed inset-0 flex items-start justify-center overflow-y-auto bg-black/50 p-4 sm:items-center"
      :class="layerClasses[layer] || layerClasses.base"
      role="presentation"
      @click.self="closeOnBackdrop && emit('close')"
    >
      <div
        ref="panel"
        class="w-full max-w-lg overflow-hidden rounded-xl border border-slate-200 bg-white shadow-xl dark:border-slate-800 dark:bg-slate-900"
        role="dialog"
        aria-modal="true"
        :aria-label="title"
      >
        <div
          class="flex items-start justify-between gap-4 px-5 py-3.5"
          :class="toneClasses[tone] || toneClasses.neutral"
        >
          <h2 class="text-base font-semibold">{{ title }}</h2>
          <button
            type="button"
            data-modal-dismiss
            class="shrink-0 rounded text-lg leading-none opacity-70 transition hover:opacity-100"
            :aria-label="t('dialog.close')"
            @click="emit('close')"
          >
            &times;
          </button>
        </div>

        <div class="px-5 py-5">
          <slot />
        </div>

        <div
          v-if="$slots.footer"
          class="flex flex-wrap justify-end gap-2 border-t border-slate-200 px-5 py-3 dark:border-slate-800"
        >
          <slot name="footer" />
        </div>
      </div>
    </div>
  </Teleport>
</template>
