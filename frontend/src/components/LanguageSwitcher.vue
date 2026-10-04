<script setup>
/**
 * Language switch, drawn by the application rather than by the platform.
 *
 * A native `<select>` would be the accessible default, but its popup is painted
 * by the operating system: it ignores the app's theme (the dark interface got a
 * light list, and the option colours that were set on `<option>` are advisory
 * only), it cannot carry a border radius or a transition, and it sits outside
 * the design language the rest of the chrome follows. So the list is drawn here,
 * with the same border/radius/colour vocabulary as every other control.
 *
 * The keyboard and ARIA behaviour a combo box needs is implemented explicitly,
 * after the "select-only combobox" pattern: focus never leaves the button, which
 * carries `role="combobox"`, `aria-expanded` and `aria-activedescendant`, while
 * the popup is a `role="listbox"` whose highlighted option is the active
 * descendant. Keeping focus on the button also keeps the focus ring on it,
 * instead of putting a browser-painted ring around the popup.
 *
 * The globe stays in front of the current language because a bare two-letter
 * word does not say "this changes the language", and each option carries `lang`
 * so it is rendered in its own script -- the only label a reader who cannot read
 * the current interface can act on.
 */
import { computed, nextTick, onBeforeUnmount, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { SUPPORTED_LOCALES, setLocale } from '@/i18n'
import { useToastStore } from '@/stores/toasts'
import AppIcon from '@/components/AppIcon.vue'

const { t, locale } = useI18n()
const toasts = useToastStore()

const open = ref(false)
const root = ref(null)
const menu = ref(null)
/** The option the keyboard is on, which is not necessarily the active one. */
const active = ref(0)
/** Viewport coordinates for the teleported list. */
const position = ref({ top: 0, left: 0 })
const MENU_WIDTH = 176

const currentIndex = computed(() =>
  Math.max(0, SUPPORTED_LOCALES.findIndex((option) => option.code === locale.value)))
const current = computed(() => SUPPORTED_LOCALES[currentIndex.value] || SUPPORTED_LOCALES[0])

function choose(option) {
  close()
  // The clicked option is about to be unmounted, which would drop focus onto
  // <body>; hand it back to the button that owns the list.
  root.value?.querySelector('button')?.focus()
  if (option.code === locale.value) {
    return
  }
  setLocale(option.code)
  toasts.info(t('common.language.switched', { language: option.label }))
}

/**
 * Open the list above everything.
 *
 * Teleported to <body> and positioned from the button's viewport rectangle: the
 * top bar is a flex row inside the shell, and a popup placed inside it would be
 * clipped by the shell's `overflow-hidden` and scrolled away with the header.
 */
async function openMenu(index = currentIndex.value) {
  open.value = true
  active.value = index
  await nextTick()
  place()
}

function place() {
  const rect = root.value?.getBoundingClientRect()
  if (!rect) {
    return
  }
  const height = menu.value?.offsetHeight || 0
  const below = rect.bottom + 6
  // Flips above the button when the list would run off the bottom of the
  // window, and stays inside the viewport on both edges.
  const top = (height && below + height > window.innerHeight && rect.top > height)
    ? rect.top - height - 6
    : below
  position.value = {
    top: Math.max(4, top),
    left: Math.max(4, Math.min(rect.right - MENU_WIDTH, window.innerWidth - MENU_WIDTH - 4)),
  }
}

function close() {
  open.value = false
}

function onButtonKeydown(event) {
  const last = SUPPORTED_LOCALES.length - 1
  if (event.key === 'Enter' || event.key === ' ') {
    // The button would otherwise turn its own keypress into a click and close
    // the list the user is trying to pick from.
    if (open.value) {
      event.preventDefault()
      choose(SUPPORTED_LOCALES[active.value])
    }
  } else if (event.key === 'Escape') {
    close()
  } else if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
    event.preventDefault()
    if (!open.value) {
      openMenu(event.key === 'ArrowDown' ? 0 : last)
      return
    }
    const step = event.key === 'ArrowDown' ? 1 : -1
    active.value = Math.min(last, Math.max(0, active.value + step))
  } else if (event.key === 'Home' && open.value) {
    active.value = 0
  } else if (event.key === 'End' && open.value) {
    active.value = last
  } else if (event.key === 'Tab') {
    close()
  }
}

function onButtonClick() {
  if (open.value) {
    close()
  } else {
    openMenu()
  }
}

function onDocumentClick(event) {
  if (!open.value) {
    return
  }
  if (root.value?.contains(event.target) || menu.value?.contains(event.target)) {
    return
  }
  close()
}

/** A fixed-position list cannot follow the page, so it gives up instead. */
function onViewportChange() {
  close()
}

onMounted(() => {
  document.addEventListener('click', onDocumentClick)
  window.addEventListener('scroll', onViewportChange, true)
  window.addEventListener('resize', onViewportChange)
})
onBeforeUnmount(() => {
  document.removeEventListener('click', onDocumentClick)
  window.removeEventListener('scroll', onViewportChange, true)
  window.removeEventListener('resize', onViewportChange)
})
</script>

<template>
  <div ref="root" class="relative">
    <button
      type="button"
      class="flex items-center gap-2 rounded-lg border border-slate-200 bg-white py-1.5 pr-2 pl-2.5 text-sm font-medium text-slate-600 transition hover:bg-slate-100 hover:text-slate-900 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700 dark:hover:text-white"
      aria-haspopup="listbox"
      role="combobox"
      :aria-expanded="open"
      :aria-controls="open ? 'language-listbox' : undefined"
      :aria-activedescendant="open ? `language-option-${SUPPORTED_LOCALES[active]?.code}` : undefined"
      :aria-label="t('common.language.label')"
      :title="t('common.language.label')"
      data-testid="language-switcher"
      @click="onButtonClick"
      @keydown="onButtonKeydown"
    >
      <AppIcon name="globe" class="size-4 text-slate-400 dark:text-slate-500" />
      <span :lang="current.htmlLang" class="whitespace-nowrap">{{ current.label }}</span>
      <AppIcon
        name="chevronDown"
        class="size-3.5 text-slate-400 transition-transform duration-150 dark:text-slate-500"
        :class="open ? 'rotate-180' : ''"
      />
    </button>

    <Teleport to="body">
      <div
        v-if="open"
        id="language-listbox"
        ref="menu"
        class="fixed z-50 rounded-lg border border-slate-200 bg-white p-1 shadow-lg dark:border-slate-700 dark:bg-slate-800"
        :style="{ top: `${position.top}px`, left: `${position.left}px`, width: `${MENU_WIDTH}px` }"
        role="listbox"
        :aria-label="t('common.language.label')"
      >
        <button
          v-for="(option, index) in SUPPORTED_LOCALES"
          :id="`language-option-${option.code}`"
          :key="option.code"
          type="button"
          role="option"
          :aria-selected="option.code === locale"
          :lang="option.htmlLang"
          class="flex w-full items-center gap-2 rounded-md px-2.5 py-2 text-left text-sm transition"
          :class="index === active
            ? 'bg-brand-50 text-brand-800 dark:bg-brand-600 dark:text-white'
            : 'text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-slate-700'"
          :data-testid="`language-option-${option.code}`"
          @click="choose(option)"
          @mouseenter="active = index"
        >
          <span class="flex-1 whitespace-nowrap">{{ option.label }}</span>
          <AppIcon
            v-if="option.code === locale"
            name="check"
            class="size-4 text-brand-600 dark:text-brand-200"
          />
        </button>
      </div>
    </Teleport>
  </div>
</template>
