<script setup>
/**
 * The download menu: every format the server offers, for one certificate.
 *
 * The list comes from `/api/meta/`, so the menu cannot offer a format the
 * server does not serve. Formats are grouped by what they give away — the
 * certificate, or the private key — because that is the distinction an operator
 * actually cares about, and the second group is where the warnings live.
 */
import { computed, nextTick, onBeforeUnmount, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import AppIcon from '@/components/AppIcon.vue'
import { useAuthStore } from '@/stores/auth'

const props = defineProps({
  certificate: { type: Object, required: true },
  /** False for a certificate imported without a key: it has nothing to give. */
  hasKey: { type: Boolean, default: true },
})

const emit = defineEmits(['choose'])

const { t } = useI18n()
const auth = useAuthStore()

const open = ref(false)
const root = ref(null)
const menu = ref(null)
/** Viewport coordinates for the teleported menu. */
const position = ref({ top: 0, left: 0 })
const MENU_WIDTH = 288

const PUBLIC_FORMATS = ['pem', 'der', 'chain', 'p7b']
const PRIVATE_FORMATS = ['pkcs12', 'key', 'key-plain', 'pair-zip']

/** Only the formats the server advertised, in the order this menu wants them. */
function pick(ids) {
  return ids
    .map((id) => auth.downloadFormats.find((spec) => spec.id === id))
    .filter(Boolean)
}

const groups = computed(() => [
  { key: 'certificate', ids: pick(PUBLIC_FORMATS) },
  { key: 'privateKey', ids: pick(PRIVATE_FORMATS) },
].filter((group) => group.ids.length))

/**
 * Whether this caller may export the private key at all.
 *
 * The owner always may. Staff may too when the key is legacy cleartext: that key
 * is not wrapped with anybody's vault password, so no vault is involved. A key
 * that *is* wrapped belongs to the account that owns it -- the server refuses
 * everyone else, administrator included, and there is nothing to offer here.
 */
const canExportKey = computed(() => props.certificate?.is_owner === true
  || (props.certificate?.unprotected_legacy === true
      && props.certificate?.can_manage === true))

/** A private format is only usable when there is a key and it can be opened. */
function privateDisabled(format) {
  return format.access === 'private' && (!props.hasKey || !canExportKey.value)
}

/**
 * Open the menu above everything.
 *
 * The menu is teleported to <body> and positioned from the button's viewport
 * rectangle, because every container it lives in clips: the certificate cards
 * are `overflow-hidden` (for their rounded header strip) and the tables scroll.
 * A menu inside them was cut off after its first row.
 */
async function toggle() {
  open.value = !open.value
  if (!open.value) {
    return
  }
  await nextTick()
  place()
}

function place() {
  const rect = root.value?.getBoundingClientRect()
  if (!rect) {
    return
  }
  // Right-aligned with the button, and flipped above it when there is no room
  // below -- a menu that runs off the bottom of the window is unusable.
  const height = menu.value?.offsetHeight || 0
  const below = rect.bottom + 4
  const top = (height && below + height > window.innerHeight && rect.top > height)
    ? rect.top - height - 4
    : below
  position.value = {
    top: Math.max(4, top),
    left: Math.max(4, Math.min(rect.right - MENU_WIDTH, window.innerWidth - MENU_WIDTH - 4)),
  }
}

function close() {
  open.value = false
}

function choose(format) {
  close()
  emit('choose', format.id)
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

function onKeydown(event) {
  if (event.key === 'Escape') {
    close()
  }
}

/** A fixed-position menu cannot follow the page, so it gives up instead. */
function onViewportChange() {
  close()
}

onMounted(() => {
  document.addEventListener('click', onDocumentClick)
  document.addEventListener('keydown', onKeydown)
  window.addEventListener('scroll', onViewportChange, true)
  window.addEventListener('resize', onViewportChange)
})
onBeforeUnmount(() => {
  document.removeEventListener('click', onDocumentClick)
  document.removeEventListener('keydown', onKeydown)
  window.removeEventListener('scroll', onViewportChange, true)
  window.removeEventListener('resize', onViewportChange)
})
</script>

<template>
  <div ref="root" class="relative">
    <button
      type="button"
      class="flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-2.5 py-1 text-xs font-medium text-slate-700 transition hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700"
      aria-haspopup="menu"
      :aria-expanded="open"
      :data-testid="`download-menu-${certificate.id}`"
      @click="toggle"
    >
      <AppIcon name="download" class="size-3.5" />
      {{ t('home.download.label') }}
      <AppIcon name="chevronDown" class="size-3.5" />
    </button>

    <Teleport to="body">
      <div
        v-if="open"
        ref="menu"
        class="fixed z-50 overflow-hidden rounded-lg border border-slate-200 bg-white py-1 shadow-lg dark:border-slate-700 dark:bg-slate-800"
        :style="{ top: `${position.top}px`, left: `${position.left}px`, width: `${MENU_WIDTH}px` }"
        role="menu"
      >
      <template v-for="group in groups" :key="group.key">
        <p class="px-3 pt-2 pb-1 text-[11px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">
          {{ t(`home.download.group.${group.key}`) }}
        </p>
        <p
          v-if="group.key === 'privateKey' && !canExportKey"
          class="px-3 pb-1 text-xs text-slate-500 dark:text-slate-400"
          data-testid="download-not-yours"
        >
          {{ t('home.download.notYours') }}
        </p>
        <button
          v-for="format in group.ids"
          :key="format.id"
          type="button"
          role="menuitem"
          class="flex w-full items-start gap-2 px-3 py-1.5 text-left text-sm text-slate-700 transition hover:bg-slate-100 disabled:cursor-not-allowed disabled:opacity-50 dark:text-slate-200 dark:hover:bg-slate-700"
          :disabled="privateDisabled(format)"
          :data-testid="`download-${format.id}-${certificate.id}`"
          @click="choose(format)"
        >
          <span class="min-w-0 flex-1">
            <span class="block">{{ t(`home.download.format.${format.id}`) }}</span>
            <span class="block text-xs text-slate-500 dark:text-slate-400">
              {{ t(`home.download.hint.${format.id}`) }}
            </span>
          </span>
          <span
            v-if="format.access === 'private'"
            class="mt-0.5 flex-none rounded-full bg-amber-100 px-1.5 py-0.5 text-[10px] font-medium text-amber-800 dark:bg-amber-900/40 dark:text-amber-200"
          >
            {{ t('home.download.keyBadge') }}
          </span>
        </button>
        </template>
      </div>
    </Teleport>
  </div>
</template>
