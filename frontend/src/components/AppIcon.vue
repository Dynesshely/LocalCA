<script setup>
/**
 * Inline icon set, drawn as strokes so an icon inherits `currentColor` and the
 * size of its context.
 *
 * Inline rather than an icon font or a sprite file, for the same reasons as
 * BrandMark: no extra request, no build step, and the colour comes from the
 * utility classes on the surrounding element. Decorative by default — the label
 * beside an icon is what assistive technology should read, so pass `title` only
 * for an icon that stands alone.
 */
const props = defineProps({
  name: { type: String, required: true },
  title: { type: String, default: '' },
})

// Every path is drawn in a 24x24 box, so one viewBox fits them all.
const PATHS = {
  home: ['M3 10.5 12 3.75l9 6.75', 'M5.25 9.75V20.25h13.5V9.75', 'M9.75 20.25v-5.25h4.5v5.25'],
  certificate: [
    'M6 3.75h12v16.5H6z',
    'M9.75 8.25h4.5',
    'M9.75 12h4.5',
    'M12 15.75v3',
    'M10.5 17.25h3',
  ],
  upload: ['M12 15.75V4.5', 'M7.5 9 12 4.5 16.5 9', 'M4.5 15v3.75a1.5 1.5 0 0 0 1.5 1.5h12a1.5 1.5 0 0 0 1.5-1.5V15'],
  list: ['M8.25 6.75h12', 'M8.25 12h12', 'M8.25 17.25h12', 'M3.75 6.75h.008', 'M3.75 12h.008', 'M3.75 17.25h.008'],
  menu: ['M3.75 6.75h16.5', 'M3.75 12h16.5', 'M3.75 17.25h16.5'],
  close: ['M6 6l12 12', 'M18 6 6 18'],
  logout: ['M15.75 9V5.25a1.5 1.5 0 0 0-1.5-1.5H6.75a1.5 1.5 0 0 0-1.5 1.5v13.5a1.5 1.5 0 0 0 1.5 1.5h7.5a1.5 1.5 0 0 0 1.5-1.5V15', 'M18.75 12H9.75', 'M15.75 9l3 3-3 3'],
  user: ['M15.75 8.25a3.75 3.75 0 1 1-7.5 0 3.75 3.75 0 0 1 7.5 0Z', 'M4.5 20.25a7.5 7.5 0 0 1 15 0'],
  key: ['M15 9.75a3 3 0 1 1-2.6-2.98', 'M13.5 12 4.5 21', 'M7.5 18l1.5 1.5', 'M10.5 15l1.5 1.5'],
  sun: [
    'M12 4.5v-1.5',
    'M12 21v-1.5',
    'M4.5 12H3',
    'M21 12h-1.5',
    'M6.7 6.7 5.6 5.6',
    'M18.4 18.4l-1.1-1.1',
    'M6.7 17.3l-1.1 1.1',
    'M18.4 5.6l-1.1 1.1',
    'M15.75 12a3.75 3.75 0 1 1-7.5 0 3.75 3.75 0 0 1 7.5 0Z',
  ],
  moon: ['M20.25 14.25A8.25 8.25 0 0 1 9.75 3.75a8.25 8.25 0 1 0 10.5 10.5Z'],
  globe: [
    'M12 3.75a8.25 8.25 0 1 0 0 16.5 8.25 8.25 0 0 0 0-16.5Z',
    'M3.75 12h16.5',
    'M12 3.75c2.1 2.2 3.15 5 3.15 8.25S14.1 18.05 12 20.25c-2.1-2.2-3.15-5-3.15-8.25S9.9 5.95 12 3.75Z',
  ],
  check: ['M4.5 12.75l4.5 4.5 10.5-10.5'],
  chevronDown: ['M6 9.75 12 15.75 18 9.75'],
  download: ['M12 3.75v11.5', 'M7.5 10.5 12 15l4.5-4.5', 'M4.5 19.5h15'],
  alert: ['M12 9v4.5', 'M12 16.5h.008', 'M10.3 3.9 2.9 17a1.5 1.5 0 0 0 1.3 2.25h15.6A1.5 1.5 0 0 0 21.1 17L13.7 3.9a1.5 1.5 0 0 0-2.6 0Z'],
}

const d = () => PATHS[props.name] || []
</script>

<template>
  <svg
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    stroke-width="1.5"
    stroke-linecap="round"
    stroke-linejoin="round"
    class="size-5 flex-none"
    :aria-hidden="title ? undefined : 'true'"
    :role="title ? 'img' : undefined"
    :aria-label="title || undefined"
  >
    <title v-if="title">{{ title }}</title>
    <path v-for="(p, i) in d()" :key="i" :d="p" />
  </svg>
</template>
