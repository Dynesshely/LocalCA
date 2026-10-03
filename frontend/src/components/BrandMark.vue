<script setup>
/**
 * The LocalCA mark: a trust shield holding the root / child hierarchy the
 * application is actually about.
 *
 * Inline rather than an image file so it inherits the brand tokens from
 * style.css (no second copy of the palette to keep in sync) and costs no extra
 * request. Decorative: the wordmark beside it already says "Local CA", so it is
 * hidden from assistive technology instead of being announced twice.
 */
defineProps({
  size: { type: Number, default: 32 },
})
</script>

<template>
  <svg
    :width="size"
    :height="size"
    viewBox="0 0 48 48"
    class="flex-none"
    aria-hidden="true"
    focusable="false"
  >
    <path
      d="M24 3 42 9.5v14c0 10.3-7.8 17.2-18 20.5C13.8 40.7 6 33.8 6 23.5v-14z"
      fill="var(--color-brand-50)"
    />
    <g
      stroke="var(--color-moss-600)"
      stroke-width="3"
      stroke-linecap="round"
      fill="none"
    >
      <path d="M24 15V22" />
      <path d="M15 22h18" />
      <path d="M15 22v5.5" />
      <path d="M33 22v5.5" />
    </g>
    <circle cx="24" cy="15" r="3.8" fill="var(--color-moss-600)" />
    <circle cx="15" cy="30.5" r="3.4" fill="var(--color-moss-600)" />
    <circle cx="33" cy="30.5" r="3.4" fill="var(--color-moss-600)" />
  </svg>
</template>
