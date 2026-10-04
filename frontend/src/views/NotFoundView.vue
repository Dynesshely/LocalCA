<script setup>
/**
 * Catch-all page. The route carries no `titleKey`, so the shell's top bar has
 * no heading here: the card's own title bar carries it instead.
 */
import { useI18n } from 'vue-i18n'
import { useRoute } from 'vue-router'

const { t } = useI18n()
const route = useRoute()
</script>

<template>
  <div class="mx-auto flex min-h-full w-full max-w-[1400px] items-center justify-center py-10">
    <div
      class="w-full max-w-lg overflow-hidden rounded-xl border border-slate-200 bg-white text-center shadow-sm dark:border-slate-800 dark:bg-slate-900"
    >
      <h2 class="bg-brand-500 px-5 py-3.5 text-base font-semibold text-white">
        {{ t('auth.notFound.title') }}
      </h2>

      <div class="px-5 py-6">
        <i18n-t keypath="auth.notFound.body" tag="p" class="text-sm text-slate-600 dark:text-slate-300">
          <template #path>
            <span class="font-mono break-all">{{ route.fullPath }}</span>
          </template>
        </i18n-t>

        <RouterLink
          :to="{ name: 'home' }"
          class="mt-6 inline-block rounded-lg bg-moss-600 px-4 py-2.5 text-sm font-medium text-white shadow-sm transition hover:bg-moss-500"
        >
          {{ t('auth.notFound.back') }}
        </RouterLink>
      </div>
    </div>
  </div>
</template>
