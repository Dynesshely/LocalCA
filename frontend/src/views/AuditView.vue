<script setup>
/**
 * Audit log. Staff only: it reveals other users' activity.
 *
 * The `details` column is prose the server wrote into the database when the
 * action happened, so it is shown exactly as stored; only the action code,
 * which this interface authors, becomes a translated label.
 */
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { audit } from '@/api'
import { useToastStore } from '@/stores/toasts'

const { t, d } = useI18n()
const toasts = useToastStore()
const entries = ref([])
const loading = ref(true)
const limit = ref(100)

/** Badge recipes, one per action family. */
const ACTION_META = {
  CREATE: {
    labelKey: 'audit.action.create',
    tone: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200',
  },
  REVOKE: {
    labelKey: 'audit.action.revoke',
    tone: 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-200',
  },
  DELETE: {
    labelKey: 'audit.action.delete',
    tone: 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-200',
  },
  DOWNLOAD_PUBLIC_KEY: {
    labelKey: 'audit.action.downloadPublicKey',
    tone: 'bg-sky-100 text-sky-800 dark:bg-sky-900/40 dark:text-sky-200',
  },
  DOWNLOAD_PRIVATE_KEY: {
    labelKey: 'audit.action.downloadPrivateKey',
    tone: 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-200',
  },
  DOWNLOAD_PKCS12: {
    labelKey: 'audit.action.downloadPkcs12',
    tone: 'bg-brand-100 text-brand-800 dark:bg-brand-900/40 dark:text-brand-200',
  },
  ACCESS: {
    labelKey: 'audit.action.access',
    tone: 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300',
  },
}

const NEUTRAL_BADGE = 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300'

/** A timestamp is only useful with its time, so the day alone will not do. */
const TIMESTAMP_FORMAT = {
  year: 'numeric',
  month: 'short',
  day: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
}

const actionTone = (action) => ACTION_META[action]?.tone || NEUTRAL_BADGE

/** An action code this interface knows becomes a label; anything else stays as-is. */
function actionLabel(action) {
  const key = ACTION_META[action]?.labelKey
  return key ? t(key) : action
}

const formatTimestamp = (value) => d(new Date(value), TIMESTAMP_FORMAT)

async function load() {
  loading.value = true
  try {
    const payload = await audit.list(limit.value)
    entries.value = payload.entries || []
  } catch (err) {
    toasts.error(t('audit.loadFailed', { message: err.message }))
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<template>
  <div class="mx-auto w-full max-w-[1400px]">
    <div class="mb-4 flex flex-wrap items-end justify-between gap-3">
      <p class="text-sm text-slate-500 dark:text-slate-400">
        {{ t('audit.summary', { count: entries.length }) }}
      </p>
      <div class="flex items-center gap-2">
        <label for="audit-limit" class="text-sm text-slate-600 dark:text-slate-300">
          {{ t('audit.show') }}
        </label>
        <select
          id="audit-limit"
          v-model.number="limit"
          class="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 shadow-sm transition focus:border-brand-500 focus:ring-2 focus:ring-brand-500/25 focus:outline-none dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
          @change="load"
        >
          <option :value="50">50</option>
          <option :value="100">100</option>
          <option :value="250">250</option>
          <option :value="500">500</option>
        </select>
        <button
          type="button"
          class="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-medium text-slate-700 transition hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700"
          @click="load"
        >
          {{ t('common.action.refresh') }}
        </button>
      </div>
    </div>

    <div
      v-if="loading"
      class="py-8 text-center text-sm text-slate-500 dark:text-slate-400"
    >
      {{ t('common.state.loading') }}
    </div>
    <div
      v-else-if="!entries.length"
      class="rounded-xl border border-slate-200 px-4 py-8 text-center text-sm text-slate-500 dark:border-slate-800 dark:text-slate-400"
    >
      {{ t('audit.empty') }}
    </div>
    <div
      v-else
      class="overflow-x-auto rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900"
    >
      <table class="w-full text-left text-sm">
        <thead class="sticky top-0 bg-slate-50 text-slate-600 dark:bg-slate-950/70 dark:text-slate-300">
          <tr>
            <th class="px-3 py-2 font-medium">{{ t('audit.column.when') }}</th>
            <th class="px-3 py-2 font-medium">{{ t('audit.column.action') }}</th>
            <th class="px-3 py-2 font-medium">{{ t('audit.column.by') }}</th>
            <th class="px-3 py-2 font-medium">{{ t('audit.column.details') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="entry in entries"
            :key="entry.id"
            class="border-t border-slate-200 dark:border-slate-800"
          >
            <td class="whitespace-nowrap px-3 py-2 text-slate-600 dark:text-slate-300">
              {{ formatTimestamp(entry.timestamp) }}
            </td>
            <td class="px-3 py-2">
              <span
                class="inline-block whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-medium"
                :class="actionTone(entry.action)"
              >
                {{ actionLabel(entry.action) }}
              </span>
            </td>
            <td class="px-3 py-2 text-slate-600 dark:text-slate-300">
              {{ entry.performed_by || t('audit.anonymous') }}
            </td>
            <td class="px-3 py-2 text-slate-600 dark:text-slate-300">{{ entry.details }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
