<script setup>
/**
 * Import certificates from a bundle.
 *
 * Two steps, both against /api/import/: "Analyze" uploads the files and shows
 * what would happen (nothing is written), "Import" re-uploads the same files to
 * apply it. Nothing is staged on the server between the two, so the operator
 * always sees the exact plan that will be executed.
 *
 * Certificates carrying a private key need the vault to be open, exactly like
 * signing does, so a 409 opens the same unlock dialog the other pages use.
 */
import { computed, ref } from 'vue'
import { RouterLink } from 'vue-router'
import { useI18n } from 'vue-i18n'
import FormField from '@/components/FormField.vue'
import { imports as importApi, meta as metaApi } from '@/api'
import { ApiError } from '@/api/client'
import { useCertificatesStore } from '@/stores/certificates'
import { useKeystoreStore } from '@/stores/keystore'
import { useToastStore } from '@/stores/toasts'

const { t } = useI18n()
const certificates = useCertificatesStore()
const keystore = useKeystoreStore()
const toasts = useToastStore()

const files = ref([])
const password = ref('')
const busy = ref(false)
const plan = ref(null)
const result = ref(null)
const formats = ref({ supported: [], unsupported: [], limits: {} })

/**
 * The server decides how many files a bundle may contain; the drop hint quotes
 * those limits, so the numbers and the explanation can never drift apart.
 */
const maxFiles = computed(() => formats.value.limits?.max_files || 8)
const maxFileKib = computed(() => Math.round((formats.value.limits?.max_file_bytes || 1048576) / 1024))

/** Plan actions, mapped to a catalogue key so the label follows the language. */
const ACTION_LABEL_KEYS = {
  create: 'import.action.create',
  skip: 'import.action.skip',
  attach_key: 'import.action.attachKey',
  conflict: 'import.action.conflict',
  unsupported: 'import.action.unsupported',
}

/** Badge tint per action: a soft chip, so the plan's row states stay legible. */
const ACTION_TONES = {
  create: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200',
  attach_key: 'bg-sky-100 text-sky-800 dark:bg-sky-900/40 dark:text-sky-200',
  skip: 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300',
  conflict: 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-200',
  unsupported: 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-200',
}

function actionLabel(action) {
  const key = ACTION_LABEL_KEYS[action]
  return key ? t(key) : ''
}

const selectedNames = computed(() => files.value.map((f) => f.name))

/** Entries that will actually be written if the plan is committed. */
const writable = computed(() => {
  if (!plan.value) return []
  return plan.value.items.filter((i) => i.action === 'create' || i.action === 'attach_key')
})

const hasProblems = computed(() => plan.value
  ? plan.value.counts.conflict + plan.value.counts.unsupported > 0
  : false)

function isVaultLocked(err) {
  return err instanceof ApiError && err.status === 409 && err.payload?.vault_locked
}

function reportError(err) {
  if (err instanceof ApiError) {
    toasts.error(err.message)
  } else {
    toasts.error(String(err))
  }
}

function chooseFiles() {
  document.getElementById('import-files')?.click()
}

function onFiles(event) {
  files.value = Array.from(event.target.files || [])
  plan.value = null
  result.value = null
}

function onDrop(event) {
  files.value = Array.from(event.dataTransfer?.files || [])
  plan.value = null
  result.value = null
}

function clearAll() {
  files.value = []
  password.value = ''
  plan.value = null
  result.value = null
  const input = document.getElementById('import-files')
  if (input) input.value = ''
}

async function analyze() {
  busy.value = true
  result.value = null
  try {
    const payload = await importApi.analyze(files.value, { password: password.value })
    plan.value = payload.plan
    formats.value = payload.formats || formats.value
    const parsed = payload.plan.items.length
    toasts.info(t('import.toast.parsed', { count: parsed }, parsed))
  } catch (err) {
    plan.value = null
    reportError(err)
  } finally {
    busy.value = false
  }
}

async function commit() {
  busy.value = true
  try {
    const payload = await importApi.commit(files.value, { password: password.value })
    result.value = payload.result
    plan.value = payload.plan
    await certificates.load()
    await keystore.load()
    const created = payload.result.created
    toasts.success(t('import.toast.imported', {
      root: created.root,
      intermediate: created.intermediate,
      leaf: created.leaf,
      wrapped: payload.result.keys_wrapped,
    }))
    if (payload.result.failed?.length) {
      const failed = payload.result.failed.length
      toasts.error(t('import.toast.failed', { count: failed }, failed))
    }
  } catch (err) {
    if (isVaultLocked(err)) {
      // The shell owns the only credential dialog; it retries this exact call
      // once the credential the server named is open.
      keystore.requestUnlock({
        reason: err.message,
        credentialId: err.credentialId,
        retry: commit,
      })
    } else {
      reportError(err)
    }
  } finally {
    busy.value = false
  }
}

metaApi.get().then((payload) => {
  if (payload.import_formats) formats.value = payload.import_formats
}).catch(() => {})
</script>

<template>
  <div class="mx-auto w-full max-w-[1400px] space-y-6">
    <p class="text-sm text-slate-600 dark:text-slate-300">
      {{ t('import.intro') }}
    </p>

    <div class="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
      <!-- ------------------------------------------------------------------
           1. Choose the files
           ------------------------------------------------------------------ -->
      <section
        class="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900"
      >
        <h2 class="bg-moss-600 px-5 py-3.5 text-base font-semibold text-white">
          {{ t('import.step1.title') }}
        </h2>
        <div class="px-5 py-5">
          <div
            class="rounded-xl border border-dashed border-slate-300 bg-slate-50 p-5 text-center text-sm dark:border-slate-700 dark:bg-slate-950/40"
            data-testid="import-dropzone"
            @dragover.prevent
            @drop.prevent="onDrop"
          >
            <input
              id="import-files"
              type="file"
              multiple
              class="hidden"
              data-testid="import-input"
              @change="onFiles"
            >
            <button
              type="button"
              class="rounded-lg bg-moss-600 px-4 py-2.5 text-sm font-medium text-white shadow-sm transition hover:bg-moss-500 disabled:cursor-not-allowed disabled:opacity-60"
              data-testid="import-choose"
              @click="chooseFiles"
            >
              {{ t('import.step1.chooseFiles') }}
            </button>
            <p class="mt-2 text-xs text-slate-500 dark:text-slate-400">
              {{ t('import.step1.dropHint', { max: maxFiles, size: maxFileKib }, maxFiles) }}
            </p>
          </div>

          <ul v-if="selectedNames.length" class="mt-3 space-y-1 text-xs">
            <li v-for="name in selectedNames" :key="name" class="truncate font-mono text-slate-600 dark:text-slate-300">
              {{ name }}
            </li>
          </ul>

          <div class="mt-4">
            <FormField
              id="import-password"
              v-model="password"
              :label="t('import.step1.password.label')"
              type="password"
              :placeholder="t('import.step1.password.placeholder')"
              :help="t('import.step1.password.help')"
            />
          </div>

          <div class="mt-4 flex flex-wrap gap-2">
            <button
              type="button"
              class="rounded-lg bg-moss-600 px-4 py-2.5 text-sm font-medium text-white shadow-sm transition hover:bg-moss-500 disabled:cursor-not-allowed disabled:opacity-60"
              :disabled="!files.length || busy"
              data-testid="import-analyze"
              @click="analyze"
            >
              {{ t('common.action.analyze') }}
            </button>
            <button
              type="button"
              class="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-medium text-slate-700 transition hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700"
              :disabled="busy && !files.length"
              @click="clearAll"
            >
              {{ t('common.action.clear') }}
            </button>
          </div>
        </div>
      </section>

      <!-- ------------------------------------------------------------------
           2. The plan the server would apply
           ------------------------------------------------------------------ -->
      <section
        class="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900"
      >
        <h2 class="bg-brand-500 px-5 py-3.5 text-base font-semibold text-white">
          {{ t('import.step2.title') }}
        </h2>
        <div class="px-5 py-5">
          <p v-if="!plan" class="text-sm text-slate-500 dark:text-slate-400">
            {{ t('import.step2.empty') }}
          </p>

          <template v-else>
            <div class="mb-3 flex flex-wrap gap-2 text-xs">
              <span
                class="inline-block whitespace-nowrap rounded-full bg-emerald-100 px-2 py-0.5 text-xs font-medium text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200"
              >
                {{ t('import.count.create', { count: plan.counts.create }) }}
              </span>
              <span
                v-if="plan.counts.attach_key"
                class="inline-block whitespace-nowrap rounded-full bg-sky-100 px-2 py-0.5 text-xs font-medium text-sky-800 dark:bg-sky-900/40 dark:text-sky-200"
              >
                {{ t('import.count.attachKey', { count: plan.counts.attach_key }, plan.counts.attach_key) }}
              </span>
              <span
                v-if="plan.counts.skip"
                class="inline-block whitespace-nowrap rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-600 dark:bg-slate-800 dark:text-slate-300"
              >
                {{ t('import.count.skip', { count: plan.counts.skip }) }}
              </span>
              <span
                v-if="plan.counts.conflict"
                class="inline-block whitespace-nowrap rounded-full bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-800 dark:bg-amber-900/40 dark:text-amber-200"
              >
                {{ t('import.count.conflict', { count: plan.counts.conflict }, plan.counts.conflict) }}
              </span>
              <span
                v-if="plan.counts.unsupported"
                class="inline-block whitespace-nowrap rounded-full bg-red-100 px-2 py-0.5 text-xs font-medium text-red-800 dark:bg-red-900/40 dark:text-red-200"
              >
                {{ t('import.count.unsupported', { count: plan.counts.unsupported }) }}
              </span>
              <span
                v-if="plan.requires_vault_unlock"
                class="inline-block whitespace-nowrap rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-600 dark:bg-slate-800 dark:text-slate-300"
              >
                {{ t('import.count.vaultLocked') }}
              </span>
            </div>

            <div class="overflow-x-auto">
              <table class="w-full text-left text-xs" data-testid="import-plan-table">
                <thead class="sticky top-0 bg-slate-50 text-slate-600 dark:bg-slate-950/70 dark:text-slate-300">
                  <tr>
                    <th class="py-2 pe-3 font-medium">{{ t('import.table.certificate') }}</th>
                    <th class="py-2 pe-3 font-medium">{{ t('import.table.type') }}</th>
                    <th class="py-2 pe-3 font-medium">{{ t('import.table.privateKey') }}</th>
                    <th class="py-2 pe-3 font-medium">{{ t('import.table.parent') }}</th>
                    <th class="py-2 font-medium">{{ t('import.table.result') }}</th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    v-for="item in plan.items"
                    :key="item.fingerprint"
                    class="border-t border-slate-200 align-top dark:border-slate-800"
                    :data-import-action="item.action"
                    :data-import-name="item.name || item.subject"
                  >
                    <td class="py-2 pe-3">
                      <div class="font-medium text-slate-800 dark:text-slate-100">
                        {{ item.name || item.subject || t('import.table.unnamed') }}
                      </div>
                      <div class="font-mono break-all text-slate-500 dark:text-slate-400">
                        {{ item.fingerprint.slice(0, 16) }}…
                      </div>
                      <div v-if="item.sans?.length" class="break-all text-slate-500 dark:text-slate-400">
                        {{ t('import.table.san', { names: item.sans.join(', ') }) }}
                      </div>
                    </td>
                    <td class="py-2 pe-3 text-slate-600 dark:text-slate-300">{{ item.kind_label }}</td>
                    <td class="py-2 pe-3">
                      <span v-if="item.has_key" class="text-slate-600 dark:text-slate-300">
                        {{ t('import.table.hasKey', { algorithm: item.key_algorithm }) }}
                      </span>
                      <span v-else class="text-slate-500 dark:text-slate-400">{{ t('common.state.no') }}</span>
                    </td>
                    <td class="py-2 pe-3 text-slate-600 dark:text-slate-300">{{ item.parent || '-' }}</td>
                    <td class="py-2">
                      <span
                        class="inline-block whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-medium"
                        :class="ACTION_TONES[item.action]"
                      >
                        {{ actionLabel(item.action) }}
                      </span>
                      <div v-if="item.reason" class="mt-1 text-slate-500 dark:text-slate-400">
                        {{ item.reason }}
                      </div>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div v-if="plan.errors.length" class="mt-3 space-y-1">
              <p
                v-for="message in plan.errors"
                :key="message"
                class="rounded-lg border-l-4 border-red-500 bg-red-50 px-3 py-2 text-sm text-red-900 dark:bg-red-950/40 dark:text-red-200"
              >
                {{ message }}
              </p>
            </div>

            <div v-if="plan.warnings.length || plan.key_warnings.length" class="mt-3 space-y-1">
              <p
                v-for="message in [...plan.warnings, ...plan.key_warnings]"
                :key="message"
                class="rounded-lg border-l-4 border-amber-500 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:bg-amber-950/40 dark:text-amber-200"
              >
                {{ message }}
              </p>
            </div>

            <div class="mt-4 flex flex-wrap items-center gap-2">
              <button
                type="button"
                class="rounded-lg bg-moss-600 px-4 py-2.5 text-sm font-medium text-white shadow-sm transition hover:bg-moss-500 disabled:cursor-not-allowed disabled:opacity-60"
                :disabled="busy || !writable.length"
                data-testid="import-commit"
                @click="commit"
              >
                {{ t('import.commit.button', { count: writable.length }, writable.length) }}
              </button>
              <span v-if="hasProblems" class="text-xs text-slate-500 dark:text-slate-400">
                {{
                  t('import.commit.warning', {
                    conflict: t('import.action.conflict'),
                    unsupported: t('import.action.unsupported'),
                  })
                }}
              </span>
            </div>
          </template>

          <div
            v-if="result"
            class="mt-4 rounded-lg bg-slate-50 px-4 py-3 text-sm text-slate-700 dark:bg-slate-950/50 dark:text-slate-200"
            data-testid="import-result"
          >
            <p class="font-medium">
              {{
                t('import.result.created', {
                  root: result.created.root,
                  intermediate: result.created.intermediate,
                  leaf: result.created.leaf,
                  wrapped: result.keys_wrapped,
                  attached: result.keys_attached,
                  skipped: result.skipped,
                })
              }}
            </p>
            <p v-if="result.failed.length" class="mt-1 text-red-700 dark:text-red-300">
              {{ t('import.result.failedEntries', { count: result.failed.length }, result.failed.length) }}
              <span v-for="failure in result.failed" :key="failure.fingerprint">
                {{ failure.name }} ({{ failure.error }})
              </span>
            </p>
            <p class="mt-2">
              <RouterLink :to="{ name: 'home' }" class="font-medium underline">
                {{ t('import.result.back') }}
              </RouterLink>
            </p>
          </div>
        </div>
      </section>
    </div>

    <!-- ------------------------------------------------------------------
         What the importer accepts, straight from the server
         ------------------------------------------------------------------ -->
    <section
      class="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900"
    >
      <h2 class="bg-brand-500 px-5 py-3.5 text-base font-semibold text-white">
        {{ t('import.formats.title') }}
      </h2>
      <div class="px-5 py-5">
        <ul class="mb-3 list-inside list-disc space-y-1 text-sm text-slate-600 dark:text-slate-300">
          <li v-for="item in formats.supported" :key="item">{{ item }}</li>
        </ul>
        <p class="mb-1 text-sm font-medium text-slate-700 dark:text-slate-200">
          {{ t('import.formats.unsupported') }}
        </p>
        <ul class="list-inside list-disc space-y-1 text-sm text-slate-600 dark:text-slate-300">
          <li v-for="item in formats.unsupported" :key="item">{{ item }}</li>
        </ul>
        <p
          class="mt-3 rounded-lg border-l-4 border-amber-500 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:bg-amber-950/40 dark:text-amber-200"
        >
          {{ t('import.formats.sensitivity') }}
        </p>
      </div>
    </section>
  </div>
</template>
