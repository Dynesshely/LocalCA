<script setup>
/**
 * Create root and intermediate CAs, with the tables of what already exists.
 *
 * Mirrors the previous two-column layout: a form beside the list of existing
 * CAs, so a new CA can be compared against what is already there.
 *
 * Colours are Tailwind utilities (`dark:` beside the light value, no CSS
 * variables) and all wording comes from the `ca` catalogue. Server validation
 * messages are attached by *field name* (`common_name`, `validity_days`,
 * `root_id`) rather than by parsing their labels.
 */
import { computed, onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import FormField from '@/components/FormField.vue'
import DownloadMenu from '@/components/DownloadMenu.vue'
import ExportDialog from '@/components/ExportDialog.vue'
import { useCertificateDownload } from '@/composables/useCertificateDownload'
import { useAuthStore } from '@/stores/auth'
import { useCertificatesStore } from '@/stores/certificates'
import { useVaultStore } from '@/stores/vault'
import { useToastStore } from '@/stores/toasts'
import { ApiError } from '@/api/client'

const { t, d } = useI18n()
const auth = useAuthStore()
const certificates = useCertificatesStore()
const vault = useVaultStore()
const toasts = useToastStore()

const busy = ref(false)
const downloads = useCertificateDownload()
const errors = ref([])
const fieldErrors = ref({})

const rootForm = reactive({ common_name: '', validity_days: 3650 })
const intermediateForm = reactive({ common_name: '', validity_days: 1825, root_id: '' })

/** The first message the server attached to a named field, or an empty string. */
const fieldError = (name) => (fieldErrors.value[name] || [])[0] || ''
/** Messages that belong to no single field: `clean()` failures and the like. */
const generalErrors = computed(() => errors.value.filter((e) => !e.includes(': ')))

const allRoots = computed(() => certificates.flat.filter((c) => c.kind === 'root'))
const allIntermediates = computed(() => certificates.flat.filter((c) => c.kind === 'intermediate'))

onMounted(async () => {
  try {
    await Promise.all([certificates.load(), certificates.loadIssuers()])
  } catch (err) {
    toasts.error(t('common.error.couldNotLoadCertificates', { message: err.message }))
  }
})

async function submitRoot() {
  errors.value = []
  fieldErrors.value = {}
  busy.value = true
  try {
    const created = await certificates.create('root', { ...rootForm })
    toasts.success(t('ca.createRoot.success', { name: created.name }))
    rootForm.common_name = ''
    await certificates.loadIssuers()
  } catch (err) {
    if (err instanceof ApiError && err.vaultLocked) {
      // The shell owns the dialog; it retries this exact call once unlocked.
      vault.requestUnlock(t('ca.createRoot.unlockReason'), submitRoot)
      return
    }
    errors.value = err instanceof ApiError ? err.errors : [String(err)]
    fieldErrors.value = err instanceof ApiError ? err.fieldErrors : {}
    toasts.error(errors.value[0] || t('ca.createRoot.failed'))
  } finally {
    busy.value = false
  }
}

async function submitIntermediate() {
  errors.value = []
  fieldErrors.value = {}
  busy.value = true
  try {
    const created = await certificates.create('intermediate', { ...intermediateForm })
    toasts.success(t('ca.createIntermediate.success', { name: created.name }))
    intermediateForm.common_name = ''
    await certificates.loadIssuers()
  } catch (err) {
    if (err instanceof ApiError && err.vaultLocked) {
      // The shell owns the dialog; it retries this exact call once unlocked.
      vault.requestUnlock(t('ca.createIntermediate.unlockReason'), submitIntermediate)
      return
    }
    errors.value = err instanceof ApiError ? err.errors : [String(err)]
    fieldErrors.value = err instanceof ApiError ? err.fieldErrors : {}
    toasts.error(errors.value[0] || t('ca.createIntermediate.failed'))
  } finally {
    busy.value = false
  }
}

function download(cert, kind) {
  const api = kind === 'private' ? 'privatePem' : 'publicPem'
  import('@/api').then(({ files }) => {
    files[api](cert.serial_number, cert.name).catch((err) => toasts.error(err.message))
  })
}

/** Short date in the reader's locale, not the browser's default formatting. */
function formatDay(value) {
  return value ? d(new Date(value), 'short') : ''
}
</script>

<template>
  <div class="mx-auto w-full max-w-[1400px] space-y-6">
    <div
      v-if="generalErrors.length"
      class="rounded-lg border-l-4 border-red-500 bg-red-50 px-3 py-2 text-sm text-red-900 dark:bg-red-950/40 dark:text-red-200"
    >
      <p v-for="(message, i) in generalErrors" :key="i">{{ message }}</p>
    </div>

    <!-- ------------------------------------------------------------ root CA -->
    <section class="grid gap-6 lg:grid-cols-2">
      <div
        class="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900"
      >
        <h2 class="bg-moss-600 px-5 py-3.5 text-base font-semibold text-white">
          {{ t('ca.createRoot.title') }}
        </h2>
        <form class="space-y-4 px-5 py-5" @submit.prevent="submitRoot">
          <FormField
            id="ca_name"
            v-model="rootForm.common_name"
            :label="t('ca.rootName.label')"
            required
            :placeholder="t('ca.rootName.placeholder')"
            :help="t('ca.rootName.help')"
            :error="fieldError('common_name')"
          />
          <FormField
            id="root_validity_days"
            v-model.number="rootForm.validity_days"
            :label="t('ca.validity.label')"
            type="number"
            required
            :min="1"
            :max="auth.maxValidityDays.root"
            :help="t('ca.validity.rootHelp', { max: auth.maxValidityDays.root })"
            :error="fieldError('validity_days')"
          />
          <button
            type="submit"
            class="w-full rounded-lg bg-moss-600 px-4 py-2.5 text-sm font-medium text-white shadow-sm transition hover:bg-moss-500 disabled:cursor-not-allowed disabled:opacity-60"
            :disabled="busy"
            data-testid="create-root"
          >
            {{ busy ? t('ca.createRoot.submitting') : t('ca.createRoot.submit') }}
          </button>
        </form>
      </div>

      <div
        class="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900"
      >
        <h2 class="bg-brand-500 px-5 py-3.5 text-base font-semibold text-white">
          {{ t('ca.list.rootsTitle') }}
        </h2>
        <div class="px-5 py-5">
          <p v-if="!allRoots.length" class="text-sm text-slate-500 dark:text-slate-400">
            {{ t('ca.list.rootsEmpty') }}
          </p>
          <div v-else class="max-h-[32rem] overflow-auto">
            <table class="w-full text-left text-sm">
              <thead class="sticky top-0 bg-slate-50 text-slate-600 dark:bg-slate-950/70 dark:text-slate-300">
                <tr>
                  <th class="px-3 py-2 font-medium">{{ t('ca.list.name') }}</th>
                  <th class="px-3 py-2 font-medium">{{ t('ca.list.status') }}</th>
                  <th class="px-3 py-2 font-medium">{{ t('ca.list.expires') }}</th>
                  <th class="px-3 py-2 font-medium">{{ t('ca.list.owner') }}</th>
                  <th class="px-3 py-2 font-medium">{{ t('ca.list.actions') }}</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="root in allRoots"
                  :key="root.id"
                  class="border-t border-slate-200 dark:border-slate-800"
                >
                  <td class="px-3 py-2 break-all text-slate-800 dark:text-slate-100">{{ root.name }}</td>
                  <td class="px-3 py-2">
                    <span
                      v-if="root.revocation"
                      class="inline-block whitespace-nowrap rounded-full bg-red-100 px-2 py-0.5 text-xs font-medium text-red-800 dark:bg-red-900/40 dark:text-red-200"
                    >
                      {{ t('common.status.revoked') }}
                    </span>
                    <span
                      v-else
                      class="inline-block whitespace-nowrap rounded-full bg-emerald-100 px-2 py-0.5 text-xs font-medium text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200"
                    >
                      {{ t('common.status.active') }}
                    </span>
                  </td>
                  <td class="px-3 py-2 whitespace-nowrap text-slate-600 dark:text-slate-300">
                    {{ formatDay(root.valid_until) }}
                  </td>
                  <td class="px-3 py-2 text-slate-600 dark:text-slate-300">{{ root.owner || '-' }}</td>
                  <td class="px-3 py-2">
                    <DownloadMenu
                      :certificate="root"
                      :has-key="root.has_key !== false"
                      @choose="(format) => downloads.run(root, format)"
                    />
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </section>

    <!-- ---------------------------------------------------- intermediate CA -->
    <section class="grid gap-6 lg:grid-cols-2">
      <div
        class="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900"
      >
        <h2 class="bg-moss-600 px-5 py-3.5 text-base font-semibold text-white">
          {{ t('ca.createIntermediate.title') }}
        </h2>
        <form class="space-y-4 px-5 py-5" @submit.prevent="submitIntermediate">
          <FormField
            id="intermediate_name"
            v-model="intermediateForm.common_name"
            :label="t('ca.intermediateName.label')"
            required
            :placeholder="t('ca.intermediateName.placeholder')"
            :help="t('ca.intermediateName.help')"
            :error="fieldError('common_name')"
          />

          <div>
            <label for="root_id" class="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-200">
              {{ t('ca.signingRoot.label') }}
            </label>
            <select
              id="root_id"
              v-model="intermediateForm.root_id"
              required
              data-testid="root_id"
              class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 shadow-sm transition focus:border-brand-500 focus:ring-2 focus:ring-brand-500/25 focus:outline-none dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
            >
              <option value="" disabled>{{ t('ca.signingRoot.placeholder') }}</option>
              <option v-for="root in certificates.issuers.roots" :key="root.id" :value="root.id">
                {{ root.name }}
              </option>
            </select>
            <p
              v-if="fieldError('root_id')"
              id="root_id-error"
              class="mt-1.5 text-xs text-red-600 dark:text-red-400"
            >
              {{ fieldError('root_id') }}
            </p>
            <p
              v-else-if="!certificates.issuers.roots.length"
              class="mt-1.5 text-xs text-amber-700 dark:text-amber-300"
            >
              {{ t('ca.signingRoot.none') }}
            </p>
            <p v-else class="mt-1.5 text-xs text-slate-500 dark:text-slate-400">
              {{ t('ca.signingRoot.help') }}
            </p>
          </div>

          <FormField
            id="intermediate_validity_days"
            v-model.number="intermediateForm.validity_days"
            :label="t('ca.validity.label')"
            type="number"
            required
            :min="1"
            :max="auth.maxValidityDays.intermediate"
            :help="t('ca.validity.intermediateHelp')"
            :error="fieldError('validity_days')"
          />

          <button
            type="submit"
            class="w-full rounded-lg bg-moss-600 px-4 py-2.5 text-sm font-medium text-white shadow-sm transition hover:bg-moss-500 disabled:cursor-not-allowed disabled:opacity-60"
            :disabled="busy || !certificates.issuers.roots.length"
            data-testid="create-intermediate"
          >
            {{ busy ? t('ca.createIntermediate.submitting') : t('ca.createIntermediate.submit') }}
          </button>
        </form>
      </div>

      <div
        class="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900"
      >
        <h2 class="bg-brand-500 px-5 py-3.5 text-base font-semibold text-white">
          {{ t('ca.list.intermediatesTitle') }}
        </h2>
        <div class="px-5 py-5">
          <p v-if="!allIntermediates.length" class="text-sm text-slate-500 dark:text-slate-400">
            {{ t('ca.list.intermediatesEmpty') }}
          </p>
          <div v-else class="max-h-[32rem] overflow-auto">
            <table class="w-full text-left text-sm">
              <thead class="sticky top-0 bg-slate-50 text-slate-600 dark:bg-slate-950/70 dark:text-slate-300">
                <tr>
                  <th class="px-3 py-2 font-medium">{{ t('ca.list.name') }}</th>
                  <th class="px-3 py-2 font-medium">{{ t('ca.list.status') }}</th>
                  <th class="px-3 py-2 font-medium">{{ t('ca.list.signedBy') }}</th>
                  <th class="px-3 py-2 font-medium">{{ t('ca.list.expires') }}</th>
                  <th class="px-3 py-2 font-medium">{{ t('ca.list.actions') }}</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="ca in allIntermediates"
                  :key="ca.id"
                  class="border-t border-slate-200 dark:border-slate-800"
                >
                  <td class="px-3 py-2 break-all text-slate-800 dark:text-slate-100">{{ ca.name }}</td>
                  <td class="px-3 py-2">
                    <span
                      v-if="ca.revocation"
                      class="inline-block whitespace-nowrap rounded-full bg-red-100 px-2 py-0.5 text-xs font-medium text-red-800 dark:bg-red-900/40 dark:text-red-200"
                    >
                      {{ t('common.status.revoked') }}
                    </span>
                    <span
                      v-else
                      class="inline-block whitespace-nowrap rounded-full bg-emerald-100 px-2 py-0.5 text-xs font-medium text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200"
                    >
                      {{ t('common.status.active') }}
                    </span>
                  </td>
                  <td class="px-3 py-2 text-slate-600 dark:text-slate-300">{{ ca.signed_by?.name }}</td>
                  <td class="px-3 py-2 whitespace-nowrap text-slate-600 dark:text-slate-300">
                    {{ formatDay(ca.valid_until) }}
                  </td>
                  <td class="px-3 py-2">
                    <DownloadMenu
                      :certificate="ca"
                      :has-key="ca.has_key !== false"
                      @choose="(format) => downloads.run(ca, format)"
                    />
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </section>
  </div>
  <ExportDialog
    :open="!!downloads.pendingFormat.value"
    :certificate="downloads.pendingCertificate.value"
    :format="downloads.pendingFormat.value || ''"
    :requires="downloads.requires(downloads.pendingFormat.value)"
    :busy="downloads.busy.value || busy"
    @close="downloads.cancel()"
    @confirm="downloads.submit"
  />
</template>
