<script setup>
/**
 * Create and manage leaf certificates.
 *
 * This is the reference page for the rest of the interface: Tailwind utilities
 * carry every colour (`dark:` beside the light value, no CSS variables), all
 * wording comes from the i18n catalogues, and server validation messages are
 * attached by *field name* rather than by parsing the message text.
 */
import { computed, onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import FormField from '@/components/FormField.vue'
import DownloadMenu from '@/components/DownloadMenu.vue'
import ExportDialog from '@/components/ExportDialog.vue'
import { useCertificateDownload } from '@/composables/useCertificateDownload'
import ConfirmActionDialog from '@/components/ConfirmActionDialog.vue'
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
const form = reactive({ common_name: '', san: '', validity_days: 365, intermediate_id: '' })

const actionOpen = ref(false)
const actionKind = ref('revoke')
const actionTarget = ref(null)

/** Messages that belong to no single field: `clean()` failures and the like. */
const generalErrors = computed(() => errors.value.filter((e) => !e.includes(': ')))
const fieldError = (name) => (fieldErrors.value[name] || [])[0] || ''

const myLeaves = computed(() =>
  certificates.flat.filter((c) => c.kind === 'leaf' && c.is_owner))

onMounted(async () => {
  try {
    await Promise.all([certificates.load(), certificates.loadIssuers()])
  } catch (err) {
    toasts.error(t('common.error.couldNotLoadCertificates', { message: err.message }))
  }
})

async function submit() {
  errors.value = []
  fieldErrors.value = {}
  busy.value = true
  try {
    const created = await certificates.create('leaf', { ...form })
    toasts.success(t('leaf.create.success', { name: created.name }))
    form.common_name = ''
    form.san = ''
  } catch (err) {
    if (err instanceof ApiError && err.vaultLocked) {
      // The shell owns the dialog; it retries this exact call once unlocked.
      vault.requestUnlock(t('leaf.create.unlockReason'), submit)
      return
    }
    errors.value = err instanceof ApiError ? err.errors : [String(err)]
    fieldErrors.value = err instanceof ApiError ? err.fieldErrors : {}
    toasts.error(errors.value[0] || t('leaf.create.failed'))
  } finally {
    busy.value = false
  }
}

function openAction(kind, certificate) {
  actionKind.value = kind
  actionTarget.value = certificate
  actionOpen.value = true
}

async function confirmAction(payload) {
  const target = actionTarget.value
  if (!target) return
  busy.value = true
  try {
    if (actionKind.value === 'revoke') {
      const result = await certificates.revoke(target.kind, target.id, {
        type: target.kind,
        id: String(target.id),
        reason: payload.reason,
        comment: payload.comment || '',
        cascade: payload.cascade ? '1' : '',
      })
      toasts.success(t('leaf.revoked', { name: result.revoked }))
    } else {
      const result = await certificates.remove(target.kind, target.id)
      toasts.success(t('leaf.deleted', { name: result.deleted }))
    }
    actionOpen.value = false
  } catch (err) {
    toasts.error(err instanceof ApiError ? err.message : String(err))
  } finally {
    busy.value = false
  }
}

/** Short date in the reader's locale, not the browser's default formatting. */
function formatDay(value) {
  return value ? d(new Date(value), 'short') : ''
}
</script>

<template>
  <div class="mx-auto w-full max-w-[1400px]">
    <!-- The table column takes the larger share: it carries a CA name, four
         SANs and two buttons, while the form is a fixed set of inputs. -->
    <div class="grid items-start gap-6 lg:grid-cols-[minmax(20rem,0.9fr)_minmax(0,1.1fr)]">
      <!-- ------------------------------------------------------------------
           Create
           ------------------------------------------------------------------ -->
      <section
        class="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900"
      >
        <h2 class="bg-moss-600 px-5 py-3.5 text-base font-semibold text-white">
          {{ t('leaf.create.title') }}
        </h2>
        <form class="space-y-4 px-5 py-5" @submit.prevent="submit">
          <div
            v-if="generalErrors.length"
            class="rounded-lg border-l-4 border-red-500 bg-red-50 px-3 py-2 text-sm text-red-900 dark:bg-red-950/40 dark:text-red-200"
          >
            <p v-for="(message, i) in generalErrors" :key="i">{{ message }}</p>
          </div>

          <FormField
            id="common_name"
            v-model="form.common_name"
            :label="t('leaf.commonName.label')"
            required
            :placeholder="t('leaf.commonName.placeholder')"
            :help="t('leaf.commonName.help')"
            :error="fieldError('common_name')"
          />

          <!-- One name per line: the shape a pasted list already has. The
               server accepts commas and whitespace as well. -->
          <FormField
            id="san"
            v-model="form.san"
            type="textarea"
            :rows="6"
            :label="t('leaf.san.label')"
            :placeholder="t('leaf.san.placeholder')"
            :help="t('leaf.san.help')"
            :error="fieldError('san')"
          />

          <div>
            <label for="intermediate_id" class="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-200">
              {{ t('leaf.intermediate.label') }}
            </label>
            <select
              id="intermediate_id"
              v-model="form.intermediate_id"
              required
              data-testid="intermediate_id"
              class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 shadow-sm transition focus:border-brand-500 focus:ring-2 focus:ring-brand-500/25 focus:outline-none dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
            >
              <option value="" disabled>{{ t('leaf.intermediate.placeholder') }}</option>
              <option v-for="ca in certificates.issuers.intermediates" :key="ca.id" :value="ca.id">
                {{ ca.name }}
              </option>
            </select>
            <i18n-t
              v-if="!certificates.issuers.intermediates.length"
              keypath="leaf.intermediate.none"
              tag="p"
              class="mt-1.5 text-xs text-amber-700 dark:text-amber-300"
            >
              <template #link>
                <RouterLink :to="{ name: 'create-ca' }" class="font-medium underline">
                  {{ t('common.nav.createCa') }}
                </RouterLink>
              </template>
            </i18n-t>
          </div>

          <FormField
            id="validity_days"
            v-model.number="form.validity_days"
            :label="t('leaf.validity.label')"
            type="number"
            required
            :min="1"
            :max="auth.maxValidityDays.leaf"
            :help="t('leaf.validity.help', { max: auth.maxValidityDays.leaf })"
            :error="fieldError('validity_days')"
          />

          <button
            type="submit"
            class="w-full rounded-lg bg-moss-600 px-4 py-2.5 text-sm font-medium text-white shadow-sm transition hover:bg-moss-500 disabled:cursor-not-allowed disabled:opacity-60"
            :disabled="busy || !certificates.issuers.intermediates.length"
            data-testid="create-leaf"
          >
            {{ busy ? t('leaf.create.submitting') : t('leaf.create.submit') }}
          </button>
        </form>
      </section>

      <!-- ------------------------------------------------------------------
           Existing
           ------------------------------------------------------------------ -->
      <section
        class="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900"
      >
        <h2 class="bg-brand-500 px-5 py-3.5 text-base font-semibold text-white">
          {{ t('leaf.list.title') }}
        </h2>
        <div class="px-5 py-5">
          <p v-if="!myLeaves.length" class="text-sm text-slate-500 dark:text-slate-400">
            {{ t('leaf.list.empty') }}
          </p>
          <div v-else class="max-h-[32rem] overflow-auto">
            <table class="w-full text-left text-sm">
              <thead class="sticky top-0 bg-slate-50 text-slate-600 dark:bg-slate-950/70 dark:text-slate-300">
                <tr>
                  <th class="px-3 py-2 font-medium">{{ t('leaf.list.commonName') }}</th>
                  <th class="px-3 py-2 font-medium">{{ t('leaf.list.status') }}</th>
                  <th class="px-3 py-2 font-medium">{{ t('leaf.list.signedBy') }}</th>
                  <th class="px-3 py-2 font-medium">{{ t('leaf.list.expires') }}</th>
                  <th class="px-3 py-2 font-medium">{{ t('leaf.list.actions') }}</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="leaf in myLeaves"
                  :key="leaf.id"
                  class="border-t border-slate-200 align-top dark:border-slate-800"
                  :data-leaf-id="leaf.id"
                >
                  <td class="px-3 py-2">
                    <div
                      class="break-all text-slate-800 dark:text-slate-100"
                      :class="{ 'line-through opacity-70': leaf.revocation }"
                    >
                      {{ leaf.name }}
                    </div>
                    <div v-if="leaf.sans?.length" class="mt-1 text-xs text-slate-500 dark:text-slate-400">
                      {{ t('common.field.sanLabel') }} {{ leaf.sans.join(', ') }}
                    </div>
                  </td>
                  <td class="px-3 py-2">
                    <span
                      v-if="leaf.revocation"
                      class="inline-block whitespace-nowrap rounded-full bg-red-100 px-2 py-0.5 text-xs font-medium text-red-800 dark:bg-red-900/40 dark:text-red-200"
                      :title="leaf.revocation.reason_label"
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
                  <td class="px-3 py-2 text-slate-600 dark:text-slate-300">{{ leaf.signed_by?.name }}</td>
                  <td class="px-3 py-2 whitespace-nowrap text-slate-600 dark:text-slate-300">
                    {{ formatDay(leaf.valid_until) }}
                  </td>
                  <td class="px-3 py-2">
                    <div class="flex flex-wrap items-center gap-1">
                      <DownloadMenu
                        :certificate="leaf"
                        :has-key="leaf.has_key !== false"
                        @choose="(format) => downloads.run(leaf, format)"
                      />
                      <button
                        v-if="!leaf.revocation"
                        type="button"
                        class="rounded-lg border border-red-300 px-2 py-1 text-xs font-medium text-red-700 transition hover:bg-red-50 dark:border-red-800 dark:text-red-300 dark:hover:bg-red-950/40"
                        :data-testid="`revoke-leaf-${leaf.id}`"
                        @click="openAction('revoke', leaf)"
                      >
                        {{ t('common.action.revoke') }}
                      </button>
                      <button
                        type="button"
                        class="rounded-lg bg-red-600 px-2 py-1 text-xs font-medium text-white transition hover:bg-red-500"
                        :data-testid="`delete-leaf-${leaf.id}`"
                        @click="openAction('delete', leaf)"
                      >
                        {{ t('common.action.delete') }}
                      </button>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </div>

    <ConfirmActionDialog
      :open="actionOpen"
      :action="actionKind"
      :certificate="actionTarget"
      :busy="busy"
      @close="actionOpen = false"
      @confirm="confirmAction"
    />
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
