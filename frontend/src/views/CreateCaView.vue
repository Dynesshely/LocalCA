<script setup>
/**
 * Create root and intermediate CAs, with the tables of what already exists.
 *
 * Mirrors the previous two-column layout: a form beside the list of existing
 * CAs, so a new CA can be compared against what is already there.
 */
import { computed, onMounted, reactive, ref } from 'vue'
import FormField from '@/components/FormField.vue'
import { useAuthStore } from '@/stores/auth'
import { useCertificatesStore } from '@/stores/certificates'
import { useToastStore } from '@/stores/toasts'
import { ApiError } from '@/api/client'

const auth = useAuthStore()
const certificates = useCertificatesStore()
const toasts = useToastStore()

const busy = ref(false)
const errors = ref([])

const rootForm = reactive({ common_name: '', validity_days: 3650 })
const intermediateForm = reactive({ common_name: '', validity_days: 1825, root_id: '' })

const fieldError = (name) => {
  const hit = errors.value.find((e) => e.toLowerCase().startsWith(name.toLowerCase() + ':'))
  return hit ? hit.split(':').slice(1).join(':').trim() : ''
}
const generalErrors = computed(() => errors.value.filter((e) => !e.includes(': ')))

const allRoots = computed(() => certificates.flat.filter((c) => c.kind === 'root'))
const allIntermediates = computed(() => certificates.flat.filter((c) => c.kind === 'intermediate'))

onMounted(async () => {
  try {
    await Promise.all([certificates.load(), certificates.loadIssuers()])
  } catch (err) {
    toasts.error(`Could not load certificates: ${err.message}`)
  }
})

async function submitRoot() {
  errors.value = []
  busy.value = true
  try {
    const created = await certificates.create('root', { ...rootForm })
    toasts.success(`Root CA "${created.name}" created successfully.`)
    rootForm.common_name = ''
    await certificates.loadIssuers()
  } catch (err) {
    errors.value = err instanceof ApiError ? err.errors : [String(err)]
    toasts.error(errors.value[0] || 'Could not create the root CA.')
  } finally {
    busy.value = false
  }
}

async function submitIntermediate() {
  errors.value = []
  busy.value = true
  try {
    const created = await certificates.create('intermediate', { ...intermediateForm })
    toasts.success(`Intermediate CA "${created.name}" created successfully.`)
    intermediateForm.common_name = ''
    await certificates.loadIssuers()
  } catch (err) {
    errors.value = err instanceof ApiError ? err.errors : [String(err)]
    toasts.error(errors.value[0] || 'Could not create the intermediate CA.')
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
</script>

<template>
  <div class="space-y-8">
    <h1 class="text-2xl font-semibold">Certificate Authorities</h1>

    <div
      v-if="generalErrors.length"
      class="rounded border-l-4 border-red-500 bg-red-50 px-4 py-3 text-sm text-red-900 dark:bg-red-950/50 dark:text-red-200"
    >
      <p v-for="(message, i) in generalErrors" :key="i">{{ message }}</p>
    </div>

    <!-- ------------------------------------------------------------ root CA -->
    <section class="grid gap-6 lg:grid-cols-2">
      <div class="rounded-xl border shadow-sm" :style="{ backgroundColor: 'var(--surface-card)', borderColor: 'var(--border-subtle)' }">
        <h2 class="rounded-t-xl px-4 py-3 text-base font-semibold text-white" :style="{ backgroundColor: 'var(--color-brand-800)' }">
          Create Root CA
        </h2>
        <form class="space-y-4 px-4 py-4" @submit.prevent="submitRoot">
          <FormField
            id="ca_name"
            v-model="rootForm.common_name"
            label="Root CA Name"
            required
            placeholder="e.g. MyCompany Root CA"
            help="Must be unique. It becomes the certificate's Common Name."
            :error="fieldError('Common name')"
          />
          <FormField
            id="root_validity_days"
            v-model.number="rootForm.validity_days"
            label="Validity period (days)"
            type="number"
            required
            :min="1"
            :max="auth.maxValidityDays.root"
            :help="`1 to ${auth.maxValidityDays.root} days.`"
            :error="fieldError('Validity days')"
          />
          <button
            type="submit"
            class="w-full rounded px-4 py-2 text-sm font-medium text-white transition disabled:opacity-60"
            :style="{ backgroundColor: 'var(--color-brand-700)' }"
            :disabled="busy"
            data-testid="create-root"
          >
            {{ busy ? 'Creating...' : 'Create Root CA' }}
          </button>
        </form>
      </div>

      <div class="rounded-xl border shadow-sm" :style="{ backgroundColor: 'var(--surface-card)', borderColor: 'var(--border-subtle)' }">
        <h2 class="rounded-t-xl px-4 py-3 text-base font-semibold text-white" :style="{ backgroundColor: 'var(--color-brand-500)' }">
          Existing Root CAs
        </h2>
        <div class="px-4 py-4">
          <div v-if="!allRoots.length" class="text-sm" :style="{ color: 'var(--text-secondary)' }">
            No root CAs yet. Create your first one.
          </div>
          <div v-else class="max-h-96 overflow-auto">
            <table class="w-full text-left text-sm">
              <thead class="sticky top-0" :style="{ backgroundColor: 'var(--surface-sunken)' }">
                <tr>
                  <th class="px-3 py-2 font-medium">Name</th>
                  <th class="px-3 py-2 font-medium">Status</th>
                  <th class="px-3 py-2 font-medium">Expires</th>
                  <th class="px-3 py-2 font-medium">Owner</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="root in allRoots" :key="root.id" class="border-t" :style="{ borderColor: 'var(--border-subtle)' }">
                  <td class="px-3 py-2 break-all">{{ root.name }}</td>
                  <td class="px-3 py-2">
                    <span v-if="root.revocation" class="rounded bg-danger px-2 py-0.5 text-xs text-white">Revoked</span>
                    <span v-else class="rounded bg-emerald-600 px-2 py-0.5 text-xs text-white">Active</span>
                  </td>
                  <td class="px-3 py-2 whitespace-nowrap">{{ new Date(root.valid_until).toLocaleDateString() }}</td>
                  <td class="px-3 py-2">{{ root.owner || '-' }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </section>

    <!-- ---------------------------------------------------- intermediate CA -->
    <section class="grid gap-6 lg:grid-cols-2">
      <div class="rounded-xl border shadow-sm" :style="{ backgroundColor: 'var(--surface-card)', borderColor: 'var(--border-subtle)' }">
        <h2 class="rounded-t-xl px-4 py-3 text-base font-semibold text-white" :style="{ backgroundColor: 'var(--color-brand-600)' }">
          Create Intermediate CA
        </h2>
        <form class="space-y-4 px-4 py-4" @submit.prevent="submitIntermediate">
          <FormField
            id="intermediate_name"
            v-model="intermediateForm.common_name"
            label="Intermediate CA Name"
            required
            placeholder="e.g. MyCompany Intermediate CA"
            help="Must be unique."
            :error="fieldError('Common name')"
          />

          <div>
            <label for="root_id" class="mb-1 block text-sm font-medium">Signing Root CA</label>
            <select
              id="root_id"
              v-model="intermediateForm.root_id"
              required
              data-testid="root_id"
              class="w-full rounded border px-3 py-2 text-sm"
              :style="{ backgroundColor: 'var(--surface-sunken)', borderColor: 'var(--border-subtle)', color: 'var(--text-primary)' }"
            >
              <option value="" disabled>Select a Root CA</option>
              <option v-for="root in certificates.issuers.roots" :key="root.id" :value="root.id">
                {{ root.name }}
              </option>
            </select>
            <p
              v-if="!certificates.issuers.roots.length"
              class="mt-1 text-xs text-red-600 dark:text-red-400"
            >
              You need a root CA of your own first: signing consumes its private key,
              so only your own roots are listed.
            </p>
            <p v-else class="mt-1 text-xs" :style="{ color: 'var(--text-secondary)' }">
              Only your own root CAs are listed.
            </p>
          </div>

          <FormField
            id="intermediate_validity_days"
            v-model.number="intermediateForm.validity_days"
            label="Validity period (days)"
            type="number"
            required
            :min="1"
            :max="auth.maxValidityDays.intermediate"
            help="Cannot outlive the signing root CA."
            :error="fieldError('Validity days')"
          />

          <button
            type="submit"
            class="w-full rounded px-4 py-2 text-sm font-medium text-white transition disabled:opacity-60"
            :style="{ backgroundColor: 'var(--color-brand-600)' }"
            :disabled="busy || !certificates.issuers.roots.length"
            data-testid="create-intermediate"
          >
            {{ busy ? 'Creating...' : 'Create Intermediate CA' }}
          </button>
        </form>
      </div>

      <div class="rounded-xl border shadow-sm" :style="{ backgroundColor: 'var(--surface-card)', borderColor: 'var(--border-subtle)' }">
        <h2 class="rounded-t-xl px-4 py-3 text-base font-semibold text-white" :style="{ backgroundColor: 'var(--color-brand-500)' }">
          Existing Intermediate CAs
        </h2>
        <div class="px-4 py-4">
          <div v-if="!allIntermediates.length" class="text-sm" :style="{ color: 'var(--text-secondary)' }">
            No intermediate CAs yet.
          </div>
          <div v-else class="max-h-96 overflow-auto">
            <table class="w-full text-left text-sm">
              <thead class="sticky top-0" :style="{ backgroundColor: 'var(--surface-sunken)' }">
                <tr>
                  <th class="px-3 py-2 font-medium">Name</th>
                  <th class="px-3 py-2 font-medium">Status</th>
                  <th class="px-3 py-2 font-medium">Signed by</th>
                  <th class="px-3 py-2 font-medium">Expires</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="ca in allIntermediates" :key="ca.id" class="border-t" :style="{ borderColor: 'var(--border-subtle)' }">
                  <td class="px-3 py-2 break-all">{{ ca.name }}</td>
                  <td class="px-3 py-2">
                    <span v-if="ca.revocation" class="rounded bg-danger px-2 py-0.5 text-xs text-white">Revoked</span>
                    <span v-else class="rounded bg-emerald-600 px-2 py-0.5 text-xs text-white">Active</span>
                  </td>
                  <td class="px-3 py-2">{{ ca.signed_by?.name }}</td>
                  <td class="px-3 py-2 whitespace-nowrap">{{ new Date(ca.valid_until).toLocaleDateString() }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </section>
  </div>
</template>
