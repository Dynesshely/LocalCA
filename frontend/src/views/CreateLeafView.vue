<script setup>
/**
 * Create and manage leaf certificates.
 */
import { computed, onMounted, reactive, ref } from 'vue'
import FormField from '@/components/FormField.vue'
import ConfirmActionDialog from '@/components/ConfirmActionDialog.vue'
import { useAuthStore } from '@/stores/auth'
import { useCertificatesStore } from '@/stores/certificates'
import { useToastStore } from '@/stores/toasts'
import { ApiError } from '@/api/client'

const auth = useAuthStore()
const certificates = useCertificatesStore()
const toasts = useToastStore()

const busy = ref(false)
const errors = ref([])
const form = reactive({ common_name: '', san: '', validity_days: 365, intermediate_id: '' })

const actionOpen = ref(false)
const actionKind = ref('revoke')
const actionTarget = ref(null)

const generalErrors = computed(() => errors.value.filter((e) => !e.includes(': ')))
const fieldError = (name) => {
  const hit = errors.value.find((e) => e.toLowerCase().startsWith(name.toLowerCase() + ': '))
  return hit ? hit.slice(hit.indexOf(':') + 1).trim() : ''
}

const myLeaves = computed(() =>
  certificates.flat.filter((c) => c.kind === 'leaf' && c.is_owner))

onMounted(async () => {
  try {
    await Promise.all([certificates.load(), certificates.loadIssuers()])
  } catch (err) {
    toasts.error(`Could not load certificates: ${err.message}`)
  }
})

async function submit() {
  errors.value = []
  busy.value = true
  try {
    const created = await certificates.create('leaf', { ...form })
    toasts.success(`Leaf certificate "${created.name}" created successfully.`)
    form.common_name = ''
    form.san = ''
  } catch (err) {
    errors.value = err instanceof ApiError ? err.errors : [String(err)]
    toasts.error(errors.value[0] || 'Could not create the leaf certificate.')
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
      toasts.success(`Certificate "${result.revoked}" revoked.`)
    } else {
      const result = await certificates.remove(target.kind, target.id)
      toasts.success(`Certificate "${result.deleted}" deleted.`)
    }
    actionOpen.value = false
  } catch (err) {
    toasts.error(err instanceof ApiError ? err.message : String(err))
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div>
    <h1 class="mb-4 text-2xl font-semibold">Leaf Certificates</h1>

    <div class="grid gap-6 lg:grid-cols-2">
      <!-- create -->
      <div class="rounded-xl border shadow-sm" :style="{ backgroundColor: 'var(--surface-card)', borderColor: 'var(--border-subtle)' }">
        <h2 class="rounded-t-xl px-4 py-3 text-base font-semibold text-white" :style="{ backgroundColor: 'var(--color-moss-600)' }">
          Create Leaf Certificate
        </h2>
        <form class="space-y-4 px-4 py-4" @submit.prevent="submit">
          <div
            v-if="generalErrors.length"
            class="rounded border-l-4 border-red-500 bg-red-50 px-3 py-2 text-sm text-red-900 dark:bg-red-950/50 dark:text-red-200"
          >
            <p v-for="(message, i) in generalErrors" :key="i">{{ message }}</p>
          </div>

          <FormField
            id="common_name"
            v-model="form.common_name"
            label="Common Name"
            required
            placeholder="e.g. example.com"
            help="The primary domain name. Also added to the SAN list."
            :error="fieldError('Common name')"
          />
          <FormField
            id="san"
            v-model="form.san"
            label="Subject Alternative Names"
            placeholder="e.g. www.example.com, api.example.com"
            help="Comma separated domain names or IP addresses."
            :error="fieldError('San')"
          />

          <div>
            <label for="intermediate_id" class="mb-1 block text-sm font-medium">Signing Intermediate CA</label>
            <select
              id="intermediate_id"
              v-model="form.intermediate_id"
              required
              data-testid="intermediate_id"
              class="w-full rounded border px-3 py-2 text-sm"
              :style="{ backgroundColor: 'var(--surface-sunken)', borderColor: 'var(--border-subtle)', color: 'var(--text-primary)' }"
            >
              <option value="" disabled>Select an Intermediate CA</option>
              <option v-for="ca in certificates.issuers.intermediates" :key="ca.id" :value="ca.id">
                {{ ca.name }}
              </option>
            </select>
            <p v-if="!certificates.issuers.intermediates.length" class="mt-1 text-xs text-red-600 dark:text-red-400">
              No intermediate CA of your own yet. Create one on the
              <RouterLink :to="{ name: 'create-ca' }" class="underline">Create CA</RouterLink> page.
            </p>
          </div>

          <FormField
            id="validity_days"
            v-model.number="form.validity_days"
            label="Validity period (days)"
            type="number"
            required
            :min="1"
            :max="auth.maxValidityDays.leaf"
            :help="`Maximum ${auth.maxValidityDays.leaf} days, and never longer than the signing intermediate.`"
            :error="fieldError('Validity days')"
          />

          <button
            type="submit"
            class="w-full rounded px-4 py-2 text-sm font-medium text-white transition disabled:opacity-60"
            :style="{ backgroundColor: 'var(--color-moss-600)' }"
            :disabled="busy || !certificates.issuers.intermediates.length"
            data-testid="create-leaf"
          >
            {{ busy ? 'Creating...' : 'Create Leaf Certificate' }}
          </button>
        </form>
      </div>

      <!-- existing -->
      <div class="rounded-xl border shadow-sm" :style="{ backgroundColor: 'var(--surface-card)', borderColor: 'var(--border-subtle)' }">
        <h2 class="rounded-t-xl px-4 py-3 text-base font-semibold text-white" :style="{ backgroundColor: 'var(--color-brand-500)' }">
          Your Leaf Certificates
        </h2>
        <div class="px-4 py-4">
          <div v-if="!myLeaves.length" class="text-sm" :style="{ color: 'var(--text-secondary)' }">
            You have not created any leaf certificates yet.
          </div>
          <div v-else class="max-h-[32rem] overflow-auto">
            <table class="w-full text-left text-sm">
              <thead class="sticky top-0" :style="{ backgroundColor: 'var(--surface-sunken)' }">
                <tr>
                  <th class="px-3 py-2 font-medium">Common name</th>
                  <th class="px-3 py-2 font-medium">Status</th>
                  <th class="px-3 py-2 font-medium">Signed by</th>
                  <th class="px-3 py-2 font-medium">Expires</th>
                  <th class="px-3 py-2 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="leaf in myLeaves"
                  :key="leaf.id"
                  class="border-t align-top"
                  :style="{ borderColor: 'var(--border-subtle)' }"
                  :data-leaf-id="leaf.id"
                >
                  <td class="px-3 py-2">
                    <div class="break-all" :class="{ 'line-through opacity-70': leaf.revocation }">
                      {{ leaf.name }}
                    </div>
                    <div v-if="leaf.sans?.length" class="mt-1 text-xs" :style="{ color: 'var(--text-secondary)' }">
                      SAN: {{ leaf.sans.join(', ') }}
                    </div>
                  </td>
                  <td class="px-3 py-2">
                    <span v-if="leaf.revocation" class="rounded bg-danger px-2 py-0.5 text-xs text-white" :title="leaf.revocation.reason_label">Revoked</span>
                    <span v-else class="rounded bg-emerald-600 px-2 py-0.5 text-xs text-white">Active</span>
                  </td>
                  <td class="px-3 py-2">{{ leaf.signed_by?.name }}</td>
                  <td class="px-3 py-2 whitespace-nowrap">{{ new Date(leaf.valid_until).toLocaleDateString() }}</td>
                  <td class="px-3 py-2">
                    <div class="flex flex-wrap gap-1">
                      <button
                        v-if="!leaf.revocation"
                        type="button"
                        class="rounded border border-red-500/60 px-2 py-1 text-xs text-red-700 transition hover:bg-red-500/10 dark:text-red-200"
                        :data-testid="`revoke-leaf-${leaf.id}`"
                        @click="openAction('revoke', leaf)"
                      >
                        Revoke
                      </button>
                      <button
                        type="button"
                        class="rounded bg-danger px-2 py-1 text-xs text-white transition hover:opacity-90"
                        :data-testid="`delete-leaf-${leaf.id}`"
                        @click="openAction('delete', leaf)"
                      >
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
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
</template>
