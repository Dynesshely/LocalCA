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
import FormField from '@/components/FormField.vue'
import VaultUnlockDialog from '@/components/VaultUnlockDialog.vue'
import { imports as importApi, meta as metaApi } from '@/api'
import { ApiError } from '@/api/client'
import { useCertificatesStore } from '@/stores/certificates'
import { useVaultStore } from '@/stores/vault'
import { useToastStore } from '@/stores/toasts'

const certificates = useCertificatesStore()
const vault = useVaultStore()
const toasts = useToastStore()

const files = ref([])
const password = ref('')
const busy = ref(false)
const plan = ref(null)
const result = ref(null)
const formats = ref({ supported: [], unsupported: [], limits: {} })

const unlockOpen = ref(false)
const unlockReason = ref('')
let retryAfterUnlock = null

const ACTION_LABELS = {
  create: 'will import',
  skip: 'already present',
  attach_key: 'add key',
  conflict: 'needs attention',
  unsupported: 'cannot store',
}

const ACTION_TONES = {
  create: 'bg-emerald-600 text-white',
  attach_key: 'bg-sky-600 text-white',
  skip: 'bg-slate-500/80 text-white',
  conflict: 'bg-amber-500 text-white',
  unsupported: 'bg-danger text-white',
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
    toasts.info(`Parsed ${payload.plan.items.length} certificate(s). Nothing has been written yet.`)
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
    await vault.load()
    const created = payload.result.created
    toasts.success(
      `Imported ${created.root} root, ${created.intermediate} intermediate and `
      + `${created.leaf} leaf certificate(s); ${payload.result.keys_wrapped} key(s) wrapped.`,
    )
    if (payload.result.failed?.length) {
      toasts.error(`${payload.result.failed.length} entry(ies) could not be imported.`)
    }
  } catch (err) {
    if (isVaultLocked(err)) {
      unlockReason.value = err.message
      retryAfterUnlock = commit
      unlockOpen.value = true
    } else {
      reportError(err)
    }
  } finally {
    busy.value = false
  }
}

async function onUnlocked() {
  unlockOpen.value = false
  await vault.load()
  const retry = retryAfterUnlock
  retryAfterUnlock = null
  if (retry) await retry()
}

metaApi.get().then((payload) => {
  if (payload.import_formats) formats.value = payload.import_formats
}).catch(() => {})
</script>

<template>
  <div class="space-y-6">
    <header>
      <h1 class="text-xl font-semibold">Import certificates</h1>
      <p class="mt-1 text-sm" :style="{ color: 'var(--text-secondary)' }">
        Bring existing certificate material into LocalCA: a root or intermediate CA
        with its private key, a leaf certificate, or a whole chain. Formats are
        recognised by content, not by file extension.
      </p>
    </header>

    <div class="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
      <section
        class="rounded-lg border p-4"
        :style="{ backgroundColor: 'var(--surface-card)', borderColor: 'var(--border-subtle)' }"
      >
        <h2 class="mb-3 text-sm font-semibold">1. Choose what to import</h2>

        <div
          class="rounded border border-dashed p-4 text-center text-sm"
          :style="{ borderColor: 'var(--border-subtle)' }"
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
            class="rounded bg-brand-800 px-3 py-2 text-sm font-medium text-white"
            data-testid="import-choose"
            @click="chooseFiles"
          >
            Choose files
          </button>
          <p class="mt-2 text-xs" :style="{ color: 'var(--text-secondary)' }">
            or drop them here — up to {{ formats.limits?.max_files || 8 }} files,
            {{ Math.round((formats.limits?.max_file_bytes || 1048576) / 1024) }} KiB each
          </p>
        </div>

        <ul v-if="selectedNames.length" class="mt-3 space-y-1 text-xs">
          <li v-for="name in selectedNames" :key="name" class="truncate font-mono">
            {{ name }}
          </li>
        </ul>

        <div class="mt-4">
          <FormField
            id="import-password"
            v-model="password"
            label="Password for encrypted keys"
            type="password"
            placeholder="PKCS#12 or encrypted private key"
            help="Only needed when a bundle or key in the upload is password protected. It is used for this request and never stored."
          />
        </div>

        <div class="mt-4 flex flex-wrap gap-2">
          <button
            type="button"
            class="rounded bg-brand-800 px-3 py-2 text-sm font-medium text-white disabled:opacity-50"
            :disabled="!files.length || busy"
            data-testid="import-analyze"
            @click="analyze"
          >
            Analyze
          </button>
          <button
            type="button"
            class="rounded border px-3 py-2 text-sm disabled:opacity-50"
            :style="{ borderColor: 'var(--border-subtle)' }"
            :disabled="busy && !files.length"
            @click="clearAll"
          >
            Clear
          </button>
        </div>
      </section>

      <section
        class="rounded-lg border p-4"
        :style="{ backgroundColor: 'var(--surface-card)', borderColor: 'var(--border-subtle)' }"
      >
        <h2 class="mb-3 text-sm font-semibold">2. Review the plan</h2>

        <p v-if="!plan" class="text-sm" :style="{ color: 'var(--text-secondary)' }">
          Nothing analyzed yet. The plan lists every certificate found, what would
          happen to it, and where it would sit in the hierarchy.
        </p>

        <template v-else>
          <div class="mb-3 flex flex-wrap gap-2 text-xs">
            <span class="rounded bg-emerald-600 px-2 py-0.5 text-white">
              {{ plan.counts.create }} to import
            </span>
            <span v-if="plan.counts.attach_key" class="rounded bg-sky-600 px-2 py-0.5 text-white">
              {{ plan.counts.attach_key }} key(s) to add
            </span>
            <span v-if="plan.counts.skip" class="rounded bg-slate-500/80 px-2 py-0.5 text-white">
              {{ plan.counts.skip }} already present
            </span>
            <span v-if="plan.counts.conflict" class="rounded bg-amber-500 px-2 py-0.5 text-white">
              {{ plan.counts.conflict }} need attention
            </span>
            <span v-if="plan.counts.unsupported" class="rounded bg-danger px-2 py-0.5 text-white">
              {{ plan.counts.unsupported }} cannot be stored
            </span>
            <span v-if="plan.requires_vault_unlock" class="rounded border px-2 py-0.5">
              vault must be unlocked
            </span>
          </div>

          <div class="overflow-x-auto">
            <table class="w-full text-left text-xs" data-testid="import-plan-table">
              <thead :style="{ color: 'var(--text-secondary)' }">
                <tr class="border-b" :style="{ borderColor: 'var(--border-subtle)' }">
                  <th class="py-2 pe-3">Certificate</th>
                  <th class="py-2 pe-3">Type</th>
                  <th class="py-2 pe-3">Private key</th>
                  <th class="py-2 pe-3">Parent</th>
                  <th class="py-2">Result</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="item in plan.items"
                  :key="item.fingerprint"
                  class="border-b align-top"
                  :style="{ borderColor: 'var(--border-subtle)' }"
                  :data-import-action="item.action"
                  :data-import-name="item.name || item.subject"
                >
                  <td class="py-2 pe-3">
                    <div class="font-medium">{{ item.name || item.subject || '(unnamed)' }}</div>
                    <div class="font-mono break-all" :style="{ color: 'var(--text-secondary)' }">
                      {{ item.fingerprint.slice(0, 16) }}…
                    </div>
                    <div v-if="item.sans?.length" class="break-all" :style="{ color: 'var(--text-secondary)' }">
                      SAN: {{ item.sans.join(', ') }}
                    </div>
                  </td>
                  <td class="py-2 pe-3">{{ item.kind_label }}</td>
                  <td class="py-2 pe-3">
                    <span v-if="item.has_key">yes ({{ item.key_algorithm }})</span>
                    <span v-else :style="{ color: 'var(--text-secondary)' }">no</span>
                  </td>
                  <td class="py-2 pe-3">{{ item.parent || '-' }}</td>
                  <td class="py-2">
                    <span class="rounded px-2 py-0.5" :class="ACTION_TONES[item.action]">
                      {{ ACTION_LABELS[item.action] }}
                    </span>
                    <div v-if="item.reason" class="mt-1" :style="{ color: 'var(--text-secondary)' }">
                      {{ item.reason }}
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <div v-if="plan.errors.length" class="mt-3 text-xs">
            <p
              v-for="message in plan.errors"
              :key="message"
              class="rounded px-2 py-1 text-red-700 dark:text-red-300"
              :style="{ backgroundColor: 'var(--surface-danger)' }"
            >
              {{ message }}
            </p>
          </div>

          <div v-if="plan.warnings.length || plan.key_warnings.length" class="mt-3 space-y-1 text-xs">
            <p
              v-for="message in [...plan.warnings, ...plan.key_warnings]"
              :key="message"
              class="rounded bg-amber-500/15 px-2 py-1 text-amber-800 dark:text-amber-200"
            >
              {{ message }}
            </p>
          </div>

          <div class="mt-4 flex flex-wrap items-center gap-2">
            <button
              type="button"
              class="rounded bg-emerald-600 px-3 py-2 text-sm font-medium text-white disabled:opacity-50"
              :disabled="busy || !writable.length"
              data-testid="import-commit"
              @click="commit"
            >
              Import {{ writable.length }} certificate(s)
            </button>
            <span v-if="hasProblems" class="text-xs" :style="{ color: 'var(--text-secondary)' }">
              Entries marked “needs attention” or “cannot be stored” are skipped; import the
              missing issuer first, then analyze again.
            </span>
          </div>
        </template>

        <div v-if="result" class="mt-4 rounded px-3 py-2 text-xs" data-testid="import-result" :style="{ backgroundColor: 'var(--surface-sunken)' }">
          <p class="font-medium">
            Created: {{ result.created.root }} root,
            {{ result.created.intermediate }} intermediate,
            {{ result.created.leaf }} leaf — {{ result.keys_wrapped }} key(s) wrapped,
            {{ result.keys_attached }} key(s) attached, {{ result.skipped }} skipped.
          </p>
          <p v-if="result.failed.length" class="mt-1 text-red-700 dark:text-red-300">
            {{ result.failed.length }} failed:
            <span v-for="failure in result.failed" :key="failure.fingerprint">
              {{ failure.name }} ({{ failure.error }})
            </span>
          </p>
          <p class="mt-2">
            <RouterLink :to="{ name: 'home' }" class="underline">Back to the hierarchy</RouterLink>
          </p>
        </div>
      </section>
    </div>

    <section
      class="rounded-lg border p-4 text-xs"
      :style="{ backgroundColor: 'var(--surface-card)', borderColor: 'var(--border-subtle)' }"
    >
      <h2 class="mb-2 text-sm font-semibold">What can be imported</h2>
      <ul class="mb-3 list-inside list-disc space-y-1" :style="{ color: 'var(--text-secondary)' }">
        <li v-for="item in formats.supported" :key="item">{{ item }}</li>
      </ul>
      <p class="mb-1 font-medium">Not supported</p>
      <ul class="list-inside list-disc space-y-1" :style="{ color: 'var(--text-secondary)' }">
        <li v-for="item in formats.unsupported" :key="item">{{ item }}</li>
      </ul>
      <p class="mt-3 rounded bg-amber-500/15 px-2 py-1 text-amber-800 dark:text-amber-200">
        An imported private key is as sensitive as a generated one. If the CA you
        import is already trusted by clients, whoever can sign with it can
        impersonate those services — and private keys leave this application only
        as a password-protected PKCS#12 bundle.
      </p>
    </section>
  </div>

  <VaultUnlockDialog
    :open="unlockOpen"
    :busy="busy"
    :reason="unlockReason"
    @close="unlockOpen = false"
    @unlocked="onUnlocked"
  />
</template>
