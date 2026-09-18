<script setup>
/**
 * Certificate hierarchy, and the owner of every destructive action dialog.
 *
 * Keeping the dialogs here (rather than inside each card) means one instance
 * handles all certificates, and the target is always explicit.
 */
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import CertificateTree from '@/components/CertificateTree.vue'
import ConfirmActionDialog from '@/components/ConfirmActionDialog.vue'
import Pkcs12Dialog from '@/components/Pkcs12Dialog.vue'
import { useAuthStore } from '@/stores/auth'
import { useCertificatesStore } from '@/stores/certificates'
import { useToastStore } from '@/stores/toasts'
import { files } from '@/api'
import { ApiError } from '@/api/client'

const auth = useAuthStore()
const certificates = useCertificatesStore()
const toasts = useToastStore()
const router = useRouter()

const busy = ref(false)
const actionTarget = ref(null)
const actionKind = ref('revoke')       // 'revoke' | 'delete'
const actionOpen = ref(false)
const p12Target = ref(null)
const p12Open = ref(false)
const query = ref('')

const dialogCertificate = computed(() => {
  if (!actionTarget.value) return null
  return certificates.find(actionTarget.value.kind, actionTarget.value.id) || actionTarget.value
})

/** Client-side filter over names, SANs, serials and owners. */
const filteredTree = computed(() => {
  const needle = query.value.trim().toLowerCase()
  if (!needle) return certificates.tree

  const matches = (cert) => {
    const haystack = [
      cert.name, cert.serial_number, cert.owner,
      ...(cert.sans || []),
    ].filter(Boolean).join(' ').toLowerCase()
    return haystack.includes(needle)
  }

  const out = []
  for (const node of certificates.tree) {
    const intermediates = []
    for (const branch of node.intermediates) {
      const leaves = branch.leaves.filter(matches)
      if (matches(branch.certificate) || leaves.length) {
        intermediates.push({ certificate: branch.certificate, leaves })
      }
    }
    if (matches(node.certificate) || intermediates.length) {
      out.push({ certificate: node.certificate, intermediates })
    }
  }
  return out
})

const totalCount = computed(() => certificates.flat.length)

onMounted(async () => {
  try {
    await certificates.load()
  } catch (err) {
    toasts.error(`Could not load certificates: ${err.message}`)
  }
})

function openAction(kind, certificate) {
  if (!auth.isAuthenticated) {
    router.push({ name: 'login', query: { next: '/' } })
    return
  }
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
      // The API validates the body against RevokeForm, which requires the
      // target (type + id) to agree with the URL -- that is what stops a stale
      // dialog from revoking the wrong certificate.
      const result = await certificates.revoke(target.kind, target.id, {
        type: target.kind,
        id: String(target.id),
        reason: payload.reason,
        comment: payload.comment || '',
        cascade: payload.cascade ? '1' : '',
      })
      const extra = result.cascaded?.length
        ? ` ${result.cascaded.length} certificate(s) signed by it were revoked too.`
        : ''
      toasts.success(`Certificate "${result.revoked}" revoked.${extra}`)
    } else {
      const result = await certificates.remove(target.kind, target.id)
      const extra = result.cascaded
        ? ` ${result.cascaded} dependent certificate(s) were deleted too.`
        : ''
      toasts.success(`Certificate "${result.deleted}" deleted.${extra}`)
    }
    actionOpen.value = false
    actionTarget.value = null
  } catch (err) {
    const message = err instanceof ApiError ? err.message : String(err)
    toasts.error(message)
  } finally {
    busy.value = false
  }
}

async function doDownload(kind, certificate) {
  try {
    if (kind === 'public') {
      await files.publicPem(certificate.serial_number, certificate.name)
    } else if (kind === 'private') {
      await files.privatePem(certificate.serial_number, certificate.name)
      toasts.info(`Private key for "${certificate.name}" downloaded.`)
    }
  } catch (err) {
    toasts.error(err instanceof ApiError ? err.message : String(err))
  }
}

function openPkcs12(certificate) {
  p12Target.value = certificate
  p12Open.value = true
}

async function exportPkcs12(password) {
  const target = p12Target.value
  if (!target) return
  busy.value = true
  try {
    await files.pkcs12(target.serial_number, target.name, password)
    toasts.success(`PKCS12 bundle for "${target.name}" downloaded.`)
    p12Open.value = false
  } catch (err) {
    toasts.error(err instanceof ApiError ? err.message : String(err))
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div>
    <div class="mb-4 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 class="text-2xl font-semibold">Certificate Hierarchy</h1>
        <p class="mt-1 text-sm" :style="{ color: 'var(--text-secondary)' }">
          {{ totalCount }} certificate(s) across
          {{ certificates.tree.length }} root(s).
        </p>
      </div>

      <div class="flex flex-wrap items-center gap-2">
        <input
          v-model="query"
          type="search"
          placeholder="Filter by name, SAN, serial or owner"
          data-testid="certificate-filter"
          class="w-64 rounded border px-3 py-2 text-sm"
          :style="{ backgroundColor: 'var(--surface-sunken)', borderColor: 'var(--border-subtle)', color: 'var(--text-primary)' }"
        />
        <button
          type="button"
          class="rounded border px-3 py-2 text-sm transition"
          :style="{ borderColor: 'var(--border-strong)', color: 'var(--text-primary)' }"
          @click="certificates.load()"
        >
          Refresh
        </button>
      </div>
    </div>

    <p
      v-if="!auth.isAuthenticated"
      class="mb-4 rounded px-4 py-3 text-sm"
      :style="{ backgroundColor: 'var(--surface-accent)', color: 'var(--text-primary)' }"
    >
      <RouterLink :to="{ name: 'login' }" class="font-medium underline">Log in</RouterLink>
      to create, revoke or delete certificates.
    </p>

    <div v-if="certificates.loading" class="py-10 text-center text-sm" :style="{ color: 'var(--text-secondary)' }">
      Loading certificates...
    </div>

    <div v-else-if="certificates.isEmpty" class="rounded border px-4 py-8 text-center text-sm"
         :style="{ borderColor: 'var(--border-subtle)', color: 'var(--text-secondary)' }">
      No certificates yet.
      <template v-if="auth.isAuthenticated">
        Start by creating a
        <RouterLink :to="{ name: 'create-ca' }" class="font-medium underline">root CA</RouterLink>.
      </template>
    </div>

    <div v-else-if="!filteredTree.length" class="py-8 text-center text-sm" :style="{ color: 'var(--text-secondary)' }">
      No certificate matches "{{ query }}".
    </div>

    <CertificateTree
      v-else
      :tree="filteredTree"
      @download-public="(c) => doDownload('public', c)"
      @download-private="(c) => doDownload('private', c)"
      @export-pkcs12="openPkcs12"
      @revoke="(c) => openAction('revoke', c)"
      @delete="(c) => openAction('delete', c)"
    />

    <ConfirmActionDialog
      :open="actionOpen"
      :action="actionKind"
      :certificate="dialogCertificate"
      :busy="busy"
      @close="actionOpen = false"
      @confirm="confirmAction"
    />

    <Pkcs12Dialog
      :open="p12Open"
      :certificate="p12Target"
      :busy="busy"
      @close="p12Open = false"
      @export="exportPkcs12"
    />
  </div>
</template>
