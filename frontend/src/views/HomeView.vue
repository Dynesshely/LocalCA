<script setup>
/**
 * Certificate hierarchy, and the owner of every destructive action dialog.
 *
 * Keeping the dialogs here (rather than inside each card) means one instance
 * handles all certificates, and the target is always explicit.
 *
 * The page's own heading is gone on purpose: the shell's top bar already shows
 * the route title, so the only line left here is the one that summarizes the
 * hierarchy.
 */
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import CertificateTree from '@/components/CertificateTree.vue'
import ConfirmActionDialog from '@/components/ConfirmActionDialog.vue'
import ExportDialog from '@/components/ExportDialog.vue'
import { useCertificateDownload } from '@/composables/useCertificateDownload'
import { useAuthStore } from '@/stores/auth'
import { useCertificatesStore } from '@/stores/certificates'
import { useKeystoreStore } from '@/stores/keystore'
import { useToastStore } from '@/stores/toasts'
import { ApiError } from '@/api/client'

const { t } = useI18n()
const auth = useAuthStore()
const certificates = useCertificatesStore()
const keystore = useKeystoreStore()
const toasts = useToastStore()
const router = useRouter()

const busy = ref(false)
const actionTarget = ref(null)
const actionKind = ref('revoke')       // 'revoke' | 'delete'
const actionOpen = ref(false)
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
    await Promise.all([certificates.load(), keystore.load()])
  } catch (err) {
    toasts.error(t('common.error.couldNotLoadCertificates', { message: err.message }))
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
      const cascaded = result.cascaded?.length || 0
      const extra = cascaded ? ` ${t('home.revokedCascade', cascaded)}` : ''
      toasts.success(`${t('home.revoked', { name: result.revoked })}${extra}`)
    } else {
      const result = await certificates.remove(target.kind, target.id)
      const extra = result.cascaded
        ? ` ${t('home.deletedCascade', Number(result.cascaded))}`
        : ''
      toasts.success(`${t('home.deleted', { name: result.deleted })}${extra}`)
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

/**
 * Downloads live in a composable: which formats exist, what each one requires
 * (a password, or an explicit confirmation), and the unlock-and-retry dance are
 * the same on every page that lists certificates.
 */
const downloads = useCertificateDownload()

/** The menu emitted `{ certificate, format }`; the composable takes it from here. */
function onDownload({ certificate, format }) {
  downloads.run(certificate, format)
}
</script>

<template>
  <div class="mx-auto w-full max-w-[1400px]">
    <div class="mb-4 flex flex-wrap items-end justify-between gap-3">
      <i18n-t keypath="home.summary.line" tag="p" class="text-sm text-slate-600 dark:text-slate-300">
        <template #certificates>
          <span class="font-semibold text-slate-900 dark:text-slate-100">
            {{ t('home.summary.certificates', totalCount) }}
          </span>
        </template>
        <template #roots>
          <span class="font-semibold text-slate-900 dark:text-slate-100">
            {{ t('home.summary.roots', certificates.tree.length) }}
          </span>
        </template>
      </i18n-t>

      <div class="flex flex-wrap items-center gap-2">
        <input
          v-model="query"
          type="search"
          :placeholder="t('home.filter.placeholder')"
          data-testid="certificate-filter"
          class="w-72 rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 shadow-sm transition placeholder:text-slate-400 focus:border-brand-500 focus:ring-2 focus:ring-brand-500/25 focus:outline-none dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
        />
        <button
          type="button"
          class="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-medium text-slate-700 transition hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700"
          @click="certificates.load()"
        >
          {{ t('common.action.refresh') }}
        </button>
      </div>
    </div>

    <i18n-t
      v-if="!auth.isAuthenticated"
      keypath="home.guestPrompt"
      tag="p"
      class="mb-4 rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-200"
    >
      <template #link>
        <RouterLink :to="{ name: 'login' }" class="font-medium underline">
          {{ t('common.nav.login') }}
        </RouterLink>
      </template>
    </i18n-t>

    <div
      v-if="certificates.loading"
      class="py-10 text-center text-sm text-slate-500 dark:text-slate-400"
    >
      {{ t('common.state.loadingCertificates') }}
    </div>

    <div
      v-else-if="certificates.isEmpty"
      class="rounded-xl border border-dashed border-slate-300 px-4 py-8 text-center text-sm text-slate-500 dark:border-slate-700 dark:text-slate-400"
    >
      <p>{{ t('home.empty.title') }}</p>
      <i18n-t
        v-if="auth.isAuthenticated"
        keypath="home.empty.hint"
        tag="p"
        class="mt-1"
      >
        <template #link>
          <RouterLink :to="{ name: 'create-ca' }" class="font-medium underline">
            {{ t('home.empty.rootCa') }}
          </RouterLink>
        </template>
      </i18n-t>
    </div>

    <div
      v-else-if="!filteredTree.length"
      class="py-8 text-center text-sm text-slate-500 dark:text-slate-400"
    >
      {{ t('home.filter.noMatch', { query }) }}
    </div>

    <CertificateTree
      v-else
      :tree="filteredTree"
      @download="onDownload"
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

    <ExportDialog
      :open="!!downloads.pendingFormat.value"
      :certificate="downloads.pendingCertificate.value"
      :format="downloads.pendingFormat.value || ''"
      :requires="downloads.requires(downloads.pendingFormat.value)"
      :busy="downloads.busy.value || busy"
      @close="downloads.cancel()"
      @confirm="downloads.submit"
    />
  </div>
</template>
