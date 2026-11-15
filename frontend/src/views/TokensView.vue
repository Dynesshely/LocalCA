<script setup>
/**
 * Personal access tokens: the credentials scripts, API clients and MCP servers
 * use instead of a browser session.
 *
 * The plaintext token exists only in the response to create. It is kept in a
 * local ref long enough to be copied, and never written to the store -- so
 * closing the dialog really is the end of it, which is what the warning says.
 */
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import AppIcon from '@/components/AppIcon.vue'
import AppModal from '@/components/AppModal.vue'
import FormField from '@/components/FormField.vue'
import { ApiError } from '@/api/client'
import { useTokensStore } from '@/stores/tokens'
import { useToastStore } from '@/stores/toasts'
import { formatDateTime } from '@/utils/date'

const { t } = useI18n()
const tokensStore = useTokensStore()
const toasts = useToastStore()

/** Which modal is up: 'create' | 'revoke' | null. */
const dialog = ref(null)
const revokeTarget = ref(null)
const createName = ref('')
/** The response to POST /api/tokens/: the one and only copy of the token. */
const created = ref(null)
const copied = ref(false)
const busy = ref(false)
const localError = ref('')

onMounted(tokensStore.load)

const statusClass = {
  active: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200',
  revoked: 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-200',
}

const statusOf = (token) => (token.revoked_at ? 'revoked' : 'active')

function openCreate() {
  dialog.value = 'create'
  createName.value = ''
  created.value = null
  copied.value = false
  localError.value = ''
}

function askRevoke(token) {
  dialog.value = 'revoke'
  revokeTarget.value = token
  localError.value = ''
}

function resetDialog() {
  dialog.value = null
  revokeTarget.value = null
  createName.value = ''
  created.value = null
  copied.value = false
  localError.value = ''
}

function closeDialog() {
  // A request in flight would otherwise be answered into a closed dialog, and
  // for create that answer is the only copy of the token.
  if (busy.value) {
    return
  }
  resetDialog()
}

/** ApiError already unwraps the server's errors array into its message. */
const messageOf = (err) => (err instanceof ApiError ? err.message : String(err))

async function submitCreate() {
  const name = createName.value.trim()
  if (!name) {
    return
  }
  busy.value = true
  localError.value = ''
  try {
    created.value = await tokensStore.create(name)
    copied.value = false
    toasts.success(t('tokens.done.created', { name }))
  } catch (err) {
    localError.value = messageOf(err)
  } finally {
    busy.value = false
  }
}

async function submitRevoke() {
  busy.value = true
  localError.value = ''
  try {
    await tokensStore.revoke(revokeTarget.value.id)
    toasts.success(t('tokens.done.revoked', { name: revokeTarget.value.name }))
    // The request is done, so bypass closeDialog's in-flight guard.
    resetDialog()
  } catch (err) {
    localError.value = messageOf(err)
  } finally {
    busy.value = false
  }
}

/**
 * Copy through the async Clipboard API where it exists, and through a hidden
 * textarea otherwise: a LAN deployment is plain HTTP, which is not a secure
 * context, so navigator.clipboard is undefined there.
 */
function legacyCopy(text) {
  const area = document.createElement('textarea')
  area.value = text
  area.setAttribute('readonly', '')
  area.style.position = 'fixed'
  area.style.opacity = '0'
  document.body.appendChild(area)
  area.select()
  let ok = false
  try {
    ok = document.execCommand('copy')
  } catch (err) {
    ok = false
  }
  document.body.removeChild(area)
  return ok
}

async function copyToken() {
  const text = created.value?.token || ''
  if (!text) {
    return
  }
  let ok = false
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text)
      ok = true
    } catch (err) {
      // Permission denied or no transient activation: fall through.
    }
  }
  if (!ok) {
    ok = legacyCopy(text)
  }
  if (ok) {
    copied.value = true
    toasts.success(t('tokens.copyOk'))
  } else {
    toasts.error(t('tokens.copyFailed'))
  }
}
</script>

<template>
  <div class="space-y-6">
    <p class="text-sm text-slate-600 dark:text-slate-300">{{ t('tokens.subtitle') }}</p>

    <!-- What a token is for, and the one header it goes in. -->
    <section class="rounded-xl border border-slate-200 bg-white px-4 py-3 dark:border-slate-800 dark:bg-slate-900">
      <h2 class="text-sm font-semibold text-slate-900 dark:text-slate-100">
        {{ t('tokens.usage.heading') }}
      </h2>
      <p class="mt-1 text-sm text-slate-600 dark:text-slate-300">{{ t('tokens.usage.body') }}</p>
      <code class="mt-2 inline-block rounded-lg bg-slate-100 px-2 py-1 font-mono text-xs text-slate-700 dark:bg-slate-800 dark:text-slate-200">
        Authorization: Bearer &lt;token&gt;
      </code>
      <p class="mt-2 text-xs text-slate-500 dark:text-slate-400">{{ t('tokens.usage.mcp') }}</p>
    </section>

    <!-- The list -->
    <section class="rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
      <header class="flex flex-wrap items-center gap-2 border-b border-slate-200 px-4 py-3 dark:border-slate-800">
        <h2 class="text-sm font-semibold text-slate-900 dark:text-slate-100">
          {{ t('tokens.list.heading') }}
        </h2>
        <p class="text-xs text-slate-500 dark:text-slate-400">{{ t('tokens.prefixHint') }}</p>
        <button
          type="button"
          class="ml-auto flex items-center gap-1.5 rounded-lg bg-brand-700 px-2.5 py-1 text-xs font-medium text-white transition hover:bg-brand-600"
          data-testid="tokens-create"
          @click="openCreate"
        >
          <AppIcon name="key" class="size-3.5" />
          {{ t('tokens.create') }}
        </button>
      </header>

      <p
        v-if="tokensStore.loading && !tokensStore.items.length"
        class="px-4 py-6 text-sm text-slate-500 dark:text-slate-400"
      >
        {{ t('common.state.loading') }}
      </p>
      <div
        v-else-if="tokensStore.error"
        class="flex flex-wrap items-center gap-3 px-4 py-6 text-sm text-red-700 dark:text-red-300"
      >
        <p>{{ t('tokens.loadFailed', { message: tokensStore.error }) }}</p>
        <button
          type="button"
          class="rounded-lg border border-slate-300 bg-white px-2.5 py-1 text-xs font-medium text-slate-700 transition hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700"
          @click="tokensStore.load()"
        >
          {{ t('common.action.retry') }}
        </button>
      </div>
      <p
        v-else-if="tokensStore.isEmpty"
        class="px-4 py-6 text-sm text-slate-500 dark:text-slate-400"
        data-testid="tokens-empty"
      >
        {{ t('tokens.empty') }}
      </p>

      <div v-else class="overflow-x-auto">
        <table class="w-full text-left text-sm">
          <thead class="text-xs tracking-wide text-slate-500 uppercase dark:text-slate-400">
            <tr>
              <th class="px-4 py-2 font-medium">{{ t('tokens.column.name') }}</th>
              <th class="px-4 py-2 font-medium">{{ t('tokens.column.prefix') }}</th>
              <th class="px-4 py-2 font-medium">{{ t('tokens.column.created') }}</th>
              <th class="px-4 py-2 font-medium">{{ t('tokens.column.lastUsed') }}</th>
              <th class="px-4 py-2 font-medium">{{ t('tokens.column.status') }}</th>
              <th class="px-4 py-2 font-medium">{{ t('tokens.column.actions') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="token in tokensStore.items"
              :key="token.id"
              class="border-t border-slate-200 dark:border-slate-800"
              :data-testid="'token-row-' + token.id"
            >
              <td class="px-4 py-2 font-medium text-slate-900 dark:text-slate-100">
                {{ token.name }}
              </td>
              <td class="px-4 py-2 font-mono text-xs text-slate-600 dark:text-slate-300">
                {{ token.prefix }}
              </td>
              <td class="whitespace-nowrap px-4 py-2 text-slate-600 dark:text-slate-300">
                {{ formatDateTime(token.created_at) }}
              </td>
              <td class="whitespace-nowrap px-4 py-2 text-slate-600 dark:text-slate-300">
                {{ token.last_used_at ? formatDateTime(token.last_used_at) : t('tokens.never') }}
              </td>
              <td class="px-4 py-2">
                <span
                  class="inline-block rounded-full px-2 py-0.5 text-xs font-medium"
                  :class="statusClass[statusOf(token)]"
                >
                  {{ t('tokens.status.' + statusOf(token)) }}
                </span>
                <span
                  v-if="token.revoked_at"
                  class="mt-1 block text-xs text-slate-500 dark:text-slate-400"
                >
                  {{ t('tokens.revokedAt', { when: formatDateTime(token.revoked_at) }) }}
                </span>
              </td>
              <td class="px-4 py-2">
                <button
                  v-if="!token.revoked_at"
                  type="button"
                  class="rounded-lg border border-red-300 bg-white px-2 py-1 text-xs font-medium text-red-700 transition hover:bg-red-50 dark:border-red-800 dark:bg-slate-900 dark:text-red-300 dark:hover:bg-red-950/40"
                  :data-testid="'token-revoke-' + token.id"
                  @click="askRevoke(token)"
                >
                  {{ t('tokens.revoke') }}
                </button>
                <span v-else class="text-slate-400 dark:text-slate-500">—</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <!-- Create, then reveal the one-time token in the same dialog -->
    <AppModal
      :open="dialog === 'create'"
      :title="created ? t('tokens.created.title') : t('tokens.createTitle')"
      :tone="created ? 'warning' : 'neutral'"
      :close-on-backdrop="false"
      @close="closeDialog"
    >
      <template v-if="created">
        <p class="rounded-lg border-l-4 border-amber-500 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:bg-amber-950/40 dark:text-amber-200">
          {{ t('tokens.created.warning') }}
        </p>
        <p class="mt-3 text-sm text-slate-600 dark:text-slate-300">{{ t('tokens.created.body') }}</p>
        <div class="mt-3 rounded-lg border border-slate-300 bg-slate-50 px-3 py-2 dark:border-slate-700 dark:bg-slate-950">
          <code
            class="block font-mono text-xs break-all text-slate-900 select-all dark:text-slate-100"
            data-testid="token-value"
          >
            {{ created.token }}
          </code>
        </div>
        <div class="mt-4 flex justify-end gap-2">
          <button
            type="button"
            class="flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-medium text-slate-700 transition hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700"
            data-testid="token-copy"
            @click="copyToken"
          >
            <AppIcon v-if="copied" name="check" class="size-4" />
            {{ copied ? t('tokens.created.copied') : t('tokens.created.copy') }}
          </button>
          <button
            type="button"
            class="rounded-lg bg-brand-700 px-3 py-2 text-sm font-medium text-white transition hover:bg-brand-600"
            data-testid="token-done"
            @click="closeDialog"
          >
            {{ t('tokens.created.done') }}
          </button>
        </div>
      </template>

      <form v-else class="space-y-3" @submit.prevent="submitCreate">
        <FormField
          id="token-name"
          v-model="createName"
          :label="t('tokens.nameLabel')"
          :placeholder="t('tokens.namePlaceholder')"
          :help="t('tokens.nameHelp')"
          required
          autofocus
        />
        <p v-if="localError" class="text-sm text-red-600 dark:text-red-400">{{ localError }}</p>
        <div class="flex justify-end gap-2">
          <button
            type="button"
            class="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-medium text-slate-700 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
            :disabled="busy"
            @click="closeDialog"
          >
            {{ t('common.action.cancel') }}
          </button>
          <button
            type="submit"
            class="rounded-lg bg-brand-700 px-3 py-2 text-sm font-medium text-white transition hover:bg-brand-600 disabled:cursor-not-allowed disabled:opacity-60"
            :disabled="busy || !createName.trim()"
            data-testid="token-create-submit"
          >
            {{ busy ? t('common.state.working') : t('tokens.createSubmit') }}
          </button>
        </div>
      </form>
    </AppModal>

    <!-- Revoke -->
    <AppModal
      :open="dialog === 'revoke'"
      :title="t('tokens.revokeTitle', { name: revokeTarget?.name || '' })"
      tone="danger"
      :close-on-backdrop="false"
      @close="closeDialog"
    >
      <p class="text-sm text-slate-600 dark:text-slate-300">{{ t('tokens.revokeBody') }}</p>
      <p class="mt-4 rounded-lg border-l-4 border-red-500 bg-red-50 px-3 py-2 text-sm text-red-900 dark:bg-red-950/40 dark:text-red-200">
        {{ t('tokens.revokeWarning') }}
      </p>
      <p v-if="localError" class="mt-3 text-sm text-red-600 dark:text-red-400">{{ localError }}</p>
      <div class="mt-4 flex justify-end gap-2">
        <button
          type="button"
          class="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-medium text-slate-700 transition hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700"
          :disabled="busy"
          @click="closeDialog"
        >
          {{ t('common.action.cancel') }}
        </button>
        <button
          type="button"
          class="rounded-lg bg-red-600 px-3 py-2 text-sm font-medium text-white transition hover:bg-red-500 disabled:opacity-60"
          :disabled="busy"
          data-testid="token-revoke-submit"
          @click="submitRevoke"
        >
          {{ busy ? t('common.state.working') : t('tokens.revokeSubmit') }}
        </button>
      </div>
    </AppModal>
  </div>
</template>
