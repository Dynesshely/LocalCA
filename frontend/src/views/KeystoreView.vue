<script setup>
/**
 * The keystore page: one place to see every private key's state and to manage
 * the named credentials that encrypt them.
 *
 * The page owns no cryptography. It shows what `/api/keystore/` reports -- which
 * credential wraps which key, and whether that credential is currently open --
 * and every action goes through the store, which reloads the inventory so the
 * view can never show a state the server disagrees with.
 */
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import AppIcon from '@/components/AppIcon.vue'
import AppModal from '@/components/AppModal.vue'
import FormField from '@/components/FormField.vue'
import { ApiError } from '@/api/client'
import { useKeystoreStore } from '@/stores/keystore'
import { useToastStore } from '@/stores/toasts'

const { t } = useI18n()
const keystore = useKeystoreStore()
const toasts = useToastStore()

/** Which modal is up, and what it acts on. */
const dialog = ref(null)          // 'rename' | 'rotate' | 'assign' | 'delete'
const target = ref(null)          // the credential or key the modal acts on
const form = ref({ name: '', current: '', next: '', credentialId: null })
const busy = ref(false)
const localError = ref('')

onMounted(keystore.load)

const statusClass = {
  unlocked: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200',
  locked: 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-200',
  plaintext: 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-200',
  orphaned: 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-200',
  unwrappable: 'bg-slate-200 text-slate-700 dark:bg-slate-700 dark:text-slate-200',
  no_key: 'bg-slate-200 text-slate-700 dark:bg-slate-700 dark:text-slate-200',
}

// The same words the hierarchy cards use, so a root is a root everywhere.
const kindLabel = (kind) => t(`home.kind.${kind}`)
const isWrapped = (key) => ['unlocked', 'locked'].includes(key.status)

const cleartextKeys = computed(() => keystore.keys.filter((key) => !isWrapped(key)))

function openAdd() {
  // The shell owns the create dialog; a null id means "there is nothing to open".
  keystore.requestUnlock({ reason: t('keystore.credentials.empty') })
}

function askUnlock(credential) {
  keystore.requestUnlock({
    reason: t('keystore.credentials.unlockTitle', { name: credential.name }),
    credentialId: credential.id,
  })
}

function openDialog(kind, subject) {
  dialog.value = kind
  target.value = subject
  localError.value = ''
  form.value = {
    name: subject?.name || '',
    current: '',
    next: '',
    credentialId: subject?.credential_id || keystore.defaultCredential?.id || null,
  }
}

function closeDialog() {
  dialog.value = null
  target.value = null
  localError.value = ''
}

async function guard(action, done) {
  busy.value = true
  localError.value = ''
  try {
    await action()
    if (done) {
      toasts.success(done)
    }
    closeDialog()
  } catch (err) {
    localError.value = err instanceof ApiError ? err.message : String(err)
  } finally {
    busy.value = false
  }
}

const submitRename = () => guard(
  () => keystore.rename(target.value.id, form.value.name.trim()),
  t('keystore.done.renamed', { name: form.value.name.trim() }))

const submitRotate = () => guard(
  () => keystore.changePassword(target.value.id, form.value.current, form.value.next),
  t('keystore.done.rotated', { name: target.value.name }))

const submitAssign = () => guard(
  () => keystore.assign(form.value.credentialId, target.value.kind, target.value.id),
  t('keystore.done.assigned', {
    name: target.value.name,
    credential: keystore.credentials.find((c) => c.id === form.value.credentialId)?.name || '',
  }))

const submitDelete = () => guard(
  () => keystore.remove(target.value.id),
  t('keystore.done.deleted', { name: target.value.name }))

const lockOne = (credential) => guard(
  () => keystore.lock(credential.id),
  t('keystore.done.locked', { name: credential.name }))

const lockAll = () => guard(() => keystore.lockAll(), t('keystore.done.lockedAll'))

const makeDefault = (credential) => guard(
  () => keystore.setDefault(credential.id),
  t('keystore.done.default', { name: credential.name }))
</script>

<template>
  <div class="space-y-6">
    <p class="text-sm text-slate-600 dark:text-slate-300">{{ t('keystore.subtitle') }}</p>

    <!-- Summary: the honest inventory, in the order an operator worries about it -->
    <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
      <div class="rounded-xl border border-slate-200 bg-white px-4 py-3 dark:border-slate-800 dark:bg-slate-900">
        <p class="text-xs font-medium tracking-wide text-slate-500 uppercase dark:text-slate-400">
          {{ t('keystore.keys.heading') }}
        </p>
        <p class="mt-1 text-lg font-semibold text-slate-900 dark:text-slate-100">
          {{ t('keystore.summary.total', { total: keystore.counts.total || 0 }) }}
        </p>
      </div>
      <div class="rounded-xl border border-slate-200 bg-white px-4 py-3 dark:border-slate-800 dark:bg-slate-900">
        <p class="text-xs font-medium tracking-wide text-slate-500 uppercase dark:text-slate-400">
          {{ t('keystore.credentials.heading') }}
        </p>
        <p class="mt-1 text-lg font-semibold text-slate-900 dark:text-slate-100">
          {{ keystore.credentials.length }}
        </p>
      </div>
      <div class="rounded-xl border border-slate-200 bg-white px-4 py-3 dark:border-slate-800 dark:bg-slate-900">
        <p class="text-xs font-medium tracking-wide text-slate-500 uppercase dark:text-slate-400">
          {{ t('keystore.credentials.unlocked') }}
        </p>
        <p class="mt-1 text-lg font-semibold text-emerald-700 dark:text-emerald-300">
          {{ keystore.counts.unlocked || 0 }}
        </p>
      </div>
      <div class="rounded-xl border border-slate-200 bg-white px-4 py-3 dark:border-slate-800 dark:bg-slate-900">
        <p class="text-xs font-medium tracking-wide text-slate-500 uppercase dark:text-slate-400">
          {{ t('keystore.status.plaintext') }}
        </p>
        <p
          class="mt-1 text-lg font-semibold"
          :class="cleartextKeys.length
            ? 'text-red-700 dark:text-red-300'
            : 'text-slate-900 dark:text-slate-100'"
        >
          {{ cleartextKeys.length }}
        </p>
      </div>
    </div>

    <!-- Credentials -->
    <section class="rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
      <header class="flex flex-wrap items-center gap-2 border-b border-slate-200 px-4 py-3 dark:border-slate-800">
        <h2 class="text-sm font-semibold text-slate-900 dark:text-slate-100">
          {{ t('keystore.credentials.heading') }}
        </h2>
        <p class="text-xs text-slate-500 dark:text-slate-400">
          {{ t('keystore.credentials.defaultHint') }}
        </p>
        <div class="ml-auto flex items-center gap-2">
          <button
            v-if="keystore.credentials.length"
            type="button"
            class="rounded-lg border border-slate-300 bg-white px-2.5 py-1 text-xs font-medium text-slate-700 transition hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700"
            data-testid="keystore-lock-all"
            @click="lockAll"
          >
            {{ t('keystore.credentials.lockAll') }}
          </button>
          <button
            type="button"
            class="flex items-center gap-1.5 rounded-lg bg-brand-700 px-2.5 py-1 text-xs font-medium text-white transition hover:bg-brand-600"
            data-testid="keystore-add"
            @click="openAdd"
          >
            <AppIcon name="key" class="size-3.5" />
            {{ t('keystore.credentials.add') }}
          </button>
        </div>
      </header>

      <p
        v-if="!keystore.credentials.length"
        class="px-4 py-6 text-sm text-slate-500 dark:text-slate-400"
        data-testid="keystore-empty"
      >
        {{ t('keystore.credentials.empty') }}
      </p>

      <div v-else class="overflow-x-auto">
        <table class="w-full text-left text-sm">
          <thead class="text-xs tracking-wide text-slate-500 uppercase dark:text-slate-400">
            <tr>
              <th class="px-4 py-2 font-medium">{{ t('keystore.credentials.name') }}</th>
              <th class="px-4 py-2 font-medium">{{ t('keystore.credentials.state') }}</th>
              <th class="px-4 py-2 font-medium">{{ t('keystore.credentials.keyCount') }}</th>
              <th class="px-4 py-2 font-medium">{{ t('keystore.credentials.actions') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="credential in keystore.credentials"
              :key="credential.id"
              class="border-t border-slate-200 dark:border-slate-800"
              :data-testid="`credential-${credential.id}`"
            >
              <td class="px-4 py-2">
                <span class="font-medium text-slate-900 dark:text-slate-100">
                  {{ credential.name }}
                </span>
                <span
                  v-if="credential.is_default"
                  class="ml-2 rounded-full bg-brand-100 px-2 py-0.5 text-[11px] font-medium text-brand-800 dark:bg-brand-700 dark:text-brand-100"
                  data-testid="credential-default"
                >
                  {{ t('keystore.credentials.default') }}
                </span>
              </td>
              <td class="px-4 py-2">
                <span
                  class="inline-block rounded-full px-2 py-0.5 text-xs font-medium"
                  :class="credential.unlocked
                    ? statusClass.unlocked
                    : statusClass.locked"
                  :data-testid="`credential-state-${credential.id}`"
                >
                  {{ credential.unlocked
                    ? t('keystore.credentials.unlocked')
                    : t('keystore.credentials.locked') }}
                </span>
                <span
                  v-if="credential.unlocked"
                  class="ml-2 text-xs text-slate-500 dark:text-slate-400"
                >
                  {{ t('keystore.credentials.remaining',
                        { seconds: credential.unseal_remaining_seconds }) }}
                </span>
              </td>
              <td class="px-4 py-2 text-slate-600 dark:text-slate-300">
                {{ credential.key_count }}
              </td>
              <td class="px-4 py-2">
                <div class="flex flex-wrap items-center gap-1">
                  <button
                    v-if="!credential.unlocked"
                    type="button"
                    class="rounded-lg border border-slate-300 bg-white px-2 py-1 text-xs font-medium text-slate-700 transition hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700"
                    :data-testid="`credential-unlock-${credential.id}`"
                    @click="askUnlock(credential)"
                  >
                    {{ t('keystore.credentials.unlock') }}
                  </button>
                  <button
                    v-else
                    type="button"
                    class="rounded-lg border border-slate-300 bg-white px-2 py-1 text-xs font-medium text-slate-700 transition hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700"
                    :data-testid="`credential-lock-${credential.id}`"
                    @click="lockOne(credential)"
                  >
                    {{ t('keystore.credentials.lock') }}
                  </button>
                  <button
                    v-if="!credential.is_default"
                    type="button"
                    class="rounded-lg border border-slate-300 bg-white px-2 py-1 text-xs font-medium text-slate-700 transition hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700"
                    :data-testid="`credential-default-${credential.id}`"
                    @click="makeDefault(credential)"
                  >
                    {{ t('keystore.credentials.setDefault') }}
                  </button>
                  <button
                    type="button"
                    class="rounded-lg border border-slate-300 bg-white px-2 py-1 text-xs font-medium text-slate-700 transition hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700"
                    :data-testid="`credential-rename-${credential.id}`"
                    @click="openDialog('rename', credential)"
                  >
                    {{ t('keystore.credentials.rename') }}
                  </button>
                  <button
                    type="button"
                    class="rounded-lg border border-slate-300 bg-white px-2 py-1 text-xs font-medium text-slate-700 transition hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700"
                    :data-testid="`credential-rotate-${credential.id}`"
                    @click="openDialog('rotate', credential)"
                  >
                    {{ t('keystore.credentials.rotate') }}
                  </button>
                  <button
                    type="button"
                    class="rounded-lg border border-red-300 bg-white px-2 py-1 text-xs font-medium text-red-700 transition hover:bg-red-50 dark:border-red-800 dark:bg-slate-900 dark:text-red-300 dark:hover:bg-red-950/40"
                    :data-testid="`credential-delete-${credential.id}`"
                    @click="openDialog('delete', credential)"
                  >
                    {{ t('keystore.credentials.delete') }}
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <!-- Keys -->
    <section class="rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
      <header class="flex items-center gap-2 border-b border-slate-200 px-4 py-3 dark:border-slate-800">
        <h2 class="text-sm font-semibold text-slate-900 dark:text-slate-100">
          {{ t('keystore.keys.heading') }}
        </h2>
      </header>

      <p
        v-if="!keystore.keys.length"
        class="px-4 py-6 text-sm text-slate-500 dark:text-slate-400"
      >
        {{ t('keystore.keys.empty') }}
      </p>

      <div v-else class="overflow-x-auto">
        <table class="w-full text-left text-sm">
          <thead class="text-xs tracking-wide text-slate-500 uppercase dark:text-slate-400">
            <tr>
              <th class="px-4 py-2 font-medium">{{ t('keystore.keys.name') }}</th>
              <th class="px-4 py-2 font-medium">{{ t('keystore.keys.kind') }}</th>
              <th class="px-4 py-2 font-medium">{{ t('keystore.keys.status') }}</th>
              <th class="px-4 py-2 font-medium">{{ t('keystore.keys.credential') }}</th>
              <th class="px-4 py-2 font-medium">{{ t('keystore.keys.actions') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="key in keystore.keys"
              :key="`${key.kind}-${key.id}`"
              class="border-t border-slate-200 dark:border-slate-800"
              :data-testid="`key-row-${key.kind}-${key.id}`"
            >
              <td class="px-4 py-2">
                <span class="font-medium text-slate-900 dark:text-slate-100">{{ key.name }}</span>
                <span class="block font-mono text-xs text-slate-500 dark:text-slate-400">
                  {{ key.serial_number }}
                </span>
              </td>
              <td class="px-4 py-2 text-slate-600 dark:text-slate-300">
                {{ kindLabel(key.kind) }}
              </td>
              <td class="px-4 py-2">
                <span
                  class="inline-block rounded-full px-2 py-0.5 text-xs font-medium"
                  :class="statusClass[key.status]"
                  :data-testid="`key-status-${key.kind}-${key.id}`"
                >
                  {{ t(`keystore.status.${key.status}`) }}
                </span>
              </td>
              <td class="px-4 py-2 text-slate-600 dark:text-slate-300">
                {{ key.credential_name || t('keystore.keys.none') }}
              </td>
              <td class="px-4 py-2">
                <button
                  v-if="keystore.credentials.length"
                  type="button"
                  class="rounded-lg border border-slate-300 bg-white px-2 py-1 text-xs font-medium text-slate-700 transition hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700"
                  :data-testid="`key-assign-${key.kind}-${key.id}`"
                  @click="openDialog('assign', key)"
                >
                  {{ isWrapped(key) ? t('keystore.keys.move') : t('keystore.keys.encrypt') }}
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <p v-if="keystore.counts.locked" class="text-xs text-slate-500 dark:text-slate-400">
      {{ t('keystore.hint.locked') }}
    </p>
    <p v-if="cleartextKeys.length" class="text-xs text-slate-500 dark:text-slate-400">
      {{ t('keystore.hint.plaintext') }}
    </p>

    <!-- Rename -->
    <AppModal
      :open="dialog === 'rename'"
      :title="t('keystore.rename.title')"
      @close="closeDialog"
    >
      <form class="space-y-3" @submit.prevent="submitRename">
        <FormField
          id="credential-rename"
          v-model="form.name"
          :label="t('keystore.rename.label')"
          required
        />
        <p v-if="localError" class="text-sm text-red-600 dark:text-red-400">{{ localError }}</p>
        <div class="flex justify-end gap-2">
          <button
            type="button"
            class="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-medium text-slate-700 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
            @click="closeDialog"
          >
            {{ t('common.action.cancel') }}
          </button>
          <button
            type="submit"
            class="rounded-lg bg-brand-700 px-3 py-2 text-sm font-medium text-white disabled:opacity-60"
            :disabled="busy || !form.name.trim()"
            data-testid="credential-rename-submit"
          >
            {{ t('keystore.rename.submit') }}
          </button>
        </div>
      </form>
    </AppModal>

    <!-- Change password -->
    <AppModal
      :open="dialog === 'rotate'"
      :title="t('keystore.rotate.title', { name: target?.name || '' })"
      @close="closeDialog"
    >
      <p class="text-xs text-slate-500 dark:text-slate-400">{{ t('keystore.rotate.help') }}</p>
      <form class="mt-3 space-y-3" @submit.prevent="submitRotate">
        <FormField
          id="credential-current"
          v-model="form.current"
          type="password"
          :label="t('keystore.rotate.current')"
          required
        />
        <FormField
          id="credential-next"
          v-model="form.next"
          type="password"
          :label="t('keystore.rotate.next')"
          required
        />
        <p v-if="localError" class="text-sm text-red-600 dark:text-red-400">{{ localError }}</p>
        <div class="flex justify-end gap-2">
          <button
            type="button"
            class="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-medium text-slate-700 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
            @click="closeDialog"
          >
            {{ t('common.action.cancel') }}
          </button>
          <button
            type="submit"
            class="rounded-lg bg-brand-700 px-3 py-2 text-sm font-medium text-white disabled:opacity-60"
            :disabled="busy || form.next.length < 8 || !form.current"
            data-testid="credential-rotate-submit"
          >
            {{ t('keystore.rotate.submit') }}
          </button>
        </div>
      </form>
    </AppModal>

    <!-- Assign / move a key -->
    <AppModal
      :open="dialog === 'assign'"
      :title="t(isWrapped(target || {}) ? 'keystore.assign.titleMove'
                                        : 'keystore.assign.title',
                { name: target?.name || '' })"
      @close="closeDialog"
    >
      <p class="text-xs text-slate-500 dark:text-slate-400">{{ t('keystore.assign.body') }}</p>
      <form class="mt-3 space-y-3" @submit.prevent="submitAssign">
        <div>
          <label
            for="assign-credential"
            class="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-200"
          >
            {{ t('keystore.assign.label') }}
          </label>
          <select
            id="assign-credential"
            v-model="form.credentialId"
            data-testid="assign-credential"
            class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
          >
            <option v-for="credential in keystore.credentials" :key="credential.id" :value="credential.id">
              {{ credential.name }}
            </option>
          </select>
        </div>
        <p v-if="localError" class="text-sm text-red-600 dark:text-red-400">{{ localError }}</p>
        <div class="flex justify-end gap-2">
          <button
            type="button"
            class="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-medium text-slate-700 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
            @click="closeDialog"
          >
            {{ t('common.action.cancel') }}
          </button>
          <button
            type="submit"
            class="rounded-lg bg-brand-700 px-3 py-2 text-sm font-medium text-white disabled:opacity-60"
            :disabled="busy || !form.credentialId"
            data-testid="assign-submit"
          >
            {{ t(isWrapped(target || {}) ? 'keystore.assign.submitMove'
                                          : 'keystore.assign.submit') }}
          </button>
        </div>
      </form>
    </AppModal>

    <!-- Delete -->
    <AppModal
      :open="dialog === 'delete'"
      :title="t('keystore.credentials.deleteTitle', { name: target?.name || '' })"
      @close="closeDialog"
    >
      <p class="text-sm text-slate-600 dark:text-slate-300">
        {{ t('keystore.credentials.deleteBody') }}
      </p>
      <p v-if="localError" class="mt-3 text-sm text-red-600 dark:text-red-400">{{ localError }}</p>
      <div class="mt-4 flex justify-end gap-2">
        <button
          type="button"
          class="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-medium text-slate-700 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
          @click="closeDialog"
        >
          {{ t('common.action.cancel') }}
        </button>
        <button
          type="button"
          class="rounded-lg bg-red-600 px-3 py-2 text-sm font-medium text-white transition hover:bg-red-500 disabled:opacity-60"
          :disabled="busy"
          data-testid="credential-delete-submit"
          @click="submitDelete"
        >
          {{ t('keystore.credentials.delete') }}
        </button>
      </div>
    </AppModal>
  </div>
</template>
