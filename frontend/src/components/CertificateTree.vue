<script setup>
/**
 * The full certificate hierarchy: roots, their intermediates, and each
 * intermediate's leaves. Pure presentation; the parent owns the dialogs.
 *
 * Each root is a sunken panel; the cards inside it are the levels. The
 * indentation and the left rule on a nested card are what make the depth
 * readable, and both live in `CertificateCard`.
 */
import { useI18n } from 'vue-i18n'
import CertificateCard from '@/components/CertificateCard.vue'

defineProps({
  tree: { type: Array, required: true },
})

// The tree is a pass-through: every event a card raises is re-emitted upward,
// so the page that owns the behaviour is the only place that knows about it.
const emit = defineEmits(['download', 'revoke', 'delete'])

const { t } = useI18n()
</script>

<template>
  <div class="space-y-6">
    <section
      v-for="node in tree"
      :key="`root-${node.certificate.id}`"
      class="rounded-xl border border-slate-200 bg-slate-50 p-3 sm:p-4 dark:border-slate-800 dark:bg-slate-950/50"
    >
      <CertificateCard
        :certificate="node.certificate"
        :depth="0"
        @download="emit('download', $event)"
        @revoke="emit('revoke', $event)"
        @delete="emit('delete', $event)"
      />

      <div v-if="node.intermediates.length" class="mt-3 space-y-4">
        <div v-for="branch in node.intermediates" :key="`int-${branch.certificate.id}`">
          <CertificateCard
            :certificate="branch.certificate"
            :depth="1"
            @download="emit('download', $event)"
            @revoke="emit('revoke', $event)"
            @delete="emit('delete', $event)"
          />

          <div v-if="branch.leaves.length" class="mt-2">
            <CertificateCard
              v-for="leaf in branch.leaves"
              :key="`leaf-${leaf.id}`"
              :certificate="leaf"
              :depth="2"
              @download="emit('download', $event)"
              @revoke="emit('revoke', $event)"
              @delete="emit('delete', $event)"
            />
          </div>
          <p
            v-else
            class="ms-12 mt-2 text-xs text-slate-500 dark:text-slate-400"
          >
            {{ t('home.tree.emptyLeaves') }}
          </p>
        </div>
      </div>
      <p
        v-else
        class="ms-6 mt-2 text-xs text-slate-500 dark:text-slate-400"
      >
        {{ t('home.tree.emptyIntermediates') }}
      </p>
    </section>
  </div>
</template>
