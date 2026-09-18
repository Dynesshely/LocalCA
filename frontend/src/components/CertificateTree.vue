<script setup>
/**
 * The full certificate hierarchy: roots, their intermediates, and each
 * intermediate's leaves. Pure presentation; the parent owns the dialogs.
 */
import CertificateCard from '@/components/CertificateCard.vue'

defineProps({
  tree: { type: Array, required: true },
})

const emit = defineEmits([
  'download-public', 'download-private', 'export-pkcs12', 'revoke', 'delete',
])
</script>

<template>
  <div class="space-y-6">
    <section
      v-for="node in tree"
      :key="`root-${node.certificate.id}`"
      class="rounded-xl border p-3 sm:p-4"
      :style="{ backgroundColor: 'var(--surface-raised)', borderColor: 'var(--border-subtle)' }"
    >
      <CertificateCard
        :certificate="node.certificate"
        :depth="0"
        @download-public="emit('download-public', $event)"
        @download-private="emit('download-private', $event)"
        @export-pkcs12="emit('export-pkcs12', $event)"
        @revoke="emit('revoke', $event)"
        @delete="emit('delete', $event)"
      />

      <div v-if="node.intermediates.length" class="mt-3 space-y-4">
        <div v-for="branch in node.intermediates" :key="`int-${branch.certificate.id}`">
          <CertificateCard
            :certificate="branch.certificate"
            :depth="1"
            @download-public="emit('download-public', $event)"
            @download-private="emit('download-private', $event)"
            @export-pkcs12="emit('export-pkcs12', $event)"
            @revoke="emit('revoke', $event)"
            @delete="emit('delete', $event)"
          />

          <div v-if="branch.leaves.length" class="mt-2">
            <CertificateCard
              v-for="leaf in branch.leaves"
              :key="`leaf-${leaf.id}`"
              :certificate="leaf"
              :depth="2"
              @download-public="emit('download-public', $event)"
              @download-private="emit('download-private', $event)"
              @export-pkcs12="emit('export-pkcs12', $event)"
              @revoke="emit('revoke', $event)"
              @delete="emit('delete', $event)"
            />
          </div>
          <p
            v-else
            class="ms-6 mt-2 text-xs"
            :style="{ color: 'var(--text-secondary)' }"
          >
            No leaf certificates signed by this intermediate yet.
          </p>
        </div>
      </div>
      <p
        v-else
        class="ms-6 mt-2 text-xs"
        :style="{ color: 'var(--text-secondary)' }"
      >
        No intermediate CAs signed by this root yet.
      </p>
    </section>
  </div>
</template>
