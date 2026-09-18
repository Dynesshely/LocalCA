<script setup>
/**
 * Labelled form control with inline error display, matching the field-level
 * validation feedback the API returns.
 */
import { computed } from 'vue'

const props = defineProps({
  modelValue: { type: [String, Number], default: '' },
  label: { type: String, required: true },
  id: { type: String, required: true },
  type: { type: String, default: 'text' },
  required: { type: Boolean, default: false },
  placeholder: { type: String, default: '' },
  help: { type: String, default: '' },
  error: { type: String, default: '' },
  min: { type: [String, Number], default: undefined },
  max: { type: [String, Number], default: undefined },
  autocomplete: { type: String, default: undefined },
  autofocus: { type: Boolean, default: false },
})

const emit = defineEmits(['update:modelValue'])

const value = computed({
  get: () => props.modelValue,
  set: (v) => emit('update:modelValue', v),
})

const inputStyle = {
  backgroundColor: 'var(--surface-sunken)',
  borderColor: 'var(--border-subtle)',
  color: 'var(--text-primary)',
}
</script>

<template>
  <div>
    <label :for="id" class="mb-1 block text-sm font-medium">
      {{ label }}
      <span v-if="!required" class="font-normal" :style="{ color: 'var(--text-secondary)' }">(optional)</span>
    </label>
    <input
      :id="id"
      v-model="value"
      :type="type"
      :required="required"
      :placeholder="placeholder"
      :min="min"
      :max="max"
      :autocomplete="autocomplete"
      :autofocus="autofocus"
      :aria-invalid="error ? 'true' : 'false'"
      :aria-describedby="error ? `${id}-error` : (help ? `${id}-help` : undefined)"
      :data-testid="id"
      class="w-full rounded border px-3 py-2 text-sm disabled:opacity-60"
      :class="error ? 'border-red-500' : ''"
      :style="inputStyle"
    />
    <p v-if="error" :id="`${id}-error`" class="mt-1 text-xs text-red-600 dark:text-red-400">
      {{ error }}
    </p>
    <p v-else-if="help" :id="`${id}-help`" class="mt-1 text-xs" :style="{ color: 'var(--text-secondary)' }">
      {{ help }}
    </p>
  </div>
</template>
