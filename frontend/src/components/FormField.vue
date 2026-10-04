<script setup>
/**
 * Labelled form control with inline error display, matching the field-level
 * validation feedback the API returns.
 *
 * `type="textarea"` renders a multi-line box instead of an input, which is what
 * a field that takes a list (the SAN box) needs: one entry per line is the
 * shape people paste in, and it stays readable as the list grows.
 */
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'

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
  rows: { type: Number, default: 5 },
  autocomplete: { type: String, default: undefined },
  autofocus: { type: Boolean, default: false },
})

const emit = defineEmits(['update:modelValue'])
const { t } = useI18n()

const value = computed({
  get: () => props.modelValue,
  set: (v) => emit('update:modelValue', v),
})

/**
 * The control classes live here rather than in a stylesheet so the whole
 * appearance of every input in the application is one string, and `dark:` sits
 * next to the light value it replaces.
 */
const CONTROL = [
  'w-full rounded-lg border bg-white px-3 py-2 text-sm text-slate-900 shadow-sm transition',
  'placeholder:text-slate-400 disabled:opacity-60',
  'focus:border-brand-500 focus:ring-2 focus:ring-brand-500/25 focus:outline-none',
  'dark:bg-slate-950 dark:text-slate-100 dark:placeholder:text-slate-500',
].join(' ')

const describedBy = computed(() => {
  if (props.error) {
    return `${props.id}-error`
  }
  return props.help ? `${props.id}-help` : undefined
})
</script>

<template>
  <div>
    <label :for="id" class="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-200">
      {{ label }}
      <span v-if="!required" class="font-normal text-slate-400 dark:text-slate-500">
        ({{ t('common.state.optional') }})
      </span>
    </label>

    <textarea
      v-if="type === 'textarea'"
      :id="id"
      v-model="value"
      :required="required"
      :placeholder="placeholder"
      :rows="rows"
      :autofocus="autofocus"
      :aria-invalid="error ? 'true' : 'false'"
      :aria-describedby="describedBy"
      :data-testid="id"
      class="resize-y font-mono leading-relaxed"
      :class="[CONTROL, error ? 'border-red-500 dark:border-red-500' : 'border-slate-300 dark:border-slate-700']"
    />
    <input
      v-else
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
      :aria-describedby="describedBy"
      :data-testid="id"
      :class="[CONTROL, error ? 'border-red-500 dark:border-red-500' : 'border-slate-300 dark:border-slate-700']"
    />

    <p v-if="error" :id="`${id}-error`" class="mt-1.5 text-xs text-red-600 dark:text-red-400">
      {{ error }}
    </p>
    <p v-else-if="help" :id="`${id}-help`" class="mt-1.5 text-xs text-slate-500 dark:text-slate-400">
      {{ help }}
    </p>
  </div>
</template>
