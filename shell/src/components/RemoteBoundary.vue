<script setup lang="ts">
import { computed, onErrorCaptured, ref } from 'vue'
import ModuleError from '@/views/ModuleError.vue'
import { useRegistry } from '@/stores/registry'

// Isolates one federated module: a render or load failure, or an outage
// reported by the gateway, shows a card in the module's area only; the shell
// and the other modules keep working.
// silent: a header slot shows nothing instead of the error card (never breaks the app bar).
const props = defineProps<{ module: string; silent?: boolean }>()
const failed = ref(false)
const attempt = ref(0)
const registry = useRegistry()
const down = computed(() => registry.unavailable(props.module))

onErrorCaptured((err) => {
  console.error(`[shell] module ${props.module} failed: ${err instanceof Error ? err.message + ' ' + (err.stack ?? '').split('\n').slice(0, 3).join(' | ') : String(err)}`)
  failed.value = true
  return false
})

function retry(): void {
  failed.value = false
  attempt.value++
}
</script>

<template>
  <span v-if="silent && (failed || down)" :data-test="'header-silent-' + module" hidden />
  <ModuleError v-else-if="failed" :module="module" :retry="retry" />
  <v-alert v-else-if="down" type="warning" variant="tonal" role="status" data-test="module-outage" :title="`The ${module} module is temporarily unavailable`">
    It will reappear here automatically as soon as it recovers.
  </v-alert>
  <component :is="silent ? 'span' : 'div'" v-else :key="attempt" :data-module="module" :class="{ 'freya-header-slot': silent }">
    <slot />
  </component>
</template>
