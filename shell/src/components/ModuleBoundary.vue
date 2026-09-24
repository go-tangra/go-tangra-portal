<script setup lang="ts">
import { computed, onErrorCaptured, ref } from 'vue'
import { UiAlert, UiRemoteBoundary } from '@go-tangra/ui'
import { useRegistry } from '@/stores/registry'

// Isolates one federated module on top of the kit's boundary: a render or load
// failure shows the module's error state (retry) in its area only, an outage
// reported by the gateway shows a status alert; the shell and the other
// modules keep working.
// silent: a header slot shows nothing instead of the error card (never breaks the app bar).
const props = defineProps<{ module: string; silent?: boolean }>()
const failed = ref(false)
const attempt = ref(0)
const registry = useRegistry()
const down = computed(() => registry.unavailable(props.module))

// Only silent slots are caught here; the kit boundary handles (and stops) the rest.
onErrorCaptured((err) => {
  if (!props.silent) return true
  console.error(`[shell] module ${props.module} failed: ${err instanceof Error ? err.message : String(err)}`)
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
  <span v-else-if="silent" :key="attempt" :data-module="module" class="freya-header-slot"><slot /></span>
  <UiAlert v-else-if="down" kind="warning" role="status" data-test="module-outage" :title="`The ${module} module is temporarily unavailable`">
    It will reappear here automatically as soon as it recovers.
  </UiAlert>
  <UiRemoteBoundary v-else :key="attempt" :module="module" data-test="module-error" @retry="retry">
    <div :data-module="module"><slot /></div>
  </UiRemoteBoundary>
</template>
