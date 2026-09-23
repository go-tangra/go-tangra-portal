<script setup lang="ts">
import { UiErrorState } from '@freya/ui'
defineProps<{ module: string; retry?: () => void }>()
</script>

<template>
  <UiErrorState :title="`The ${module} module is unavailable`" text="The rest of the platform keeps working." data-test="module-error" @retry="retry?.()" />
</template>
