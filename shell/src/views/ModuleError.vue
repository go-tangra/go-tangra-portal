<script setup lang="ts">
defineProps<{ module: string; retry?: () => void }>()
</script>

<template>
  <v-alert type="warning" variant="tonal" role="alert" :title="`The ${module} module is unavailable`" data-test="module-error">
    The rest of the platform keeps working. <v-btn v-if="retry" size="small" variant="text" data-test="module-retry" @click="retry">Retry</v-btn>
  </v-alert>
</template>
