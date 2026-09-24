<script setup lang="ts">
import { UiCard } from '@go-tangra/ui'
</script>

<template>
  <UiCard role="alert" class="mx-auto max-w-lg text-center">
    <h1 class="mb-2 text-xl font-semibold">Page not found</h1>
    <RouterLink to="/" class="btn btn-text" data-test="home">Back to home</RouterLink>
  </UiCard>
</template>
