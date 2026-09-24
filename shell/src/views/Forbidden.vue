<script setup lang="ts">
import { UiCard, UiIcon } from '@go-tangra/ui'
</script>

<template>
  <UiCard role="alert" class="mx-auto max-w-lg text-center">
    <UiIcon name="mdi-shield-off-outline" size="xl" class="mx-auto mb-3 text-error" />
    <h1 class="mb-1 text-xl font-semibold">You do not have access to this page</h1>
    <p class="text-base-content/70">Ask an administrator for the required permission.</p>
    <RouterLink to="/" class="btn btn-text mt-4" data-test="home">Back to home</RouterLink>
  </UiCard>
</template>
