<script setup lang="ts">
import { UiToast, UiConfirm } from '@go-tangra/ui'
</script>

<template>
  <main class="flex min-h-screen items-center justify-center bg-base-200 p-4">
    <div class="w-full max-w-[560px] [&_.card-body]:p-6 sm:[&_.card-body]:p-8"><slot /></div>
    <UiToast />
    <UiConfirm />
  </main>
</template>
