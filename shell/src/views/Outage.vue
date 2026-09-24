<script setup lang="ts">
import { useRouter } from 'vue-router'
import { UiCard, UiIcon, UiButton } from '@go-tangra/ui'
import { useSession } from '@/stores/session'

const router = useRouter()
const session = useSession()

async function retry(): Promise<void> {
  await session.load(true)
  if (session.status !== 'outage') await router.replace('/')
}
</script>

<template>
  <UiCard role="alert" aria-live="assertive" class="text-center">
    <UiIcon name="mdi-cloud-off-outline" size="xl" class="mx-auto mb-3 text-warning" />
    <h1 class="mb-1 text-xl font-semibold">The platform is temporarily unavailable</h1>
    <p class="mb-5 text-base-content/70">Your work is not lost. Try again in a moment.</p>
    <UiButton data-test="retry" @click="retry">Try again</UiButton>
  </UiCard>
</template>
