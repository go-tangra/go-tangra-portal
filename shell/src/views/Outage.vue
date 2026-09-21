<script setup lang="ts">
import { useRouter } from 'vue-router'
import { useSession } from '@/stores/session'

const router = useRouter()
const session = useSession()

async function retry(): Promise<void> {
  await session.load(true)
  if (session.status !== 'outage') await router.replace('/')
}
</script>

<template>
  <v-card class="pa-6 text-center" role="alert" aria-live="assertive">
    <v-icon size="48" color="warning" class="mb-4">mdi-cloud-off-outline</v-icon>
    <h1 class="text-h5 mb-2">The platform is temporarily unavailable</h1>
    <p class="text-body-1 mb-6">Your work is not lost. Try again in a moment.</p>
    <v-btn color="primary" data-test="retry" @click="retry">Try again</v-btn>
  </v-card>
</template>
