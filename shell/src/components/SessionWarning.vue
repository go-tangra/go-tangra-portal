<script setup lang="ts">
// Asks an idle person whether to stay signed in before their session ends.
import { computed } from 'vue'
import { UiDialog, UiButton } from '@go-tangra/ui'
import { keeper } from '@/session'

const emit = defineEmits<{ signOut: [] }>()
const left = computed(() => {
  const s = Math.max(0, keeper.state.secondsLeft)
  return Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0')
})
</script>

<template>
  <UiDialog :model-value="keeper.state.warning" title="Still there?" size="sm" persistent hide-close data-test="session-warning">
    <p>Your session ends in <strong class="tabular-nums" data-test="session-warning-left">{{ left }}</strong> because of inactivity.</p>
    <template #actions>
      <UiButton variant="text" data-test="session-warning-signout" @click="emit('signOut')">Sign out</UiButton>
      <UiButton data-test="session-warning-stay" @click="keeper.stay()">Stay signed in</UiButton>
    </template>
  </UiDialog>
</template>
