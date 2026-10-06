<script setup lang="ts">
import { computed, onMounted, onUnmounted } from 'vue'
import { useRoute } from 'vue-router'
import { useSession } from '@/stores/session'
import { watchSessionExpiry } from '@/session'
import Default from '@/layouts/Default.vue'
import Bare from '@/layouts/Bare.vue'

const route = useRoute()
const session = useSession()
const layout = computed(() => (route.meta.layout === 'bare' ? Bare : Default))
let unbind: (() => void) | null = null
let unwatch: (() => void) | null = null
onMounted(() => {
  unbind = session.bindEvents()
  // A session that ended (any 401, a dropped live stream) goes to sign-in.
  unwatch = watchSessionExpiry()
})
onUnmounted(() => {
  unbind?.()
  unwatch?.()
})
</script>

<template>
  <!-- The toast and confirm hosts live inside UiAppShell / Bare; remotes use useToast()/useConfirm(). -->
  <component :is="layout">
    <router-view v-slot="{ Component }">
      <component :is="Component" />
    </router-view>
  </component>
</template>
