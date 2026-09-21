<script setup lang="ts">
import { computed, onMounted, onUnmounted } from 'vue'
import { useRoute } from 'vue-router'
import { useSession } from '@/stores/session'
import Default from '@/layouts/Default.vue'
import Bare from '@/layouts/Bare.vue'

const route = useRoute()
const session = useSession()
const layout = computed(() => (route.meta.layout === 'bare' ? Bare : Default))
let unbind: (() => void) | null = null
onMounted(() => {
  unbind = session.bindEvents()
})
onUnmounted(() => unbind?.())
</script>

<template>
  <v-app>
    <component :is="layout">
      <router-view v-slot="{ Component }">
        <component :is="Component" />
      </router-view>
    </component>
  </v-app>
</template>
