<script setup lang="ts">
import { useSession } from '@/stores/session'
const session = useSession()
</script>

<template>
  <h1 class="text-h4 mb-1">Welcome{{ session.displayName ? `, ${session.displayName}` : '' }}</h1>
  <p class="mb-6">Modules registered with the platform gateway.</p>
  <v-card>
    <v-card-title>Modules</v-card-title>
    <v-list v-if="session.modules.length" data-test="module-list" lines="two">
      <v-list-item v-for="m in session.modules" :key="m.module ?? ''" :title="m.display_name || m.module || ''" :subtitle="m.version ?? ''" :data-test="'module-' + m.module">
        <template #prepend>
          <v-avatar color="primary" variant="tonal" rounded="lg"><v-icon icon="mdi-view-module-outline" /></v-avatar>
        </template>
        <template #append>
          <v-chip size="small" :color="m.state === 'active' ? 'success' : 'warning'" variant="tonal">{{ m.state }}</v-chip>
        </template>
      </v-list-item>
    </v-list>
    <v-card-text v-else data-test="no-modules">No modules are registered yet.</v-card-text>
  </v-card>
</template>
