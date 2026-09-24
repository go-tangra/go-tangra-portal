<script setup lang="ts">
import { UiPage, UiCard, UiEmptyState, UiIcon, UiStatusChip } from '@go-tangra/ui'
import { useSession } from '@/stores/session'
const session = useSession()
</script>

<template>
  <UiPage :title="'Welcome' + (session.displayName ? `, ${session.displayName}` : '')" subtitle="Modules registered with the platform gateway.">
    <UiCard title="Modules" :padded="false">
      <ul v-if="session.modules.length" class="divide-y divide-base-300" data-test="module-list">
        <li v-for="m in session.modules" :key="m.module ?? ''" class="flex items-center gap-3 px-4 py-3" :data-test="'module-' + m.module">
          <span class="flex size-10 shrink-0 items-center justify-center rounded-box bg-primary/10 text-primary"><UiIcon name="mdi-view-module-outline" /></span>
          <span class="min-w-0 grow">
            <span class="block truncate font-medium">{{ m.display_name || m.module || '' }}</span>
            <span class="block truncate text-xs text-base-content/70">{{ m.version ?? '' }}</span>
          </span>
          <UiStatusChip :status="m.state ?? ''" />
        </li>
      </ul>
      <UiEmptyState v-else title="No modules are registered yet." data-test="no-modules" />
    </UiCard>
  </UiPage>
</template>
