<script setup lang="ts">
import { computed } from 'vue'
import { RouterLink } from 'vue-router'
import { UiAppShell, UiNavDrawer, UiButton, UiAvatar, UiIcon, useTheme, type NavGroup } from '@freya/ui'
import { useSession } from '@/stores/session'
import { navigation } from '@/router'
import { headerSlots, type BootContext } from '@/federation/boot'
import { ability } from '@/casl/ability'
import { api } from '@/api/client'
import { live } from '@/api/live'
import ModuleBoundary from '@/components/ModuleBoundary.vue'

const session = useSession()
const headerCtx: BootContext = { ability, session, api, live }
// Module header components in the order of their first nav entry (contracts/shell-changes.md).
const headerModules = computed(() => {
  const order = new Map(session.navGroups.map((g, i) => [g.module, i]))
  return [...headerSlots.entries()].sort(([a], [b]) => (order.get(a) ?? 1e9) - (order.get(b) ?? 1e9))
})
// One collapsible menu per module (the kit opens the one owning the active route), Home above, operations below.
const groups = computed<NavGroup[]>(() => [
  { items: [{ title: 'Home', path: '/', icon: 'mdi-home-outline', exact: true, testId: 'nav-home' }] },
  ...session.navGroups.map((g) => ({ key: g.module, title: g.title, icon: g.icon, testId: 'nav-group-' + g.module, items: g.entries.map((n) => ({ title: n.title, path: n.path, icon: n.icon || 'mdi-circle-small', testId: 'nav-' + n.module })) })),
  ...(session.operator ? [{ items: [{ title: 'Gateway operations', path: '/ops', icon: 'mdi-server-network', testId: 'nav-ops' }] }] : []),
])
const theme = useTheme()
const dark = computed(() => theme.theme.value === 'freya-dark')

async function signOut(): Promise<void> {
  // The auth module ends the session (the gateway relays the cookie clear);
  // every module area is then signed out, and a full navigation drops remote state.
  await session.signOut()
  navigation.assign('/console/signin')
}
</script>

<template>
  <UiAppShell title="Freya">
    <template #brand>
      <RouterLink to="/" class="inline-flex items-center gap-3" aria-label="Freya home">
        <span class="rounded-field bg-primary text-primary-content flex size-9 items-center justify-center"><UiIcon name="mdi-shield-half-full" /></span>
        <span class="flex flex-col">
          <span class="text-base-content text-lg font-semibold leading-tight">Freya</span>
          <span class="text-base-content/70 text-xs">Platform</span>
        </span>
      </RouterLink>
    </template>
    <template #app-bar>
      <UiButton variant="text" size="sm" icon-only :icon="dark ? 'mdi-weather-sunny' : 'mdi-weather-night'" :label="dark ? 'Switch to the light theme' : 'Switch to the dark theme'" data-test="theme-toggle" @click="theme.toggle()" />
      <!-- Module header slots (./header): each inside its own boundary so a failing one shows nothing. -->
      <template v-if="session.signedIn">
        <ModuleBoundary v-for="[m, c] in headerModules" :key="m" :module="m" silent>
          <component :is="c" v-bind="headerCtx" :data-test="'header-' + m" />
        </ModuleBoundary>
        <div class="ms-2 flex items-center gap-2">
          <span class="text-base-content hidden text-sm font-medium md:inline" data-test="me-name">{{ session.displayName || session.userId }}</span>
          <span data-test="me-avatar"><UiAvatar :name="session.displayName || session.userId" :src="session.avatarUrl || undefined" size="sm" /></span>
          <UiButton variant="text" size="sm" icon-only icon="mdi-logout" label="Sign out" data-test="signout" @click="signOut" />
        </div>
      </template>
    </template>
    <template #nav="{ close }">
      <UiNavDrawer :groups="groups" @navigate="close" />
    </template>
    <slot />
  </UiAppShell>
</template>
