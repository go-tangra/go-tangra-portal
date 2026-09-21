<script setup lang="ts">
import { computed, ref } from 'vue'
import { useTheme } from 'vuetify'
import { useSession } from '@/stores/session'
import { navigation } from '@/router'
import { storeTheme } from '@/theme/materio'
import { headerSlots, type BootContext } from '@/federation/boot'
import { ability } from '@/casl/ability'
import { api } from '@/api/client'
import { live } from '@/api/live'
import RemoteBoundary from '@/components/RemoteBoundary.vue'

const session = useSession()
const drawer = ref<boolean | null>(null)
const headerCtx: BootContext = { ability, session, api, live }
// Module header components in the order of their first nav entry (contracts/shell-changes.md).
const headerModules = computed(() => {
  const order = new Map(session.navGroups.map((g, i) => [g.module, i]))
  return [...headerSlots.entries()].sort(([a], [b]) => (order.get(a) ?? 1e9) - (order.get(b) ?? 1e9))
})
const theme = useTheme()
const dark = computed(() => theme.current.value.dark)
function toggleTheme(): void {
  const next = dark.value ? 'light' : 'dark'
  theme.change(next)
  storeTheme(next)
}

async function signOut(): Promise<void> {
  // The auth module ends the session (the gateway relays the cookie clear);
  // every module area is then signed out, and a full navigation drops remote state.
  await session.signOut()
  navigation.assign('/console/signin')
}
</script>

<template>
  <!-- Materio layout: full-height menu on the left, a detached top bar and the page inside shared gutters. -->
  <v-navigation-drawer v-model="drawer" class="freya-drawer" :width="260" :order="0">
    <router-link to="/" class="freya-brand" aria-label="Freya home">
      <span class="freya-brand__mark"><v-icon icon="mdi-shield-half-full" size="20" /></span>
      <span class="freya-brand__text">Freya</span>
    </router-link>
    <!-- One menu per module; Vuetify opens the menu owning the active entry. -->
    <v-list nav density="compact" role="presentation" aria-label="Modules">
      <v-list-item to="/" exact prepend-icon="mdi-home-outline" title="Home" data-test="nav-home" />
      <v-list-group v-for="g in session.navGroups" :key="g.module" :value="g.module">
        <template #activator="{ props, isOpen }">
          <!-- Vuetify marks the header as an option; as a disclosure button it needs no listbox parent (axe aria-required-parent). -->
          <v-list-item v-bind="props" role="button" :aria-selected="undefined" :aria-expanded="isOpen" :prepend-icon="g.icon" :title="g.title" :data-test="'nav-group-' + g.module" />
        </template>
        <v-list-item v-for="n in g.entries" :key="n.path" :to="n.path" :prepend-icon="n.icon || 'mdi-circle-small'" :title="n.title" :data-test="'nav-' + n.module" />
      </v-list-group>
      <v-list-item v-if="session.operator" to="/ops" prepend-icon="mdi-server-network" title="Gateway operations" data-test="nav-ops" />
    </v-list>
  </v-navigation-drawer>
  <v-app-bar class="freya-appbar" flat :height="64" :order="1">
    <v-app-bar-nav-icon aria-label="Toggle navigation" @click="drawer = !drawer" />
    <v-spacer />
    <v-btn :icon="dark ? 'mdi-weather-sunny' : 'mdi-weather-night'" variant="text" :aria-label="dark ? 'Switch to the light theme' : 'Switch to the dark theme'" data-test="theme-toggle" @click="toggleTheme" />
    <!-- Module header slots (./header): each inside its own boundary so a failing one shows nothing. -->
    <template v-if="session.signedIn">
      <RemoteBoundary v-for="[m, c] in headerModules" :key="m" :module="m" silent>
        <component :is="c" v-bind="headerCtx" :data-test="'header-' + m" />
      </RemoteBoundary>
    </template>
    <template v-if="session.signedIn">
      <span class="freya-avatar ml-1 mr-3">
        <v-avatar size="38" color="primary" data-test="me-avatar">
          <v-img v-if="session.avatarUrl" :src="session.avatarUrl" :alt="session.displayName || 'Avatar'" cover />
          <span v-else class="text-body-2 font-weight-medium" aria-hidden="true">{{ session.initials }}</span>
        </v-avatar>
        <span class="freya-avatar__status" aria-hidden="true" />
      </span>
      <span class="mr-4 text-body-2 font-weight-medium" data-test="me-name">{{ session.displayName || session.userId }}</span>
      <v-btn variant="text" prepend-icon="mdi-logout" data-test="signout" @click="signOut">Sign out</v-btn>
    </template>
  </v-app-bar>
  <v-main>
    <v-container fluid class="freya-page">
      <slot />
    </v-container>
  </v-main>
</template>
