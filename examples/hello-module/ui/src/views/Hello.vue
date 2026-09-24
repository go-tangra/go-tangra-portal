<script setup lang="ts">
import { ref } from 'vue'
import { useAbility } from '@casl/vue'

// The shell provides one CASL ability derived from the caller's API
// permissions; `hello:say` yields `create Greeting`.
const ability = useAbility()
const greeting = ref('')
const error = ref('')

function csrf(): string {
  const hit = document.cookie.split('; ').find((c) => c.startsWith('__Host-csrf='))
  return hit ? decodeURIComponent(hit.slice('__Host-csrf='.length)) : ''
}

async function load(): Promise<void> {
  const res = await fetch('/api/hello', { credentials: 'same-origin' })
  greeting.value = res.ok ? ((await res.json()) as { greeting: string }).greeting : ''
}

async function say(): Promise<void> {
  error.value = ''
  const res = await fetch('/api/hello', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf() }, body: JSON.stringify({ name: 'platform' }) })
  if (!res.ok) {
    error.value = ((await res.json().catch(() => ({ reason: 'error' }))) as { reason: string }).reason
    return
  }
  greeting.value = ((await res.json()) as { greeting: string }).greeting
}

void load()
</script>

<template>
  <v-card class="pa-6" data-test="hello-module">
    <v-card-title class="text-h5">Hello module</v-card-title>
    <p class="text-body-1 my-4" data-test="greeting">{{ greeting || '…' }}</p>
    <Can I="create" a="Greeting">
      <v-btn color="primary" data-test="say" @click="say">Say hello</v-btn>
    </Can>
    <Can not I="create" a="Greeting">
      <p class="text-body-2" data-test="no-permission">You cannot send greetings.</p>
    </Can>
    <v-alert v-if="error" type="error" class="mt-4" data-test="error">{{ error }}</v-alert>
    <p v-if="ability.can('create', 'Greeting')" class="text-caption mt-2" data-test="can">API and UI agree: hello:say held.</p>
  </v-card>
</template>
