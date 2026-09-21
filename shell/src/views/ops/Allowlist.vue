<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, ApiError } from '@/api/client'

export interface AllowEntry {
  id: string
  spiffe_id: string
  prefixes: string[]
  names: string[]
  created_by: string
  created_at: string
  revoked_at?: string
}

const rows = ref<AllowEntry[]>([])
const error = ref('')
const spiffe = ref('')
const prefixes = ref('')
const names = ref('')

async function load(): Promise<void> {
  try {
    rows.value = await api<AllowEntry[]>('GET', '/gateway/v1/ops/allowlist')
  } catch (err) {
    error.value = err instanceof ApiError ? err.reason : 'error'
  }
}

const split = (s: string): string[] => s.split(',').map((x) => x.trim()).filter(Boolean)
const valid = (): boolean => spiffe.value.startsWith('spiffe://') && split(prefixes.value).length > 0 && split(names.value).length > 0

async function add(): Promise<void> {
  if (!valid()) return
  error.value = ''
  try {
    await api('POST', '/gateway/v1/ops/allowlist', { spiffe_id: spiffe.value.trim(), prefixes: split(prefixes.value), names: split(names.value) })
    spiffe.value = prefixes.value = names.value = ''
    await load()
  } catch (err) {
    error.value = err instanceof ApiError ? err.reason : 'error'
  }
}

async function revoke(e: AllowEntry): Promise<void> {
  try {
    await api('POST', `/gateway/v1/ops/allowlist/${e.id}/revoke`)
    await load()
  } catch (err) {
    error.value = err instanceof ApiError ? err.reason : 'error'
  }
}

onMounted(load)
</script>

<template>
  <h1 class="text-h5 mb-4">Allow-list</h1>
  <v-alert v-if="error" type="error" variant="tonal" class="mb-4" data-test="ops-error">{{ error }}</v-alert>
  <v-form class="mb-6" data-test="allow-form" @submit.prevent="add">
    <v-row dense>
      <v-col cols="12" md="4"><v-text-field v-model="spiffe" label="SPIFFE ID" placeholder="spiffe://example.org/svc/orders" data-test="allow-spiffe" /></v-col>
      <v-col cols="12" md="3"><v-text-field v-model="prefixes" label="Prefixes (comma separated)" placeholder="/api/orders" data-test="allow-prefixes" /></v-col>
      <v-col cols="12" md="3"><v-text-field v-model="names" label="Module names" placeholder="orders" data-test="allow-names" /></v-col>
      <v-col cols="12" md="2"><v-btn type="submit" color="primary" block :disabled="!valid()" data-test="allow-add">Allow</v-btn></v-col>
    </v-row>
  </v-form>
  <v-table data-test="allowlist">
    <thead><tr><th>Identity</th><th>Prefixes</th><th>Names</th><th>Created</th><th /></tr></thead>
    <tbody>
      <tr v-for="e in rows" :key="e.id" :data-test="'allow-' + e.id" :class="{ 'text-disabled': e.revoked_at }">
        <td>{{ e.spiffe_id }}</td>
        <td>{{ e.prefixes.join(', ') }}</td>
        <td>{{ e.names.join(', ') }}</td>
        <td>{{ e.created_at }} <span class="text-caption">by {{ e.created_by }}</span><span v-if="e.revoked_at"> (revoked)</span></td>
        <td><v-btn v-if="!e.revoked_at" size="small" variant="text" color="error" :data-test="'allow-revoke-' + e.id" @click="revoke(e)">Revoke</v-btn></td>
      </tr>
    </tbody>
  </v-table>
</template>
