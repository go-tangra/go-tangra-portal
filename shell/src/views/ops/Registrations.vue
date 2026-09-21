<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, ApiError } from '@/api/client'

export interface Registration {
  module: string
  identity: string
  state: 'active' | 'draining' | 'unhealthy' | 'revoked'
  instances: number
  unhealthy: number
  last_renewal?: string
  manifest: { version?: string; display_name?: string; prefixes?: string[]; routes?: number; methods?: number }
  traffic: { requests_1m: number; refusals_1m: number; p95_ms: number }
}

const rows = ref<Registration[]>([])
const error = ref('')
const busy = ref('')
const revokeFor = ref<Registration | null>(null)
const reason = ref('')

async function load(): Promise<void> {
  error.value = ''
  try {
    rows.value = await api<Registration[]>('GET', '/gateway/v1/ops/registrations')
  } catch (err) {
    error.value = err instanceof ApiError ? err.reason : 'error'
  }
}

async function act(r: Registration, action: 'drain' | 'undrain'): Promise<void> {
  busy.value = r.module
  try {
    await api('POST', `/gateway/v1/ops/registrations/${r.module}/${action}`)
    await load()
  } catch (err) {
    error.value = err instanceof ApiError ? err.reason : 'error'
  } finally {
    busy.value = ''
  }
}

const reasonValid = (): boolean => reason.value.trim().length >= 10

async function revoke(): Promise<void> {
  if (!revokeFor.value || !reasonValid()) return
  busy.value = revokeFor.value.module
  try {
    await api('POST', `/gateway/v1/ops/registrations/${revokeFor.value.module}/revoke`, { reason: reason.value.trim() })
    revokeFor.value = null
    reason.value = ''
    await load()
  } catch (err) {
    error.value = err instanceof ApiError ? err.reason : 'error'
  } finally {
    busy.value = ''
  }
}

onMounted(load)
</script>

<template>
  <h1 class="text-h5 mb-4">Registrations</h1>
  <v-alert v-if="error" type="error" variant="tonal" class="mb-4" data-test="ops-error">{{ error }}</v-alert>
  <v-table data-test="registrations">
    <thead>
      <tr><th>Module</th><th>State</th><th>Instances</th><th>Requests (1m)</th><th>Refusals (1m)</th><th>p95 ms</th><th>Last renewal</th><th /></tr>
    </thead>
    <tbody>
      <tr v-for="r in rows" :key="r.module" :data-test="'reg-' + r.module">
        <td>{{ r.manifest.display_name || r.module }} <span class="text-caption">{{ r.manifest.version }}</span></td>
        <td><v-chip size="small" :color="r.state === 'active' ? 'success' : r.state === 'revoked' ? 'error' : 'warning'" :data-test="'state-' + r.module">{{ r.state }}</v-chip></td>
        <td>{{ r.instances }}<span v-if="r.unhealthy" class="text-error"> ({{ r.unhealthy }} unhealthy)</span></td>
        <td>{{ r.traffic.requests_1m }}</td>
        <td>{{ r.traffic.refusals_1m }}</td>
        <td>{{ r.traffic.p95_ms.toFixed(1) }}</td>
        <td>{{ r.last_renewal ?? '—' }}</td>
        <td class="text-no-wrap">
          <v-btn v-if="r.state === 'active' || r.state === 'unhealthy'" size="small" variant="text" :loading="busy === r.module" :data-test="'drain-' + r.module" @click="act(r, 'drain')">Drain</v-btn>
          <v-btn v-if="r.state === 'draining'" size="small" variant="text" :loading="busy === r.module" :data-test="'undrain-' + r.module" @click="act(r, 'undrain')">Undrain</v-btn>
          <v-btn v-if="r.state !== 'revoked'" size="small" variant="text" color="error" :data-test="'revoke-' + r.module" @click="revokeFor = r">Revoke</v-btn>
        </td>
      </tr>
      <tr v-if="!rows.length"><td colspan="8" class="text-center text-medium-emphasis" data-test="empty">No registrations</td></tr>
    </tbody>
  </v-table>
  <v-dialog :model-value="!!revokeFor" max-width="480" @update:model-value="revokeFor = null">
    <v-card v-if="revokeFor" data-test="revoke-dialog">
      <v-card-title>Revoke {{ revokeFor.module }}</v-card-title>
      <v-card-text>
        <p class="mb-4">Renewals will be refused and the module's routes withdrawn. This is recorded in the audit trail with your identity.</p>
        <v-textarea v-model="reason" label="Reason (at least 10 characters)" rows="2" data-test="revoke-reason" :error="reason.length > 0 && !reasonValid()" />
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" data-test="revoke-cancel" @click="revokeFor = null">Cancel</v-btn>
        <v-btn color="error" :disabled="!reasonValid()" data-test="revoke-confirm" @click="revoke">Revoke</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>
