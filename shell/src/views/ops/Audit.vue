<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, ApiError } from '@/api/client'

export interface AuditEvent {
  ts: string
  event_type: string
  module: string
  actor_kind: string
  actor_id: string
  subject_kind: string
  subject_id: string
  outcome: string
  reason: string
  correlation_id: string
  details: Record<string, unknown>
}

const events = ref<AuditEvent[]>([])
const module = ref('')
const eventType = ref('')
const error = ref('')
const next = ref('')

const eventTypes = ['registration_accepted', 'registration_refused', 'registration_updated', 'registration_withdrawn', 'renewal_refused', 'module_drained', 'module_revoked', 'module_unhealthy', 'module_recovered', 'allowlist_changed', 'identity_refused', 'permission_refused', 'stream_terminated', 'limit_exceeded']

async function load(more = false): Promise<void> {
  error.value = ''
  try {
    const page = await api<{ events: AuditEvent[]; next_cursor?: string }>('GET', '/gateway/v1/ops/audit', undefined, {
      query: { module: module.value || undefined, event_type: eventType.value || undefined, cursor: more ? next.value || undefined : undefined },
    })
    events.value = more ? [...events.value, ...page.events] : page.events
    next.value = page.next_cursor ?? ''
  } catch (err) {
    error.value = err instanceof ApiError ? err.reason : 'error'
  }
}

onMounted(() => load())
</script>

<template>
  <h1 class="text-h5 mb-4">Gateway audit</h1>
  <v-alert v-if="error" type="error" variant="tonal" class="mb-4" data-test="ops-error">{{ error }}</v-alert>
  <v-row dense class="mb-2">
    <v-col cols="12" md="4"><v-text-field v-model="module" label="Module" clearable data-test="audit-module" @keyup.enter="load()" /></v-col>
    <v-col cols="12" md="5"><v-select v-model="eventType" :items="eventTypes" label="Event type" clearable data-test="audit-type" /></v-col>
    <v-col cols="12" md="3"><v-btn color="primary" block data-test="audit-search" @click="load()">Search</v-btn></v-col>
  </v-row>
  <v-table data-test="audit">
    <thead><tr><th>Time</th><th>Event</th><th>Module</th><th>Actor</th><th>Subject</th><th>Outcome</th><th>Reason</th></tr></thead>
    <tbody>
      <tr v-for="e in events" :key="e.ts + e.event_type + e.subject_id" :data-test="'audit-' + e.event_type">
        <td class="text-no-wrap">{{ e.ts }}</td>
        <td>{{ e.event_type }}</td>
        <td>{{ e.module }}</td>
        <td>{{ e.actor_kind }} {{ e.actor_id }}</td>
        <td>{{ e.subject_kind }} {{ e.subject_id }}</td>
        <td><v-chip size="x-small" :color="e.outcome === 'ok' ? 'success' : 'warning'">{{ e.outcome }}</v-chip></td>
        <td>{{ e.reason }}</td>
      </tr>
      <tr v-if="!events.length"><td colspan="7" class="text-center text-medium-emphasis" data-test="empty">No events</td></tr>
    </tbody>
  </v-table>
  <v-btn v-if="next" variant="text" class="mt-2" data-test="audit-more" @click="load(true)">Load more</v-btn>
</template>
