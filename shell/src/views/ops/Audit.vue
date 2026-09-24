<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { UiPage, UiAlert, UiCard, UiInput, UiSelect, UiButton, UiDataTable, UiStatusChip, type Column, type SelectOption } from '@go-tangra/ui'
import { api, ApiError } from '@/api/client'

export interface AuditEvent extends Record<string, unknown> {
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

const typeOptions: SelectOption[] = eventTypes.map((t) => ({ title: t, value: t }))
const columns: Column<AuditEvent>[] = [
  { key: 'ts', label: 'Time', width: 'sm' },
  { key: 'event_type', label: 'Event' },
  { key: 'module', label: 'Module' },
  { key: 'actor_id', label: 'Actor', format: (e) => `${e.actor_kind} ${e.actor_id}`, hideOnStack: true },
  { key: 'subject_id', label: 'Subject', format: (e) => `${e.subject_kind} ${e.subject_id}` },
  { key: 'outcome', label: 'Outcome', width: 'sm' },
  { key: 'reason', label: 'Reason', hideOnStack: true },
]
onMounted(() => load())
</script>

<template>
  <UiPage title="Gateway audit" subtitle="Registration, identity and permission decisions taken by the gateway">
    <UiAlert v-if="error" kind="error" class="mb-4" data-test="ops-error">{{ error }}</UiAlert>
    <template #filters>
      <div class="grid w-full grid-cols-1 gap-2 md:grid-cols-12 md:items-end">
        <div class="md:col-span-4"><UiInput id="audit-module" v-model="module" label="Module" size="sm" data-test="audit-module" @enter="load()" /></div>
        <div class="md:col-span-5"><UiSelect id="audit-type" v-model="eventType" label="Event type" :options="typeOptions" size="sm" data-test="audit-type" /></div>
        <div class="md:col-span-3"><UiButton block size="sm" data-test="audit-search" @click="load()">Search</UiButton></div>
      </div>
    </template>
    <UiCard :padded="false">
      <UiDataTable :items="events" :columns="columns" caption="Audit events" empty-title="No events" :row-attrs="(e) => ({ 'data-test': 'audit-' + e.event_type })" data-test="audit">
        <template #cell-outcome="{ row }"><UiStatusChip :status="String(row.outcome)" :colors="{ ok: 'success' }" /></template>
      </UiDataTable>
      <div v-if="next" class="px-4 pb-3"><UiButton variant="text" size="sm" data-test="audit-more" @click="load(true)">Load more</UiButton></div>
    </UiCard>
  </UiPage>
</template>
