<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { UiPage, UiAlert, UiCard, UiInput, UiSelect, UiButton, UiDataTable, UiStatusChip, type Column, type SelectOption } from '@go-tangra/ui'
import { useServerList } from '@/composables/useServerList'

export interface AuditEvent extends Record<string, unknown> {
  id: number
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

const module = ref('')
const eventType = ref('')
const list = useServerList<AuditEvent>('audit', '/gateway/v1/ops/audit', { sortable: ['ts', 'module', 'event_type'], defaultSort: { key: 'ts', dir: 'desc' }, defaultSize: 50 },
  () => ({ module: module.value || undefined, event_type: eventType.value || undefined }))
const { lq, load, search } = list

const eventTypes = ['registration_accepted', 'registration_refused', 'registration_updated', 'registration_withdrawn', 'renewal_refused', 'module_drained', 'module_revoked', 'module_unhealthy', 'module_recovered', 'allowlist_changed', 'identity_refused', 'permission_refused', 'stream_terminated', 'limit_exceeded', 'enrollment_token_minted']


const typeOptions: SelectOption[] = eventTypes.map((t) => ({ title: t, value: t }))
const columns: Column<AuditEvent>[] = [
  { key: 'ts', label: 'Time', width: 'sm', sortable: true, defaultDir: 'desc' },
  { key: 'event_type', label: 'Event', sortable: true },
  { key: 'module', label: 'Module', sortable: true },
  { key: 'actor_id', label: 'Actor', format: (e) => `${e.actor_kind} ${e.actor_id}`, hideOnStack: true },
  { key: 'subject_id', label: 'Subject', format: (e) => `${e.subject_kind} ${e.subject_id}` },
  { key: 'outcome', label: 'Outcome', width: 'sm' },
  { key: 'reason', label: 'Reason', hideOnStack: true },
]
onMounted(load)
</script>

<template>
  <UiPage title="Gateway audit" subtitle="Registration, identity and permission decisions taken by the gateway (last 7 days)">
    <UiAlert v-if="list.error.value" kind="error" class="mb-4" data-test="ops-error">{{ list.error.value }}</UiAlert>
    <template #filters>
      <div class="grid w-full grid-cols-1 gap-2 md:grid-cols-12 md:items-end">
        <div class="md:col-span-4"><UiInput id="audit-module" v-model="module" label="Module" size="sm" data-test="audit-module" @enter="search()" /></div>
        <div class="md:col-span-5"><UiSelect id="audit-type" v-model="eventType" label="Event type" :options="typeOptions" size="sm" data-test="audit-type" @update:model-value="search()" /></div>
        <div class="md:col-span-3"><UiButton block size="sm" data-test="audit-search" @click="search()">Search</UiButton></div>
      </div>
    </template>
    <UiCard :padded="false">
      <UiDataTable :items="list.items.value" :total="list.total.value" :page="lq.page.value" :page-size="lq.pageSize.value" :sort="lq.sort.value" :loading="list.loading.value" :columns="columns" caption="Audit events" empty-title="No events in this period" :row-attrs="(e) => ({ 'data-test': 'audit-' + e.event_type })" data-test="audit" @update:page="lq.setPage" @update:page-size="lq.setPageSize" @update:sort="lq.setSort">
        <template #cell-outcome="{ row }"><UiStatusChip :status="String(row.outcome)" :colors="{ ok: 'success' }" /></template>
      </UiDataTable>
    </UiCard>
  </UiPage>
</template>
