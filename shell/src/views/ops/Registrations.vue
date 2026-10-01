<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { UiPage, UiAlert, UiCard, UiButton, UiDataTable, UiDialog, UiForm, UiTextarea, UiStatusChip, type Column } from '@go-tangra/ui'
import { useZodForm } from '@go-tangra/ui/forms'
import { api, ApiError } from '@/api/client'
import { useServerList } from '@/composables/useServerList'
import { revokeSchema } from '@/schemas/ops'
import { releaseLabel } from '@/api/versions'

export interface Registration extends Record<string, unknown> {
  module: string
  identity: string
  state: 'active' | 'draining' | 'unhealthy' | 'revoked'
  instances: number
  unhealthy: number
  last_renewal?: string
  manifest: { version?: string; display_name?: string; prefixes?: string[]; routes?: number; methods?: number }
  /** Releases the instances run (ascending); manifest.version is the contract version. */
  build_versions?: string[]
  traffic: { requests_1m: number; refusals_1m: number; p95_ms: number }
}

const list = useServerList<Registration>('reg', '/gateway/v1/ops/registrations', { sortable: ['module', 'state', 'instances', 'last_renewal'], defaultSort: { key: 'module', dir: 'asc' } })
const { lq, load } = list
const error = ref('')
const busy = ref('')
const revokeFor = ref<Registration | null>(null)

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

const revokeForm = useZodForm(revokeSchema, {
  initial: { reason: '' },
  onSubmit: async (payload) => {
    if (!revokeFor.value) return
    busy.value = revokeFor.value.module
    try {
      await api('POST', `/gateway/v1/ops/registrations/${revokeFor.value.module}/revoke`, payload)
    } finally {
      busy.value = ''
    }
  },
  onSuccess: async () => {
    revokeFor.value = null
    revokeForm.reset({ reason: '' })
    await load()
  },
})

const columns: Column<Registration>[] = [
  { key: 'module', label: 'Module', format: (r) => `${r.manifest.display_name || r.module} ${releaseLabel(r)}`.trim(), sortable: true },
  { key: 'manifest', label: 'Manifest', format: (r) => r.manifest.version ?? '—', hideOnStack: true },
  { key: 'state', label: 'State', width: 'sm', sortable: true },
  { key: 'instances', label: 'Instances', format: (r) => String(r.instances) + (r.unhealthy ? ` (${r.unhealthy} unhealthy)` : ''), sortable: true, defaultDir: 'desc' },
  { key: 'requests', label: 'Requests (1m)', align: 'end', format: (r) => String(r.traffic.requests_1m), hideOnStack: true },
  { key: 'refusals', label: 'Refusals (1m)', align: 'end', format: (r) => String(r.traffic.refusals_1m), hideOnStack: true },
  { key: 'p95', label: 'p95 ms', align: 'end', format: (r) => r.traffic.p95_ms.toFixed(1) },
  { key: 'last_renewal', label: 'Last renewal', format: (r) => r.last_renewal ?? '—', sortable: true, defaultDir: 'desc', hideOnStack: true },
]

onMounted(load)
</script>

<template>
  <UiPage title="Registrations" subtitle="Modules registered with the gateway and their traffic">
    <UiAlert v-if="list.error.value || error" kind="error" class="mb-4" data-test="ops-error">{{ list.error.value || error }}</UiAlert>
    <UiCard :padded="false">
      <UiDataTable :items="list.items.value" :total="list.total.value" :page="lq.page.value" :page-size="lq.pageSize.value" :sort="lq.sort.value" :loading="list.loading.value" :columns="columns" row-key="module" caption="Registrations" empty-title="No registrations" @update:page="lq.setPage" @update:page-size="lq.setPageSize" @update:sort="lq.setSort" :row-attrs="(r) => ({ 'data-test': 'reg-' + r.module })" data-test="registrations">
        <template #cell-state="{ row }"><UiStatusChip :status="String(row.state)" :colors="{ draining: 'warning', unhealthy: 'warning' }" :data-test="'state-' + row.module" /></template>
        <template #actions="{ row }">
          <UiButton v-if="row.state === 'active' || row.state === 'unhealthy'" size="sm" variant="text" :loading="busy === row.module" :data-test="'drain-' + row.module" @click="act(row, 'drain')">Drain</UiButton>
          <UiButton v-if="row.state === 'draining'" size="sm" variant="text" :loading="busy === row.module" :data-test="'undrain-' + row.module" @click="act(row, 'undrain')">Undrain</UiButton>
          <UiButton v-if="row.state !== 'revoked'" size="sm" variant="text" color="error" :data-test="'revoke-' + row.module" @click="revokeFor = row">Revoke</UiButton>
        </template>
      </UiDataTable>
    </UiCard>
    <UiDialog :model-value="!!revokeFor" :title="revokeFor ? `Revoke ${revokeFor.module}` : ''" size="sm" @update:model-value="revokeFor = null">
      <UiForm v-if="revokeFor" :form="revokeForm" data-test="revoke-dialog">
        <p class="mb-3 text-sm">The module is removed from the platform immediately; its identity must be re-allowed before it can register again.</p>
        <UiTextarea v-bind="revokeForm.field('reason')" label="Reason (at least 10 characters)" :rows="2" required data-test="revoke-reason" />
      </UiForm>
      <template #actions>
        <UiButton variant="text" data-test="revoke-cancel" @click="revokeFor = null">Cancel</UiButton>
        <UiButton color="error" :disabled="!revokeForm.valid.value" :loading="!!busy" data-test="revoke-confirm" @click="revokeForm.submit()">Revoke</UiButton>
      </template>
    </UiDialog>
  </UiPage>
</template>
