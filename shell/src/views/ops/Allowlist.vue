<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { UiPage, UiAlert, UiCard, UiForm, UiInput, UiButton, UiDataTable, type Column } from '@go-tangra/ui'
import { useZodForm } from '@go-tangra/ui/forms'
import { api, ApiError } from '@/api/client'
import { allowEntrySchema } from '@/schemas/ops'

export interface AllowEntry extends Record<string, unknown> {
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

async function load(): Promise<void> {
  try {
    rows.value = await api<AllowEntry[]>('GET', '/gateway/v1/ops/allowlist')
  } catch (err) {
    error.value = err instanceof ApiError ? err.reason : 'error'
  }
}

const form = useZodForm(allowEntrySchema, {
  initial: { spiffe_id: '', prefixes: '', names: '' },
  onSubmit: (payload) => api('POST', '/gateway/v1/ops/allowlist', payload),
  onSuccess: async () => {
    form.reset({ spiffe_id: '', prefixes: '', names: '' })
    await load()
  },
})

async function revoke(e: AllowEntry): Promise<void> {
  try {
    await api('POST', `/gateway/v1/ops/allowlist/${e.id}/revoke`)
    await load()
  } catch (err) {
    error.value = err instanceof ApiError ? err.reason : 'error'
  }
}

const columns: Column<AllowEntry>[] = [
  { key: 'spiffe_id', label: 'Identity' },
  { key: 'prefixes', label: 'Prefixes', format: (e) => e.prefixes.join(', ') },
  { key: 'names', label: 'Names', format: (e) => e.names.join(', ') },
  { key: 'created_at', label: 'Created', format: (e) => `${e.created_at} by ${e.created_by}${e.revoked_at ? ' (revoked)' : ''}`, hideOnStack: true },
]
onMounted(load)
</script>

<template>
  <UiPage title="Allow-list" subtitle="Workload identities allowed to register modules with the gateway">
    <UiAlert v-if="error" kind="error" class="mb-4" data-test="ops-error">{{ error }}</UiAlert>
    <UiCard class="mb-4">
      <UiForm :form="form" data-test="allow-form">
        <div class="grid grid-cols-1 gap-3 md:grid-cols-12 md:items-end">
          <div class="md:col-span-4"><UiInput v-bind="form.field('spiffe_id')" label="SPIFFE ID" placeholder="spiffe://example.org/svc/orders" required data-test="allow-spiffe" /></div>
          <div class="md:col-span-3"><UiInput v-bind="form.field('prefixes')" label="Prefixes (comma separated)" placeholder="/api/orders" required data-test="allow-prefixes" /></div>
          <div class="md:col-span-3"><UiInput v-bind="form.field('names')" label="Module names" placeholder="orders" required data-test="allow-names" /></div>
          <div class="md:col-span-2"><UiButton type="submit" block :loading="form.submitting.value" data-test="allow-add">Allow</UiButton></div>
        </div>
      </UiForm>
    </UiCard>
    <UiCard :padded="false">
      <UiDataTable :items="rows" :columns="columns" row-key="id" caption="Allow-list entries" empty-title="No entries" :row-attrs="(e) => ({ 'data-test': 'allow-' + e.id, class: e.revoked_at ? 'opacity-50' : '' })" data-test="allowlist">
        <template #actions="{ row }">
          <UiButton v-if="!row.revoked_at" size="sm" variant="text" color="error" :data-test="'allow-revoke-' + row.id" @click="revoke(row)">Revoke</UiButton>
        </template>
      </UiDataTable>
    </UiCard>
  </UiPage>
</template>
