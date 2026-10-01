<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { UiPage, UiAlert, UiCard, UiForm, UiInput, UiButton, UiDataTable, type Column } from '@go-tangra/ui'
import { useZodForm } from '@go-tangra/ui/forms'
import { api, ApiError } from '@/api/client'
import { useServerList } from '@/composables/useServerList'
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

const list = useServerList<AllowEntry>('allow', '/gateway/v1/ops/allowlist', { sortable: ['spiffe_id', 'created_at', 'revoked_at'], defaultSort: { key: 'spiffe_id', dir: 'asc' } })
const { lq, load } = list
const actionError = ref('')

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
    actionError.value = err instanceof ApiError ? err.reason : 'error'
  }
}

const columns: Column<AllowEntry>[] = [
  { key: 'spiffe_id', label: 'Identity', sortable: true },
  { key: 'prefixes', label: 'Prefixes', format: (e) => e.prefixes.join(', ') },
  { key: 'names', label: 'Names', format: (e) => e.names.join(', ') },
  { key: 'created_at', label: 'Created', format: (e) => `${e.created_at} by ${e.created_by}`, sortable: true, defaultDir: 'desc', hideOnStack: true },
  { key: 'revoked_at', label: 'Revoked', format: (e) => e.revoked_at ?? '', sortable: true, defaultDir: 'desc', hideOnStack: true },
]
onMounted(load)
</script>

<template>
  <UiPage title="Allow-list" subtitle="Workload identities allowed to register modules with the gateway">
    <UiAlert v-if="list.error.value || actionError" kind="error" class="mb-4" data-test="ops-error">{{ list.error.value || actionError }}</UiAlert>
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
      <UiDataTable :items="list.items.value" :total="list.total.value" :page="lq.page.value" :page-size="lq.pageSize.value" :sort="lq.sort.value" :loading="list.loading.value" :columns="columns" row-key="id" caption="Allow-list entries" empty-title="No entries" @update:page="lq.setPage" @update:page-size="lq.setPageSize" @update:sort="lq.setSort" :row-attrs="(e) => ({ 'data-test': 'allow-' + e.id, class: e.revoked_at ? 'opacity-50' : '' })" data-test="allowlist">
        <template #actions="{ row }">
          <UiButton v-if="!row.revoked_at" size="sm" variant="text" color="error" :data-test="'allow-revoke-' + row.id" @click="revoke(row)">Revoke</UiButton>
        </template>
      </UiDataTable>
    </UiCard>
  </UiPage>
</template>
