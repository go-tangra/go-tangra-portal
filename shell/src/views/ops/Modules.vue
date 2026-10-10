<script setup lang="ts">
// Every module the gateway has seen register, running or not (module
// catalogue, phase 1). A module that is installed but not registered shows
// "down" when it should be running, "stopped" when an administrator marked
// it not expected. Only platform administrators may change the list.
import { computed, onMounted, ref } from 'vue'
import { UiPage, UiAlert, UiCard, UiButton, UiDataTable, UiDialog, UiStatusChip, UiSwitch, type Column } from '@go-tangra/ui'
import { api, ApiError } from '@/api/client'
import type { components } from '@/api/schema'

type Item = components['schemas']['CatalogueItem'] & Record<string, unknown>

const items = ref<Item[]>([])
const canManage = ref(false)
const partial = ref(false)
const loading = ref(false)
const error = ref('')
const busy = ref('')
const forgetFor = ref<Item | null>(null)

const down = computed(() => items.value.filter((i) => i.state === 'down').length)

async function load(): Promise<void> {
  loading.value = true
  try {
    const v = await api<components['schemas']['Catalogue']>('GET', '/gateway/v1/ops/catalogue')
    items.value = v.items as Item[]
    canManage.value = v.can_manage
    partial.value = !!v.partial
    error.value = ''
  } catch (err) {
    error.value = err instanceof ApiError ? err.reason : 'error'
  } finally {
    loading.value = false
  }
}

async function run(module: string, fn: () => Promise<unknown>): Promise<void> {
  busy.value = module
  try {
    await fn()
    await load()
  } catch (err) {
    error.value = err instanceof ApiError ? err.reason : 'error'
  } finally {
    busy.value = ''
  }
}

function setExpected(row: Item, expected: boolean): Promise<void> {
  return run(row.module, () => api('PATCH', `/gateway/v1/ops/catalogue/${row.module}`, { expected }))
}

async function forget(): Promise<void> {
  const row = forgetFor.value
  if (!row) return
  await run(row.module, () => api('DELETE', `/gateway/v1/ops/catalogue/${row.module}`))
  forgetFor.value = null
}

function when(v?: string): string {
  return v ? new Date(v).toLocaleString() : '—'
}

const columns = computed<Column<Item>[]>(() => [
  { key: 'module', label: 'Module', format: (r) => r.display_name || r.module },
  { key: 'state', label: 'State', width: 'sm' },
  { key: 'version', label: 'Version', format: (r) => (r.registered && r.build_versions.length ? r.build_versions.join(', ') : r.last_version) || '—' },
  { key: 'instances', label: 'Instances', align: 'end', format: (r) => String(r.instances), hideOnStack: true },
  { key: 'last_seen_at', label: 'Last seen', format: (r) => (r.registered ? 'now' : when(r.last_seen_at)) },
  { key: 'first_seen_at', label: 'First seen', format: (r) => when(r.first_seen_at), hideOnStack: true },
  ...(canManage.value ? [{ key: 'expected', label: 'Expected', width: 'sm' as const }] : []),
])

onMounted(load)
</script>

<template>
  <UiPage title="Modules" subtitle="Every module the gateway has seen register, running or not">
    <UiAlert v-if="error" kind="error" class="mb-4" data-test="modules-error">{{ error }}</UiAlert>
    <UiAlert v-if="partial" kind="warning" class="mb-4" data-test="modules-partial">The module record is unavailable; only modules registered now are listed.</UiAlert>
    <p class="mb-3 text-sm" data-test="down-count">{{ down }} expected module{{ down === 1 ? ' is' : 's are' }} down.</p>
    <UiCard :padded="false">
      <UiDataTable :items="items" :total="items.length" :page="1" :page-size="Math.max(items.length, 1)" :loading="loading" :columns="columns" row-key="module" caption="Modules" empty-title="No modules seen yet" :row-attrs="(r) => ({ 'data-test': 'mod-' + r.module })" data-test="modules">
        <template #cell-state="{ row }"><UiStatusChip :status="String(row.state)" :colors="{ down: 'error', stopped: 'neutral', draining: 'warning', unhealthy: 'warning' }" :data-test="'state-' + row.module" /></template>
        <template #cell-expected="{ row }">
          <UiSwitch :id="'expected-' + row.module" :model-value="row.expected" :label="row.expected ? 'Yes' : 'No'" :disabled="busy === row.module" :data-test="'expected-' + row.module" @update:model-value="(v: boolean) => setExpected(row, v)" />
        </template>
        <template #actions="{ row }">
          <UiButton v-if="canManage && !row.registered" size="sm" variant="text" color="error" :loading="busy === row.module" :data-test="'forget-' + row.module" @click="forgetFor = row">Forget</UiButton>
        </template>
      </UiDataTable>
    </UiCard>
    <UiDialog :model-value="!!forgetFor" :title="forgetFor ? `Forget ${forgetFor.module}` : ''" size="sm" @update:model-value="forgetFor = null">
      <p class="text-sm" data-test="forget-dialog">The module is removed from this list. If it registers again later, it reappears.</p>
      <template #actions>
        <UiButton variant="text" data-test="forget-cancel" @click="forgetFor = null">Cancel</UiButton>
        <UiButton color="error" :loading="!!busy" data-test="forget-confirm" @click="forget()">Forget</UiButton>
      </template>
    </UiDialog>
  </UiPage>
</template>
