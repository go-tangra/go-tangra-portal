<script setup lang="ts">
// Add-module wizard (spec 036): asks for the inputs the module's catalogue
// entry declares, downloads the join bundle the gateway renders (token,
// allow-list and every core value included), then follows the install:
// token used, registered, active. Spec 037: the bundle can instead be
// delivered to a host through its enrolled inventory agent; the wizard then
// also follows the delivery (queued, fetched, written).
import { computed, onBeforeUnmount, reactive, ref, watch } from 'vue'
import { UiAlert, UiButton, UiDialog, UiInput, UiSelect, type SelectOption } from '@go-tangra/ui'
import { csrfToken, CSRF_HEADER } from '@/api/client'
import { api } from '@/api/client'
import type { components } from '@/api/schema'

type Item = components['schemas']['CatalogueItem']
type Progress = components['schemas']['JoinProgress']
type Target = components['schemas']['ModuleTarget']
type Delivery = components['schemas']['ModuleDelivery']

const props = defineProps<{ item: Item | null; canDeliver?: boolean }>()
const emit = defineEmits<{ (e: 'close'): void; (e: 'installed'): void }>()

const values = reactive<Record<string, string>>({})
const ttl = ref('24')
const busy = ref(false)
const error = ref('')
const joinId = ref('')
const progress = ref<Progress | null>(null)
const channel = ref<'download' | 'agent'>('download')
const query = ref('')
const targets = ref<Target[]>([])
const searched = ref(false)
const hostId = ref('')
const prefilled = reactive<Record<string, string>>({})
let timer: ReturnType<typeof setInterval> | null = null

const open = computed(() => !!props.item)
const minCore = computed(() => Object.entries(props.item?.min_core ?? {}).map(([k, v]) => `${k} ${v}`).join(', '))
const channelOptions: SelectOption[] = [
  { title: 'Download the bundle', value: 'download' },
  { title: 'Deliver to a host (inventory agent)', value: 'agent' },
]
const capabilityText: Record<string, string> = {
  disabled_on_host: 'module delivery is turned off in the agent configuration',
  upgrade_required: 'the agent is too old',
  not_supported_platform: 'not supported on this platform',
  no_agent: 'no enrolled agent',
  ambiguous_agent: 'more than one agent claims the host',
  disabled_on_server: 'module delivery is turned off on the inventory',
}
const eligible = computed(() => targets.value.filter((t) => t.capability === 'enabled'))
const ineligible = computed(() => targets.value.filter((t) => t.capability !== 'enabled'))
const hostOptions = computed<SelectOption[]>(() => eligible.value.map((t) => ({
  title: `${t.hostname} · ${t.os_name}${t.agent_online ? '' : ' (offline: delivered when it reconnects)'}`, value: t.host_id,
})))
const delivery = computed<Delivery | undefined>(() => progress.value?.delivery)

watch(() => props.item, (it) => {
  stop()
  joinId.value = ''
  progress.value = null
  error.value = ''
  channel.value = 'download'
  targets.value = []
  searched.value = false
  hostId.value = ''
  query.value = ''
  for (const k of Object.keys(values)) delete values[k]
  for (const k of Object.keys(prefilled)) delete prefilled[k]
  for (const h of it?.host_inputs ?? []) values[h.key] = h.default ?? ''
}, { immediate: true })

// Pre-fill *_HOST with the host name and *_IP with its first address, unless
// the administrator typed something else.
watch(hostId, (id) => {
  const t = targets.value.find((x) => x.host_id === id)
  if (!t) return
  for (const h of props.item?.host_inputs ?? []) {
    let v = ''
    if (h.key.endsWith('_HOST')) v = t.hostname
    else if (h.key.endsWith('_IP')) v = t.ip_addresses[0] ?? ''
    if (!v) continue
    if (values[h.key] === '' || values[h.key] === (h.default ?? '') || values[h.key] === prefilled[h.key]) {
      values[h.key] = v
      prefilled[h.key] = v
    }
  }
})

function stop(): void {
  if (timer) clearInterval(timer)
  timer = null
}

function headers(): Record<string, string> {
  const h: Record<string, string> = { 'Content-Type': 'application/json' }
  const tok = csrfToken()
  if (tok) h[CSRF_HEADER] = tok
  return h
}

async function refusal(res: Response): Promise<string> {
  let reason = `HTTP ${res.status}`
  try {
    const b = await res.json() as { reason?: string; detail?: { param?: string; reason?: string } }
    if (res.status === 409 && b.detail?.reason) return `This host can't receive the module: ${capabilityText[b.detail.reason] ?? b.detail.reason}.`
    if (res.status === 409) return 'A different allow-list entry exists for this module; resolve it on the Allow-list page.'
    reason = b.detail?.param ? `${b.reason}: ${b.detail.param}` : (b.reason ?? reason)
  } catch { /* not JSON */ }
  return reason
}

async function poll(): Promise<void> {
  if (!props.item || !joinId.value) return
  try {
    progress.value = await api<Progress>('GET', `/gateway/v1/ops/catalogue/${props.item.module}/join/${joinId.value}`)
    if (progress.value.registered && progress.value.state === 'active') {
      stop()
      emit('installed')
    }
  } catch {
    /* transient: keep polling */
  }
}

function follow(): void {
  stop()
  timer = setInterval(() => void poll(), 5000)
}

async function search(): Promise<void> {
  const it = props.item
  if (!it) return
  busy.value = true
  error.value = ''
  try {
    // fetch, not api(): a 503 here means "not available", not an outage.
    const res = await fetch(`/gateway/v1/ops/catalogue/${it.module}/targets?q=${encodeURIComponent(query.value)}`, { credentials: 'same-origin' })
    if (!res.ok) {
      error.value = res.status === 503 ? 'The inventory is not reachable or agent delivery is not configured.' : await refusal(res)
      return
    }
    targets.value = ((await res.json()) as { hosts: Target[] }).hosts
    searched.value = true
    if (!eligible.value.some((t) => t.host_id === hostId.value)) hostId.value = eligible.value[0]?.host_id ?? ''
  } catch {
    error.value = 'network'
  } finally {
    busy.value = false
  }
}

async function deliver(): Promise<void> {
  const it = props.item
  if (!it || !hostId.value) return
  busy.value = true
  error.value = ''
  try {
    const res = await fetch(`/gateway/v1/ops/catalogue/${it.module}/deliver`, {
      method: 'POST', credentials: 'same-origin', headers: headers(),
      body: JSON.stringify({ host_id: hostId.value, inputs: { ...values }, ttl_hours: Number(ttl.value) }),
    })
    if (!res.ok) {
      error.value = await refusal(res)
      return
    }
    const out = await res.json() as { join_id: string; delivery: Delivery }
    joinId.value = out.join_id
    progress.value = { id: out.join_id, module: it.module, version: it.latest_version ?? '', created_at: '', expires_at: '', token_used: false, registered: false,
      channel: 'agent', delivery: out.delivery }
    follow()
  } catch {
    error.value = 'network'
  } finally {
    busy.value = false
  }
}

async function download(): Promise<void> {
  const it = props.item
  if (!it) return
  busy.value = true
  error.value = ''
  try {
    const res = await fetch(`/gateway/v1/ops/catalogue/${it.module}/join`, {
      method: 'POST', credentials: 'same-origin', headers: headers(),
      body: JSON.stringify({ inputs: { ...values }, ttl_hours: Number(ttl.value) }),
    })
    if (!res.ok) {
      error.value = await refusal(res)
      return
    }
    joinId.value = res.headers.get('X-Join-Id') ?? ''
    const blob = await res.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${it.module}-join.zip`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
    follow()
  } catch {
    error.value = 'network'
  } finally {
    busy.value = false
  }
}

function step(done: boolean | undefined): string {
  return done ? 'done' : 'waiting'
}

const deliveryText: Record<string, string> = {
  pending: 'queued for the agent', delivered: 'sent to the agent', fetched: 'agent is writing the bundle', installed: 'written on the host',
  failed: 'failed', hook_failed: 'written, but the host hook failed', unsupported: 'the host cannot receive it', superseded: 'replaced by a newer delivery',
  expired: 'expired before the agent fetched it',
}
const deliveryFailed = computed(() => ['failed', 'hook_failed', 'unsupported', 'expired'].includes(delivery.value?.state ?? ''))

onBeforeUnmount(stop)
</script>

<template>
  <UiDialog :model-value="open" :title="item ? `Add ${item.display_name || item.module} ${item.latest_version ?? ''}` : ''" size="md" @update:model-value="emit('close')">
    <div v-if="item" data-test="join-wizard">
      <template v-if="!joinId">
        <p class="mb-3 text-sm">The gateway renders a ready-to-run bundle for the module host: core addresses, issuer and trust domain from this core, a single-use join token and the allow-list entry.</p>
        <UiSelect v-if="canDeliver" id="join-channel" v-model="channel" label="How" :options="channelOptions" :clearable="false" class="mb-3" data-test="join-channel" />
        <template v-if="channel === 'agent'">
          <p class="mb-2 text-sm">The host's enrolled inventory agent fetches the bundle and writes it to its modules directory; the token is minted only then. The agent starts the module only if its owner configured a deploy hook.</p>
          <div class="mb-2 flex items-end gap-2">
            <UiInput id="join-host-query" v-model="query" label="Host name contains" class="grow" data-test="join-host-query" @keyup.enter="search()" />
            <UiButton variant="text" :loading="busy" data-test="join-host-search" @click="search()">Find hosts</UiButton>
          </div>
          <UiSelect v-if="hostOptions.length" id="join-host" v-model="hostId" label="Host" :options="hostOptions" :clearable="false" class="mb-2" data-test="join-host" />
          <UiAlert v-else-if="searched" kind="info" class="mb-2" data-test="join-no-hosts">No host found that can receive modules.</UiAlert>
          <details v-if="ineligible.length" class="mb-3 text-sm" data-test="join-ineligible">
            <summary>{{ ineligible.length }} host(s) can't receive modules</summary>
            <ul><li v-for="t in ineligible" :key="t.host_id">{{ t.hostname }}: {{ capabilityText[t.capability] ?? t.capability }}</li></ul>
          </details>
        </template>
        <p v-else class="mb-3 text-sm">Unzip it on the module host and run <code>docker compose up -d</code>.</p>
        <UiAlert v-if="minCore" kind="info" class="mb-3">Needs at least {{ minCore }}.</UiAlert>
        <UiInput v-for="h in item.host_inputs ?? []" :id="'input-' + h.key" :key="h.key" v-model="values[h.key]" :label="h.label" :hint="h.key" class="mb-2" :data-test="'input-' + h.key" />
        <UiInput id="join-ttl" v-model="ttl" type="number" :label="channel === 'agent' ? 'Delivery valid for (hours, 1-24)' : 'Join token valid for (hours, 1-24)'" class="mb-2" data-test="join-ttl" />
        <UiAlert v-if="error" kind="error" class="mt-2" data-test="join-error">{{ error }}</UiAlert>
      </template>
      <template v-else>
        <p v-if="progress?.channel !== 'agent'" class="mb-3 text-sm">Bundle downloaded. On the module host: <code>unzip {{ item.module }}-join.zip &amp;&amp; cd {{ item.module }} &amp;&amp; docker compose up -d</code></p>
        <ul class="text-sm" data-test="join-progress">
          <li v-if="delivery" data-test="step-delivery">Delivery to {{ delivery.hostname }}: {{ deliveryText[delivery.state] ?? delivery.state }}<span v-if="delivery.reason"> ({{ delivery.reason }})</span><span v-if="!delivery.agent_online && delivery.state === 'pending'">, agent offline</span></li>
          <li data-test="step-token">Join token used: {{ step(progress?.token_used) }}</li>
          <li data-test="step-registered">Registered with the gateway: {{ step(progress?.registered) }}<span v-if="progress?.state"> ({{ progress.state }})</span></li>
        </ul>
        <UiAlert v-if="delivery?.state === 'installed' && !progress?.token_used" kind="info" class="mt-2" data-test="join-start-hint">The bundle is in the agent's modules directory on {{ delivery.hostname }}. If the host has no deploy hook, start it there with <code>docker compose up -d</code>.</UiAlert>
        <UiAlert v-if="deliveryFailed" kind="error" class="mt-2" data-test="join-delivery-failed">The delivery did not complete. Fix the cause on the host, then deliver again.</UiAlert>
        <UiAlert v-if="progress?.last_refusal" kind="warning" class="mt-2" data-test="join-refusal">Registration refused: {{ progress.last_refusal.reason }}</UiAlert>
      </template>
    </div>
    <template #actions>
      <UiButton variant="text" data-test="join-close" @click="emit('close')">{{ joinId ? 'Close' : 'Cancel' }}</UiButton>
      <UiButton v-if="!joinId && channel === 'download'" :loading="busy" data-test="join-download" @click="download()">Download bundle</UiButton>
      <UiButton v-if="!joinId && channel === 'agent'" :loading="busy" :disabled="!hostId" data-test="join-deliver" @click="deliver()">Deliver</UiButton>
    </template>
  </UiDialog>
</template>
