<script setup lang="ts">
// Add-module wizard (spec 036): asks for the inputs the module's catalogue
// entry declares, downloads the join bundle the gateway renders (token,
// allow-list and every core value included), then follows the install:
// token used, registered, active.
import { computed, onBeforeUnmount, reactive, ref, watch } from 'vue'
import { UiAlert, UiButton, UiDialog, UiInput } from '@go-tangra/ui'
import { csrfToken, CSRF_HEADER } from '@/api/client'
import { api } from '@/api/client'
import type { components } from '@/api/schema'

type Item = components['schemas']['CatalogueItem']
type Progress = components['schemas']['JoinProgress']

const props = defineProps<{ item: Item | null }>()
const emit = defineEmits<{ (e: 'close'): void; (e: 'installed'): void }>()

const values = reactive<Record<string, string>>({})
const ttl = ref('24')
const busy = ref(false)
const error = ref('')
const joinId = ref('')
const progress = ref<Progress | null>(null)
let timer: ReturnType<typeof setInterval> | null = null

const open = computed(() => !!props.item)
const minCore = computed(() => Object.entries(props.item?.min_core ?? {}).map(([k, v]) => `${k} ${v}`).join(', '))

watch(() => props.item, (it) => {
  stop()
  joinId.value = ''
  progress.value = null
  error.value = ''
  for (const k of Object.keys(values)) delete values[k]
  for (const h of it?.host_inputs ?? []) values[h.key] = h.default ?? ''
}, { immediate: true })

function stop(): void {
  if (timer) clearInterval(timer)
  timer = null
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

async function download(): Promise<void> {
  const it = props.item
  if (!it) return
  busy.value = true
  error.value = ''
  try {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' }
    const tok = csrfToken()
    if (tok) headers[CSRF_HEADER] = tok
    const res = await fetch(`/gateway/v1/ops/catalogue/${it.module}/join`, {
      method: 'POST', credentials: 'same-origin', headers,
      body: JSON.stringify({ inputs: { ...values }, ttl_hours: Number(ttl.value) }),
    })
    if (!res.ok) {
      let reason = `HTTP ${res.status}`
      try {
        const b = await res.json() as { reason?: string; detail?: { param?: string } }
        reason = b.detail?.param ? `${b.reason}: ${b.detail.param}` : (b.reason ?? reason)
      } catch { /* not JSON */ }
      error.value = res.status === 409 ? 'A different allow-list entry exists for this module; resolve it on the Allow-list page.' : reason
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
    stop()
    timer = setInterval(() => void poll(), 5000)
  } catch {
    error.value = 'network'
  } finally {
    busy.value = false
  }
}

function step(done: boolean | undefined): string {
  return done ? 'done' : 'waiting'
}

onBeforeUnmount(stop)
</script>

<template>
  <UiDialog :model-value="open" :title="item ? `Add ${item.display_name || item.module} ${item.latest_version ?? ''}` : ''" size="md" @update:model-value="emit('close')">
    <div v-if="item" data-test="join-wizard">
      <template v-if="!joinId">
        <p class="mb-3 text-sm">The gateway renders a ready-to-run bundle for the module host: core addresses, issuer and trust domain from this core, a single-use join token and the allow-list entry. Unzip it there and run <code>docker compose up -d</code>.</p>
        <UiAlert v-if="minCore" kind="info" class="mb-3">Needs at least {{ minCore }}.</UiAlert>
        <UiInput v-for="h in item.host_inputs ?? []" :id="'input-' + h.key" :key="h.key" v-model="values[h.key]" :label="h.label" :hint="h.key" class="mb-2" :data-test="'input-' + h.key" />
        <UiInput id="join-ttl" v-model="ttl" type="number" label="Join token valid for (hours, 1-24)" class="mb-2" data-test="join-ttl" />
        <UiAlert v-if="error" kind="error" class="mt-2" data-test="join-error">{{ error }}</UiAlert>
      </template>
      <template v-else>
        <p class="mb-3 text-sm">Bundle downloaded. On the module host: <code>unzip {{ item.module }}-join.zip &amp;&amp; cd {{ item.module }} &amp;&amp; docker compose up -d</code></p>
        <ul class="text-sm" data-test="join-progress">
          <li data-test="step-token">Join token used: {{ step(progress?.token_used) }}</li>
          <li data-test="step-registered">Registered with the gateway: {{ step(progress?.registered) }}<span v-if="progress?.state"> ({{ progress.state }})</span></li>
        </ul>
        <UiAlert v-if="progress?.last_refusal" kind="warning" class="mt-2" data-test="join-refusal">Registration refused: {{ progress.last_refusal.reason }}</UiAlert>
      </template>
    </div>
    <template #actions>
      <UiButton variant="text" data-test="join-close" @click="emit('close')">{{ joinId ? 'Close' : 'Cancel' }}</UiButton>
      <UiButton v-if="!joinId" :loading="busy" data-test="join-download" @click="download()">Download bundle</UiButton>
    </template>
  </UiDialog>
</template>
