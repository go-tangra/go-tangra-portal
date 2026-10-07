<script setup lang="ts">
// Mints single-use lcm enrolment (join) tokens for services of this trust
// domain: the console equivalent of `authsvc mint-enrollment-token`. The token
// is shown once, in this page's memory only, and is never stored.
import { computed, onBeforeUnmount, ref } from 'vue'
import { UiPage, UiAlert, UiCard, UiForm, UiInput, UiSelect, UiButton, UiKeyValueTable, UiTextarea, type SelectOption } from '@go-tangra/ui'
import { useZodForm } from '@go-tangra/ui/forms'
import { api } from '@/api/client'
import { enrollmentSchema, ENROLL_TTLS } from '@/schemas/ops'

/** POST /gateway/v1/ops/enrollment-tokens. */
interface EnrollmentToken {
  token: string
  expires_at: string
  spiffe_ids: string[]
  tenant_id: string
}

const MESH_TENANT = '00000000-0000-0000-0000-000000000001'
const minted = ref<EnrollmentToken | null>(null)
const error = ref('')
const copied = ref(false)
let copiedTimer: ReturnType<typeof setTimeout> | undefined

const ttlOptions: SelectOption[] = ENROLL_TTLS.map((m) => ({ title: m + ' minutes', value: String(m) }))
const form = useZodForm(enrollmentSchema, {
  initial: { services: '', ttl: '30', tenant_id: '' },
  onSubmit: (v) =>
    api<EnrollmentToken>('POST', '/gateway/v1/ops/enrollment-tokens', { services: v.services, ttl_seconds: Number(v.ttl) * 60, ...(v.tenant_id ? { tenant_id: v.tenant_id } : {}) }),
  // Refusals (validation, forbidden, auth unreachable) are shown by UiForm.
  onSuccess: (t) => {
    minted.value = t
    error.value = ''
    copied.value = false
  },
})

const details = computed(() =>
  minted.value
    ? [
        { label: 'For', value: minted.value.spiffe_ids.join(', ') },
        { label: 'Tenant', value: minted.value.tenant_id === MESH_TENANT ? minted.value.tenant_id + ' (mesh)' : minted.value.tenant_id },
        { label: 'Expires', value: new Date(minted.value.expires_at).toLocaleString() },
      ]
    : [],
)
async function copy(): Promise<void> {
  if (!minted.value) return
  try {
    await navigator.clipboard.writeText(minted.value.token)
    copied.value = true
    if (copiedTimer) clearTimeout(copiedTimer)
    copiedTimer = setTimeout(() => (copied.value = false), 1500)
  } catch {
    error.value = 'Copying failed: select the token and copy it by hand.'
  }
}
function another(): void {
  minted.value = null
  form.reset({ services: '', ttl: '30', tenant_id: '' })
}
onBeforeUnmount(() => {
  if (copiedTimer) clearTimeout(copiedTimer)
  minted.value = null
})
</script>

<template>
  <UiPage title="Enrolment tokens" subtitle="Single-use join tokens a service presents to lcm for its first mesh identity (SVID)">
    <UiAlert v-if="error" kind="error" class="mb-4" data-test="enroll-error">{{ error }}</UiAlert>
    <UiCard v-if="!minted" class="mb-4">
      <UiForm :form="form" data-test="enroll-form">
        <div class="grid grid-cols-1 gap-3 md:grid-cols-12 md:items-end">
          <div class="md:col-span-6"><UiInput v-bind="form.field('services')" label="Services (comma separated)" placeholder="sms-gw" required data-test="enroll-services" /></div>
          <div class="md:col-span-3"><UiSelect v-bind="form.field('ttl')" label="Valid for" :options="ttlOptions" :clearable="false" data-test="enroll-ttl" /></div>
          <div class="md:col-span-3"><UiButton type="submit" block :loading="form.submitting.value" icon="mdi-key-plus" data-test="enroll-mint">Mint token</UiButton></div>
          <div class="md:col-span-6"><UiInput v-bind="form.field('tenant_id')" label="Tenant (optional)" :placeholder="MESH_TENANT + ' (mesh)'" data-test="enroll-tenant" /></div>
        </div>
        <p class="mt-3 text-xs text-base-content/70">A name like <code>sms-gw</code> becomes <code>spiffe://&lt;trust domain&gt;/svc/sms-gw</code>. Leave the tenant empty for the mesh tenant, which every service normally uses.</p>
      </UiForm>
    </UiCard>
    <UiCard v-else title="Token minted" data-test="enroll-result">
      <UiAlert kind="warning" class="mb-3">Copy it now: the token is shown only once, works only once, and expires {{ new Date(minted.expires_at).toLocaleTimeString() }}.</UiAlert>
      <UiKeyValueTable :items="details" class="mb-3" data-test="enroll-details" />
      <UiTextarea id="enroll-token" :model-value="minted.token" label="Enrolment token" readonly :rows="4" class="font-mono" data-test="enroll-token" />
      <p class="mt-2 text-xs text-base-content/70">Give it to the service as its enrolment token (the file its <code>enroll.token_file</code> setting names) and start it before the token expires.</p>
      <div class="mt-3 flex flex-wrap gap-2">
        <UiButton :icon="copied ? 'mdi-check' : 'mdi-content-copy'" data-test="enroll-copy" @click="copy">{{ copied ? 'Copied' : 'Copy token' }}</UiButton>
        <UiButton variant="text" data-test="enroll-another" @click="another">Mint another</UiButton>
      </div>
    </UiCard>
  </UiPage>
</template>
