// Gateway operations forms (specs/003 contracts/gateway.yaml ops section).
import { z } from 'zod'
import { nonEmpty } from '@go-tangra/ui/forms'

/** "a, b ,c" → ["a","b","c"]; at least one entry. */
const csvList = z
  .string()
  .transform((s) => s.split(',').map((x) => x.trim()).filter(Boolean))
  .pipe(z.array(z.string().max(200)).min(1, 'Enter at least one value.'))
  .meta({ kind: 'text' })

export const allowEntrySchema = z.object({
  spiffe_id: nonEmpty(300).refine((s) => s.startsWith('spiffe://'), 'Must be a SPIFFE ID (spiffe://…).'),
  prefixes: csvList,
  names: csvList,
})
export type AllowEntryInput = z.output<typeof allowEntrySchema>

export const revokeSchema = z.object({
  reason: z.string().trim().min(10, 'Give a reason of at least 10 characters.').max(500),
})
export type RevokeInput = z.output<typeof revokeSchema>

/** Lifetimes offered for an enrolment token (auth caps them at 30 minutes). */
export const ENROLL_TTLS = [5, 10, 15, 30] as const

const serviceName = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/
/** A service name ("sms-gw") or a SPIFFE id ("spiffe://<td>/svc/sms-gw"). */
const serviceRef = z.string().refine((s) => serviceName.test(s) || /^spiffe:\/\/[^/]+\/svc\/[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(s), 'Use a service name like sms-gw or a SPIFFE ID spiffe://<trust domain>/svc/<name>.')

export const enrollmentSchema = z.object({
  services: z
    .string()
    .transform((s) => s.split(',').map((x) => x.trim()).filter(Boolean))
    .pipe(z.array(serviceRef).min(1, 'Enter at least one service.').max(10, 'At most 10 services per token.'))
    .meta({ kind: 'text' }),
  ttl: z.enum(['5', '10', '15', '30']),
  tenant_id: z
    .string()
    .trim()
    .refine((s) => s === '' || /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(s), 'Must be a tenant id (UUID).'),
})
export type EnrollmentInput = z.output<typeof enrollmentSchema>
