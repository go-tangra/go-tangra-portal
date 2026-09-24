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
