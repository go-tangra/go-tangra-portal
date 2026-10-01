/**
 * Release label for a module: the build version(s) its instances report
 * (e.g. "4.10.2", or "4.10.1 → 4.10.2" during a rollout). Empty when no
 * instance reported one — never the manifest contract version, which is not
 * the release a user can relate to.
 */
export function releaseLabel(m: { build_version?: string; build_versions?: string[] | null }): string {
  const all = (m.build_versions ?? []).filter((v) => v !== '')
  if (all.length > 1) return all.join(' → ')
  return all[0] ?? m.build_version ?? ''
}
