// Shared singletons every remote must declare identically (specs/003 contracts/federation.md,
// amended by specs/013 contracts/federation-changes.md).
export const shared = {
  vue: { singleton: true, requiredVersion: '^3.5.0' },
  'vue-router': { singleton: true, requiredVersion: '^5.0.0' },
  pinia: { singleton: true, requiredVersion: '^4.0.0' },
  '@casl/ability': { singleton: true, requiredVersion: '^7.0.0' },
  '@casl/vue': { singleton: true, requiredVersion: '^3.0.0' },
  zod: { singleton: true, requiredVersion: '^4.0.0', strictVersion: true },
  '@go-tangra/ui': { singleton: true, requiredVersion: '^4.0.0', strictVersion: true },
  '@go-tangra/ui/forms': { singleton: true, requiredVersion: '^4.0.0', strictVersion: true },
  '@go-tangra/ui/api': { singleton: true, requiredVersion: '^4.0.0', strictVersion: true },
}

export const hostConfig = {
  name: 'shell',
  // Remotes are registered at runtime from /gateway/v1/me/modules; nothing is pinned here.
  remotes: {},
  shared,
}
