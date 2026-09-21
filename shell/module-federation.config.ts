// Shared singletons every remote must declare identically (contracts/federation.md).
export const shared = {
  vue: { singleton: true, requiredVersion: '^3.5.0' },
  'vue-router': { singleton: true, requiredVersion: '^5.0.0' },
  pinia: { singleton: true, requiredVersion: '^4.0.0' },
  vuetify: { singleton: true, requiredVersion: '^4.0.0' },
  '@casl/ability': { singleton: true, requiredVersion: '^7.0.0' },
  '@casl/vue': { singleton: true, requiredVersion: '^3.0.0' },
}

export const hostConfig = {
  name: 'shell',
  // Remotes are registered at runtime from /gateway/v1/me/modules; nothing is pinned here.
  remotes: {},
  shared,
}
