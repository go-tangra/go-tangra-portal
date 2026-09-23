import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'
import { federation } from '@module-federation/vite'
import { hostConfig } from './module-federation.config'

// The shell is served by the gateway at /; remotes are loaded at runtime from
// /m/<module>/mf-manifest.json (same origin). In development, API calls are
// proxied to the gateway's edge listener. Vuetify stays only for legacy remotes
// (transitional, see ui/MIGRATION.md).
export default defineConfig({
  base: '/',
  resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) } },
  plugins: [vue(), tailwindcss(), federation(hostConfig)],
  server: {
    proxy: {
      '/gateway': { target: 'https://127.0.0.1:8443', secure: false },
      '/api': { target: 'https://127.0.0.1:8443', secure: false },
      '/m': { target: 'https://127.0.0.1:8443', secure: false },
    },
  },
  build: { outDir: 'dist', emptyOutDir: true, sourcemap: false, target: 'esnext' },
  test: {
    environment: 'jsdom',
    environmentOptions: { jsdom: { url: 'https://localhost/' } },
    include: ['tests/unit/**/*.spec.ts'],
    setupFiles: ['tests/unit/setup.ts'],
    server: { deps: { inline: ['@freya/ui'] } },
  },
})
