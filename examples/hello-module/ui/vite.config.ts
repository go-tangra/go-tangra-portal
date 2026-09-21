import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import vuetify from 'vite-plugin-vuetify'
import { federation } from '@module-federation/vite'

// The hello module UI is a federated remote served by the module under /ui/
// and relayed by the gateway at /m/hello/. Shared singletons must match the
// platform shell (services/gateway/shell/module-federation.config.ts).
export default defineConfig({
  base: '/m/hello/',
  resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) } },
  plugins: [
    vue(),
    vuetify({ autoImport: true }),
    federation({
      name: 'hello',
      filename: 'remoteEntry.js',
      manifest: true,
      exposes: { './routes': './src/remote/routes.ts' },
      shared: {
        vue: { singleton: true, requiredVersion: '^3.5.0' },
        'vue-router': { singleton: true, requiredVersion: '^5.0.0' },
        pinia: { singleton: true, requiredVersion: '^4.0.0' },
        vuetify: { singleton: true, requiredVersion: '^4.0.0' },
        '@casl/ability': { singleton: true, requiredVersion: '^7.0.0' },
        '@casl/vue': { singleton: true, requiredVersion: '^3.0.0' },
      },
    }),
  ],
  build: { outDir: 'dist', emptyOutDir: true, target: 'esnext' },
})
