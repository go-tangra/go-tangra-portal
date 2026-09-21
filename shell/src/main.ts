import { createApp } from 'vue'
import { createPinia } from 'pinia'
import { createVuetify } from 'vuetify'
import 'vuetify/styles'
import '@mdi/font/css/materialdesignicons.css' // icon font (mdi-* names), bundled: CSP font-src 'self'
import '@fontsource-variable/inter' // Materio's typeface, bundled for the same reason
import '@/theme/materio.css'
import App from './App.vue'
import { router } from '@/router'
import { installAbilities } from '@/casl/ability'
import { boot } from '@/federation/boot'
import { materioTheme, storedTheme } from '@/theme/materio'

// Browsers hide the nonce attribute once CSP is active; read the property.
const cspNonce = document.querySelector<HTMLMetaElement>('meta[property="csp-nonce"]')?.nonce || undefined
const vuetify = createVuetify(materioTheme(storedTheme() ?? 'light', cspNonce))

const app = createApp(App).use(createPinia()).use(vuetify)
installAbilities(app)
app.use(router)
void boot(router).finally(() => app.mount('#app'))

