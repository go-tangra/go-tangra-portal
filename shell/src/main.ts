import { createApp } from 'vue'
import { createPinia } from 'pinia'
import '@fontsource-variable/inter' // bundled typeface (CSP font-src 'self')
import './main.css'
import App from './App.vue'
import { router } from '@/router'
import { installAbilities } from '@/casl/ability'
import { boot } from '@/federation/boot'

const app = createApp(App).use(createPinia())
installAbilities(app)
app.use(router)
void boot(router).finally(() => app.mount('#app'))
