// Standalone preview entry (development only); in the platform the remote is
// composed by the shell through ./routes and never mounts itself.
import { createApp } from 'vue'
import { createPinia } from 'pinia'
import { createRouter, createWebHistory } from 'vue-router'
import { createVuetify } from 'vuetify'
import { createMongoAbility } from '@casl/ability'
import { abilitiesPlugin } from '@casl/vue'
import 'vuetify/styles'
import { routes } from './remote/routes'

const app = createApp({ template: '<v-app><v-main><router-view /></v-main></v-app>' })
app.use(createPinia()).use(createVuetify()).use(createRouter({ history: createWebHistory('/m/hello/'), routes }))
app.use(abilitiesPlugin, createMongoAbility([{ action: 'create', subject: 'Greeting' }]), { useGlobalProperties: true })
app.mount('#app')
