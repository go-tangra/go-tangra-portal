import type { RouteRecordRaw } from 'vue-router'

// Routes mounted by the platform shell under the module's navigation root.
export const routes: RouteRecordRaw[] = [
  { path: '/hello', name: 'hello:home', component: () => import('@/views/Hello.vue') },
]
export default routes
