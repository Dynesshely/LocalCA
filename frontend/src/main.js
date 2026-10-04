import { createApp } from 'vue'
import { createPinia } from 'pinia'

import App from './App.vue'
import router from './router'
import { i18n, setLocale } from './i18n'
import './style.css'

const app = createApp(App)
app.use(createPinia())
app.use(i18n)
app.use(router)

// Apply the detected locale through the same path the switcher uses, so
// `<html lang>` matches the active catalogues from the very first render.
setLocale(i18n.global.locale.value)

app.mount('#app')
