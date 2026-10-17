import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'

// Django serves the bundle from STATIC_URL; the dev server has to serve the app
// at the origin root, because a '/static/' base would move every client route.
// Vite bakes whichever base is in effect into index.html, so the source stays
// base-agnostic.
const DJANGO_ORIGIN = process.env.LOCALCA_API_TARGET || 'http://127.0.0.1:18001'

export default defineConfig(({ command }) => ({
  base: command === 'build' ? '/static/' : '/',

  plugins: [vue(), tailwindcss()],

  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },

  build: {
    // Named by settings.FRONTEND_DIST, which adds it to TEMPLATES and static files.
    outDir: 'dist',
    emptyOutDir: true,
    assetsDir: 'assets',
    sourcemap: false,
    rollupOptions: {
      output: {
        // Hashed names make a rebuilt bundle impossible to serve from cache.
        // index.html carries them, so nothing needs a manifest.
        entryFileNames: 'assets/[name]-[hash].js',
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash][extname]',
      },
    },
  },

  server: {
    port: 5173,
    strictPort: true,
    // One origin in development too, so the session cookie and CSRF behave
    // exactly as they do behind Django.
    proxy: {
      '/api': { target: DJANGO_ORIGIN, changeOrigin: false },
      '/static/admin': { target: DJANGO_ORIGIN, changeOrigin: false },
    },
  },
}))
