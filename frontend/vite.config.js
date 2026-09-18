import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'

/**
 * LocalCA is served by Django in production and by Vite during development, and
 * the two need different base paths:
 *
 *   build  -> '/static/'  : Django serves the bundle from STATIC_URL, so the
 *                           asset URLs written into index.html must carry that
 *                           prefix.
 *   serve  -> '/'         : the dev server must serve the app at the origin
 *                           root. A '/static/' base would move the whole app
 *                           (and therefore every client route) under /static/,
 *                           which does not match the router's paths.
 *
 * Vite rewrites the configured base into index.html while serving, so the
 * source index.html stays base-agnostic.
 */
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
    // Django picks this directory up by name: settings.FRONTEND_DIST adds it to
    // TEMPLATES['DIRS'] and STATICFILES_DIRS. Entry filenames are fixed (no
    // content hashes) so the shell can reference them without reading a manifest.
    outDir: 'dist',
    emptyOutDir: true,
    assetsDir: 'assets',
    sourcemap: false,
    rollupOptions: {
      output: {
        entryFileNames: 'assets/app.js',
        chunkFileNames: 'assets/[name].js',
        // Pin the stylesheet name too: Vite otherwise names it after its source
        // file, and Django's shell references assets by path.
        assetFileNames: (assetInfo) =>
          (assetInfo.names || [assetInfo.name]).some((n) => n && n.endsWith('.css'))
            ? 'assets/app.css'
            : 'assets/[name][extname]',
      },
    },
  },

  server: {
    port: 5173,
    strictPort: true,
    // Proxy the API to Django so the SPA runs on a single origin during
    // development, which is what makes the session cookie and CSRF work exactly
    // as they do in production.
    proxy: {
      '/api': { target: DJANGO_ORIGIN, changeOrigin: false },
      '/static/admin': { target: DJANGO_ORIGIN, changeOrigin: false },
    },
  },
}))
