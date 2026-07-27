import { defineConfig } from 'astro/config'
import react from '@astrojs/react'
import tailwindcss from '@tailwindcss/vite'

// GitHub Pages project site. The repository is literally named "Cloister-" (trailing
// hyphen), so that is the base path; every internal link goes through BASE_URL rather
// than being written as an absolute "/" path, or it breaks in production and not in dev.
export default defineConfig({
  site: 'https://adityakumar0927.github.io',
  base: '/Cloister-',
  trailingSlash: 'ignore',
  output: 'static',
  integrations: [react()],
  vite: {
    plugins: [tailwindcss()],
    // WebLLM ships a WASM/WebGPU runtime and must not be pre-bundled into the SSR pass.
    ssr: { noExternal: [] },
    optimizeDeps: { exclude: ['@mlc-ai/web-llm'] },
  },
  build: { inlineStylesheets: 'auto' },
})
