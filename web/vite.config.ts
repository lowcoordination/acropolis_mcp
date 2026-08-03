import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    outDir: 'dist',
  },
  server: {
    proxy: {
      // In dev, proxy API calls to a locally-running Argus backend (python -m argus)
      // so `npm run dev` doesn't need CORS handling.
      '/api': 'http://localhost:8000',
      '/mcp': 'http://localhost:8000',
    },
  },
})
