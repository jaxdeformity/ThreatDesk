import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'node:path'

// Build output lands in ../web-dist, which the FastAPI app serves.
// During dev, Vite proxies /api to uvicorn on THREATDESK_PORT (8444).
const apiPort = process.env.THREATDESK_PORT || '8444'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { '@': path.resolve(__dirname, './src') },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': { target: `http://127.0.0.1:${apiPort}`, changeOrigin: true },
    },
  },
  build: {
    outDir: '../web-dist',
    emptyOutDir: true,
    sourcemap: false,
  },
})
