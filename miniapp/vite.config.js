import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { resolve } from 'path'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000
  },
  build: {
    outDir: "dist",
    rollupOptions: {
      input: resolve(__dirname, "public/index.html")   // 👈 point Vite here
    }
  }
})
