import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:5000',
        changeOrigin: true,
        secure: false,
      },
    },
  },
  build: {
    // Recharts is 566 kB minified but ~161 kB gzip; raise Vite's raw-size
    // warning threshold to avoid flagging this compressed production chunk.
    chunkSizeWarningLimit: 600,
    rollupOptions: {
      output: {
        manualChunks: { charts: ['recharts'] },
      },
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: './src/test-setup.ts',
    globals: true,
  },
});
