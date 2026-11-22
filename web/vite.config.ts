import { defineConfig } from 'vite';

export default defineConfig({
  base: '/',
  server: {
    port: 5173,
    proxy: {
      '/v1': 'http://127.0.0.1:9090',
      '/metrics': 'http://127.0.0.1:9090',
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    target: 'es2022',
    sourcemap: false,
  },
});
