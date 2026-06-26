import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";


const environment = (
  globalThis as typeof globalThis & {
    process?: { env?: Record<string, string | undefined> };
  }
).process?.env ?? {};
const backendTarget = environment.DEV_API_PROXY_TARGET ?? (
  "http://127.0.0.1:8000"
);


export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    proxy: {
      "/api": backendTarget
    }
  },
  build: {
    chunkSizeWarningLimit: 800
  },
  test: {
    environment: "node"
  }
});
