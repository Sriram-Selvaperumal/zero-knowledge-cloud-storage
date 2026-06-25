import react from "@vitejs/plugin-react";
import type { Plugin } from "vite";
import { defineConfig } from "vitest/config";


const spaRoutes = new Set(["/files", "/files/"]);

interface SpaFallbackRequest {
  headers?: {
    accept?: string | string[];
  };
  method?: string;
  url?: string;
}

const environment = (
  globalThis as typeof globalThis & {
    process?: { env?: Record<string, string | undefined> };
  }
).process?.env ?? {};
const backendTarget = environment.DEV_API_PROXY_TARGET ?? (
  "http://127.0.0.1:8000"
);


function spaFallbackPlugin(): Plugin {
  return {
    name: "prototype-spa-fallback",
    configureServer(server) {
      server.middlewares.use((request, _response, next) => {
        const spaRequest = request as SpaFallbackRequest;
        const path = spaRequest.url?.split("?")[0];
        const accept = spaRequest.headers?.accept;
        const acceptsHtml = Array.isArray(accept)
          ? accept.some((value) => value.includes("text/html"))
          : accept?.includes("text/html");

        if (
          spaRequest.method === "GET"
          && path
          && spaRoutes.has(path)
          && acceptsHtml
        ) {
          spaRequest.url = "/";
        }

        next();
      });
    }
  };
}


export default defineConfig({
  plugins: [spaFallbackPlugin(), react()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    proxy: {
      // Forward backend routes to FastAPI so browser requests stay same-origin.
      "/auth": backendTarget,
      "/files": backendTarget,
      "/shares": backendTarget
    }
  },
  build: {
    chunkSizeWarningLimit: 800
  },
  test: {
    environment: "node"
  }
});
