import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In local dev the frontend runs on :5173 and proxies /api to the backend on
// :8000, so the browser makes same-origin calls. In production the nginx image
// does the same reverse-proxy. The React code therefore always calls "/api/...".
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: process.env.VITE_BACKEND_URL || "http://localhost:8000",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
    },
  },
});
