import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In local dev the frontend runs on :5173 and proxies /api to the backend on
// :8000, so the browser makes same-origin calls. In production the nginx image
// does the same reverse-proxy. The React code therefore always calls "/api/...".
export default defineConfig({
  plugins: [react()],
  // Automatic JSX runtime, so components do not import React and test files do
  // not have to either. Set explicitly because the React plugin's own Babel
  // transform is not applied in the Vitest environment.
  esbuild: { jsx: "automatic" },
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
  // Component and unit tests. These never reach a network: `fetch` is stubbed
  // per test, so there is no backend, no database and no LLM involved.
  // Browser-level tests against a real stack live in e2e/ (Playwright).
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.js"],
    include: ["src/**/*.test.{js,jsx}"],
    // e2e/ is Playwright's; running it under vitest would hang on a browser.
    exclude: ["e2e/**", "node_modules/**"],
    restoreMocks: true,
    coverage: {
      provider: "v8",
      include: ["src/**/*.{js,jsx}"],
      exclude: ["src/main.jsx", "src/test/**", "src/**/*.test.{js,jsx}"],
    },
  },
});
