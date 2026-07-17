import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  // @vitejs/plugin-react's types target vite 6; vitest 2.x bundles its own
  // vite 5 types, so the plugin instance is cast through the boundary. The
  // runtime behavior is unaffected -- both speak the same plugin protocol.
  plugins: [react() as never],
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: "./tests/setup.ts",
  },
});
