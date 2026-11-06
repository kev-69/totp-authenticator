import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    environment: "node",
    // Empty test files are fine while stages are still being written.
    passWithNoTests: true,
  },
});
