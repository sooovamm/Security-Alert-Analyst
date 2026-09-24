import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach, beforeEach, vi } from "vitest";

// Every test gets a clean DOM and a fresh fetch stub. Nothing here reaches a
// network: a test that forgets to stub a call gets a loud failure rather than
// a silent attempt to contact a backend that is not running.
beforeEach(() => {
  vi.stubGlobal(
    "fetch",
    vi.fn(() => {
      throw new Error("Unstubbed fetch call — stub it with mockApi() in the test.");
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});
