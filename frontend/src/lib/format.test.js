import { describe, expect, it } from "vitest";
import { confidenceBand, formatTimestamp, riskBand, riskLevel, truncate } from "./format.js";

/**
 * These helpers only present values the backend already decided. The tests
 * that matter are therefore the boundaries — an off-by-one in a band would
 * mislabel a real verdict — and the "no data" cases, where inventing a value
 * would be worse than showing nothing.
 */

describe("formatTimestamp", () => {
  it("renders a compact UTC timestamp", () => {
    expect(formatTimestamp("2025-09-13T22:05:19Z")).toBe("2025-09-13 22:05Z");
  });

  it("is timezone-independent", () => {
    // The same instant, expressed with an offset, must render identically:
    // an analyst comparing two consoles must not see two different times.
    expect(formatTimestamp("2025-09-14T00:05:19+02:00")).toBe("2025-09-13 22:05Z");
  });

  it.each([null, undefined, "", "not-a-date"])("shows a dash for %s", (value) => {
    expect(formatTimestamp(value)).toBe("—");
  });
});

describe("riskBand", () => {
  it.each([
    [0, "Minimal"],
    [19, "Minimal"],
    [20, "Low"],
    [39, "Low"],
    [40, "Moderate"],
    [69, "Moderate"],
    [70, "High"],
    [89, "High"],
    [90, "Critical"],
    [100, "Critical"],
  ])("maps %i to %s", (score, band) => {
    expect(riskBand(score)).toBe(band);
  });

  it("shows a dash rather than a band when there is no score", () => {
    expect(riskBand(null)).toBe("—");
    expect(riskBand(undefined)).toBe("—");
  });

  it("does not treat a zero score as missing", () => {
    // 0 is falsy in JavaScript: a `!score` check here would report an
    // analysed, zero-risk alert as never analysed.
    expect(riskBand(0)).toBe("Minimal");
    expect(riskLevel(0)).toBe("low");
  });
});

describe("riskLevel", () => {
  it.each([
    [null, "none"],
    [10, "low"],
    [39, "low"],
    [40, "moderate"],
    [69, "moderate"],
    [70, "high"],
    [100, "high"],
  ])("maps %s to %s", (score, level) => {
    expect(riskLevel(score)).toBe(level);
  });
});

describe("confidenceBand", () => {
  it.each([
    [null, "—"],
    [0, "Low"],
    [49, "Low"],
    [50, "Moderate"],
    [74, "Moderate"],
    [75, "High"],
    [100, "High"],
  ])("maps %s to %s", (score, band) => {
    expect(confidenceBand(score)).toBe(band);
  });
});

describe("truncate", () => {
  it("leaves short text alone", () => {
    expect(truncate("short", 10)).toBe("short");
  });

  it("truncates with an ellipsis and trims the trailing space", () => {
    expect(truncate("aaaa bbbb cccc", 10)).toBe("aaaa bbbb…");
  });

  it("returns an empty string for missing text", () => {
    expect(truncate(null)).toBe("");
    expect(truncate(undefined)).toBe("");
  });

  it("keeps text of exactly the limit intact", () => {
    expect(truncate("abcde", 5)).toBe("abcde");
  });
});
