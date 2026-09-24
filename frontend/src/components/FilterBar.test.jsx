import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { FilterBar } from "./FilterBar.jsx";

const NO_FILTERS = { q: "", severity: "", classification: "", category: "" };

function renderBar(overrides = {}) {
  const props = {
    filters: NO_FILTERS,
    onChange: vi.fn(),
    onReset: vi.fn(),
    resultCount: 45,
    totalCount: 45,
    busy: false,
    ...overrides,
  };
  render(<FilterBar {...props} />);
  return props;
}

describe("FilterBar controls", () => {
  it("labels every control", () => {
    renderBar();
    expect(screen.getByLabelText("Search")).toBeInTheDocument();
    expect(screen.getByLabelText("Severity")).toBeInTheDocument();
    expect(screen.getByLabelText("AI classification")).toBeInTheDocument();
    expect(screen.getByLabelText("Category")).toBeInTheDocument();
  });

  it("offers every severity and classification the backend accepts", () => {
    renderBar();
    const severities = screen.getByLabelText("Severity");
    expect([...severities.options].map((o) => o.value))
      .toEqual(["", "low", "medium", "high", "critical"]);

    const classifications = screen.getByLabelText("AI classification");
    expect([...classifications.options].map((o) => o.value))
      .toEqual(["", "Benign", "Suspicious", "Malicious"]);
  });

  it("reports each typed character so the hook can debounce", async () => {
    const user = userEvent.setup();
    const { onChange } = renderBar();

    await user.type(screen.getByLabelText("Search"), "ps");

    expect(onChange).toHaveBeenCalledTimes(2);
    expect(onChange).toHaveBeenLastCalledWith({ ...NO_FILTERS, q: "s" });
  });

  it("reports a severity selection without discarding the other filters", async () => {
    const user = userEvent.setup();
    const { onChange } = renderBar({ filters: { ...NO_FILTERS, q: "powershell" } });

    await user.selectOptions(screen.getByLabelText("Severity"), "critical");

    expect(onChange).toHaveBeenCalledWith({
      ...NO_FILTERS,
      q: "powershell",
      severity: "critical",
    });
  });

  it("reports a classification selection", async () => {
    const user = userEvent.setup();
    const { onChange } = renderBar();

    await user.selectOptions(screen.getByLabelText("AI classification"), "Malicious");

    expect(onChange).toHaveBeenCalledWith({ ...NO_FILTERS, classification: "Malicious" });
  });

  it("reports a category selection", async () => {
    const user = userEvent.setup();
    const { onChange } = renderBar();

    await user.selectOptions(screen.getByLabelText("Category"), "Malware Detection");

    expect(onChange).toHaveBeenCalledWith({ ...NO_FILTERS, category: "Malware Detection" });
  });

  it("says that the classification filter hides unanalysed alerts", () => {
    // Without this, a filtered queue looks like the whole queue.
    renderBar();
    expect(screen.getByText(/excludes alerts that have not been analysed/i))
      .toBeInTheDocument();
  });
});

describe("FilterBar result summary", () => {
  it("shows a plain count when nothing is filtered", () => {
    renderBar({ resultCount: 45, totalCount: 45 });
    expect(screen.getByText(/45/)).toBeInTheDocument();
    expect(screen.queryByText(/matching filters/)).not.toBeInTheDocument();
  });

  it("shows the matched count against the total when filtered", () => {
    renderBar({ filters: { ...NO_FILTERS, severity: "high" }, resultCount: 7, totalCount: 45 });
    const summary = screen.getByText(/of 45 alerts/);
    expect(summary).toHaveTextContent("7");
    expect(summary).toHaveTextContent("matching filters");
  });

  it("announces loading instead of a stale count", () => {
    // Showing the previous count while a new query is in flight would state a
    // number that is not the answer to the question being asked.
    renderBar({ busy: true, resultCount: 45, totalCount: 45 });
    expect(screen.getByText("Loading alerts…")).toBeInTheDocument();
  });

  it("announces count changes politely", () => {
    renderBar({ resultCount: 7, totalCount: 45 });
    expect(screen.getByText(/of 45 alerts/).closest("[aria-live]"))
      .toHaveAttribute("aria-live", "polite");
  });
});

describe("FilterBar reset", () => {
  it("offers no reset when nothing is filtered", () => {
    renderBar();
    expect(screen.queryByRole("button", { name: "Clear filters" })).not.toBeInTheDocument();
  });

  it.each([
    ["q", "powershell"],
    ["severity", "high"],
    ["classification", "Benign"],
    ["category", "Malware Detection"],
  ])("offers a reset when %s is set", (key, value) => {
    renderBar({ filters: { ...NO_FILTERS, [key]: value } });
    expect(screen.getByRole("button", { name: "Clear filters" })).toBeInTheDocument();
  });

  it("resets when the control is activated", async () => {
    const user = userEvent.setup();
    const { onReset } = renderBar({ filters: { ...NO_FILTERS, severity: "high" } });

    await user.click(screen.getByRole("button", { name: "Clear filters" }));

    expect(onReset).toHaveBeenCalledTimes(1);
  });
});
