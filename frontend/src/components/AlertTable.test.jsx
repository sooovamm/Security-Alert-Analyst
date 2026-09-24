import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { AlertTable } from "./AlertTable.jsx";
import { BENIGN_ALERT, SUSPICIOUS_ALERT, makeAlert } from "../test/fixtures.js";

/** Renders the queue and returns the data rows (excluding the header row). */
function renderTable(alerts, props = {}) {
  const onSelect = props.onSelect ?? vi.fn();
  render(<AlertTable alerts={alerts} selectedId={props.selectedId ?? null} onSelect={onSelect} />);
  return { onSelect, rows: within(screen.getByRole("table")).getAllByRole("row").slice(1) };
}

describe("AlertTable rendering", () => {
  it("renders one row per alert with its telemetry", () => {
    const { rows } = renderTable([makeAlert(), SUSPICIOUS_ALERT, BENIGN_ALERT]);
    expect(rows).toHaveLength(3);

    const first = within(rows[0]);
    expect(first.getByRole("button", { name: /ALRT-1003/ })).toBeInTheDocument();
    expect(first.getByText("SRV-APP-02")).toBeInTheDocument();
    expect(first.getByText("SYSTEM")).toBeInTheDocument();
    expect(first.getByText("PowerShell Execution")).toBeInTheDocument();
    expect(first.getByText("2025-09-13 22:05Z")).toBeInTheDocument();
  });

  it("renders an empty tbody rather than failing when there are no alerts", () => {
    const { rows } = renderTable([]);
    expect(rows).toHaveLength(0);
  });

  it("shows the stored verdict when one exists", () => {
    const { rows } = renderTable([
      makeAlert({ latest_classification: "Malicious", latest_risk_score: 88 }),
    ]);
    const row = within(rows[0]);
    expect(row.getByText("Malicious")).toBeInTheDocument();
    expect(row.getByText("88")).toBeInTheDocument();
  });

  it("marks an unanalysed alert as such instead of implying a verdict", () => {
    // The dashboard must never let "we have not looked at this" read as
    // "we looked and it was fine".
    const { rows } = renderTable([makeAlert()]);
    expect(within(rows[0]).getByText(/not analysed/i)).toBeInTheDocument();
    expect(within(rows[0]).queryByText(/benign/i)).not.toBeInTheDocument();
  });

  it("renders a zero risk score rather than treating it as absent", () => {
    const { rows } = renderTable([
      makeAlert({ latest_classification: "Benign", latest_risk_score: 0 }),
    ]);
    expect(within(rows[0]).getByText("0")).toBeInTheDocument();
  });

  it("truncates a long description so one alert cannot flood the queue", () => {
    const description = "A".repeat(400);
    const { rows } = renderTable([makeAlert({ description })]);
    const summary = within(rows[0]).getByText(/^A+…$/);
    expect(summary.textContent.length).toBeLessThan(description.length);
  });

  it("escapes rather than interprets alert text", () => {
    // Alert telemetry is attacker-controlled; it must render as text.
    const { rows } = renderTable([
      makeAlert({ description: "<img src=x onerror=alert(1)>" }),
    ]);
    expect(within(rows[0]).getByText("<img src=x onerror=alert(1)>")).toBeInTheDocument();
    expect(rows[0].querySelector("img")).toBeNull();
  });
});

describe("AlertTable selection", () => {
  it("selects an alert when its ID button is activated", async () => {
    const user = userEvent.setup();
    const { onSelect, rows } = renderTable([makeAlert(), SUSPICIOUS_ALERT]);

    await user.click(within(rows[1]).getByRole("button", { name: /ALRT-1010/ }));

    expect(onSelect).toHaveBeenCalledWith("ALRT-1010");
  });

  it("selects an alert when the row itself is clicked", async () => {
    const user = userEvent.setup();
    const { onSelect, rows } = renderTable([makeAlert()]);

    await user.click(rows[0]);

    expect(onSelect).toHaveBeenCalledWith("ALRT-1003");
  });

  it("reports the selection once when the button inside a row is clicked", async () => {
    // The row and the button both handle clicks; without stopPropagation the
    // same selection would fire twice.
    const user = userEvent.setup();
    const { onSelect, rows } = renderTable([makeAlert()]);

    await user.click(within(rows[0]).getByRole("button", { name: /ALRT-1003/ }));

    expect(onSelect).toHaveBeenCalledTimes(1);
  });

  it("gives the row control a readable accessible name", () => {
    // Regression: the name was assembled from a visually-hidden "View alert "
    // prefix plus the id. Each text node is trimmed before being joined, so a
    // screen reader announced "View alertALRT-1003".
    renderTable([makeAlert()]);
    expect(screen.getByRole("button", { name: "View alert ALRT-1003" })).toBeInTheDocument();
  });

  it("marks the selected row for assistive technology", () => {
    const { rows } = renderTable([makeAlert(), SUSPICIOUS_ALERT], { selectedId: "ALRT-1010" });
    expect(rows[0]).not.toHaveAttribute("aria-current");
    expect(rows[1]).toHaveAttribute("aria-current", "true");
  });

  it("is reachable by keyboard", async () => {
    const user = userEvent.setup();
    const { onSelect } = renderTable([makeAlert()]);

    await user.tab();
    await user.keyboard("{Enter}");

    expect(onSelect).toHaveBeenCalledWith("ALRT-1003");
  });
});
