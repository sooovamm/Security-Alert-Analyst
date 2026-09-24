import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AnalysisPanel } from "./AnalysisPanel.jsx";
import { makeAnalysis } from "../test/fixtures.js";

/**
 * The panel is the only thing an analyst reads before acting on an alert, so
 * the tests here are mostly about honesty: an assessment with no evidence
 * behind it must say so, a failed retrieval must not look like a quiet one,
 * and nothing may be inferred locally from the backend's numbers.
 */

function renderPanel(overrides = {}) {
  const analysis = makeAnalysis(overrides);
  render(<AnalysisPanel analysis={analysis} />);
  return analysis;
}

describe("AnalysisPanel verdict", () => {
  it("renders the verdict, scores, reasoning and recommended action", () => {
    const analysis = renderPanel();

    expect(screen.getByText("Malicious")).toBeInTheDocument();
    expect(screen.getByText("88")).toBeInTheDocument();
    expect(screen.getByText(analysis.assessment.reasoning)).toBeInTheDocument();
    expect(screen.getByText(analysis.assessment.recommended_action)).toBeInTheDocument();
  });

  it.each(["Benign", "Suspicious", "Malicious"])("renders the %s verdict", (classification) => {
    renderPanel({ assessment: { classification } });
    expect(screen.getByText(classification)).toBeInTheDocument();
  });

  it("lists the evidence the backend returned", () => {
    renderPanel();
    expect(screen.getByText("IEX DownloadString in command_line")).toBeInTheDocument();
    expect(screen.getByText("external IP 185.220.101.44")).toBeInTheDocument();
  });

  it("shows the human-review gate and its reasons", () => {
    renderPanel({
      assessment: {
        human_review_required: true,
        human_review_reasons: ["recommends an irreversible action"],
      },
    });
    expect(screen.getByText(/human review required/i)).toBeInTheDocument();
    expect(screen.getByText(/recommends an irreversible action/)).toBeInTheDocument();
  });

  it("omits the review gate when the backend did not set it", () => {
    renderPanel({ assessment: { human_review_required: false, human_review_reasons: [] } });
    expect(screen.queryByText(/human review required/i)).not.toBeInTheDocument();
  });

  it("surfaces backend validation warnings rather than hiding them", () => {
    renderPanel({ assessment: { validation_warnings: ["risk score inconsistent with verdict"] } });
    expect(screen.getByText("Validation warnings")).toBeInTheDocument();
    expect(screen.getByText("risk score inconsistent with verdict")).toBeInTheDocument();
  });

  it("flags the model's own unsupported claims", () => {
    renderPanel({ assessment: { unsupported_claims: ["attributed to a named threat actor"] } });
    expect(screen.getByText("Unsupported claims")).toBeInTheDocument();
    expect(screen.getByText("attributed to a named threat actor")).toBeInTheDocument();
  });

  it("marks a stored assessment so a cached verdict is not read as fresh", () => {
    renderPanel({ meta: { cached: true } });
    expect(screen.getByText("Stored assessment")).toBeInTheDocument();
  });
});

describe("AnalysisPanel retrieval states", () => {
  it("lists retrieved knowledge and marks what was cited", () => {
    renderPanel();
    expect(screen.getByText("PowerShell Attacks")).toBeInTheDocument();
    expect(screen.getByText("Cited")).toBeInTheDocument();
    expect(screen.getByText("0.312")).toBeInTheDocument();
  });

  it("does not mark an uncited document as cited", () => {
    renderPanel({ retrieval: { cited_chunk_ids: [] } });
    expect(screen.getByText("PowerShell Attacks")).toBeInTheDocument();
    expect(screen.queryByText("Cited")).not.toBeInTheDocument();
  });

  it("says plainly when nothing met the relevance threshold", () => {
    renderPanel({
      retrieval: {
        status: "insufficient",
        sufficient: false,
        documents: [],
        cited_chunk_ids: [],
        note: "No retrieved knowledge met the relevance threshold.",
      },
    });
    expect(screen.getByText(/no knowledge base entry met the relevance threshold/i))
      .toBeInTheDocument();
  });

  it("distinguishes a failed retrieval from an empty one", () => {
    // These mean different things: "we looked and found nothing" versus "we
    // could not look". Collapsing them would let a broken retriever pass for
    // a quiet one.
    renderPanel({
      retrieval: {
        status: "failed",
        sufficient: false,
        documents: [],
        cited_chunk_ids: [],
        note: "The embedder was unavailable.",
      },
    });
    expect(screen.getByText(/knowledge retrieval unavailable/i)).toBeInTheDocument();
    expect(screen.getByText(/treat it as low-confidence/i)).toBeInTheDocument();
    expect(screen.queryByText(/met the relevance threshold/i)).not.toBeInTheDocument();
  });
});

describe("AnalysisPanel provenance", () => {
  it("shows which model produced the assessment", () => {
    renderPanel();
    expect(screen.getByText("gpt-4o-mini")).toBeInTheDocument();
    expect(screen.getByText("openai")).toBeInTheDocument();
    expect(screen.getByText("analysis-v1")).toBeInTheDocument();
    expect(screen.getByText("2.4s")).toBeInTheDocument();
  });

  it("shows backend notes such as a retry correction", () => {
    renderPanel({ meta: { notes: ["The first model response was rejected and retried."] } });
    expect(screen.getByText("The first model response was rejected and retried."))
      .toBeInTheDocument();
  });

  it("renders model text as text, never as markup", () => {
    // Model output is untrusted: it must not be able to inject markup.
    renderPanel({ assessment: { reasoning: "<script>alert(1)</script> suspicious" } });
    expect(screen.getByText("<script>alert(1)</script> suspicious")).toBeInTheDocument();
    expect(document.querySelector("script")).toBeNull();
  });
});
