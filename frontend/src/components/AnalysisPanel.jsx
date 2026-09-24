import { ClassificationBadge } from "./Badge.jsx";
import { ConfidenceIndicator, RiskScoreBar } from "./RiskScore.jsx";
import { formatTimestamp } from "../lib/format.js";

/**
 * Renders one assessment exactly as the backend returned it: verdict, scores,
 * reasoning, recommended action, evidence and the retrieved knowledge behind
 * it. Nothing here is inferred or filled in locally.
 */
export function AnalysisPanel({ analysis }) {
  const { assessment, retrieval, meta } = analysis;

  return (
    <div className="analysis">
      <div className="analysis__verdict">
        <div className="analysis__verdict-main">
          <ClassificationBadge classification={assessment.classification} />
          {meta.cached && (
            <span className="tag" title={`Stored ${formatTimestamp(meta.analyzed_at)}`}>
              Stored assessment
            </span>
          )}
        </div>
        <dl className="analysis__scores">
          <div>
            <dt>Risk score</dt>
            <dd><RiskScoreBar score={assessment.risk_score} /></dd>
          </div>
          <div>
            <dt>Confidence</dt>
            <dd><ConfidenceIndicator score={assessment.confidence_score} /></dd>
          </div>
        </dl>
      </div>

      {retrieval.status === "failed" && (
        <p className="retrieval-flag" role="status">
          <strong>Knowledge retrieval unavailable.</strong> The knowledge base could not be
          consulted, so this assessment is based on the alert data alone with no supporting
          evidence. Treat it as low-confidence.
        </p>
      )}

      {assessment.human_review_required && (
        <p className="review-flag">
          <strong>Human review required</strong>
          {assessment.human_review_reasons?.length > 0
            && `: ${assessment.human_review_reasons.join("; ")}.`}
        </p>
      )}

      <section className="analysis__section">
        <h4>Recommended action</h4>
        <p className="analysis__action">{assessment.recommended_action}</p>
      </section>

      <section className="analysis__section">
        <h4>Reasoning</h4>
        <p>{assessment.reasoning}</p>
      </section>

      {assessment.evidence?.length > 0 && (
        <section className="analysis__section">
          <h4>Evidence</h4>
          <ul className="list list--evidence">
            {assessment.evidence.map((item) => <li key={item}>{item}</li>)}
          </ul>
        </section>
      )}

      {assessment.unsupported_claims?.length > 0 && (
        <section className="analysis__section">
          <h4>Unsupported claims</h4>
          <p className="analysis__note">
            The model flagged these as not supported by the available evidence.
          </p>
          <ul className="list list--caution">
            {assessment.unsupported_claims.map((item) => <li key={item}>{item}</li>)}
          </ul>
        </section>
      )}

      {assessment.validation_warnings?.length > 0 && (
        <section className="analysis__section">
          <h4>Validation warnings</h4>
          <p className="analysis__note">Raised by the backend when checking the model output.</p>
          <ul className="list list--caution">
            {assessment.validation_warnings.map((item) => <li key={item}>{item}</li>)}
          </ul>
        </section>
      )}

      <section className="analysis__section">
        <h4>Retrieved knowledge</h4>
        {retrieval.status === "failed" ? (
          <p className="analysis__note analysis__note--warn">
            Retrieval failed, so no knowledge was consulted and there is no supporting
            evidence to show. {retrieval.note}
          </p>
        ) : retrieval.documents.length === 0 ? (
          <p className="analysis__note">
            No knowledge base entry met the relevance threshold, so this assessment rests on
            the alert data alone. {retrieval.note}
          </p>
        ) : (
          <>
            <p className="analysis__note">
              Internal knowledge retrieved for this alert. Cited entries were used by the model.
            </p>
            <ul className="list list--knowledge">
              {retrieval.documents.map((document) => {
                const cited = retrieval.cited_chunk_ids?.includes(document.chunk_id);
                return (
                  <li key={document.chunk_id} className={cited ? "is-cited" : undefined}>
                    <div className="knowledge__head">
                      <span className="knowledge__title">{document.title}</span>
                      {cited && <span className="tag tag--cited">Cited</span>}
                      <span className="knowledge__score" title="Similarity score">
                        {document.score.toFixed(3)}
                      </span>
                    </div>
                    <p className="knowledge__excerpt">{document.excerpt}</p>
                    <p className="knowledge__meta mono">{document.chunk_id} · {document.source}</p>
                  </li>
                );
              })}
            </ul>
          </>
        )}
      </section>

      <footer className="analysis__meta">
        <dl>
          <div><dt>Model</dt><dd className="mono">{meta.model}</dd></div>
          <div><dt>Provider</dt><dd className="mono">{meta.provider}</dd></div>
          <div><dt>Prompt</dt><dd className="mono">{meta.prompt_version}</dd></div>
          <div><dt>Analysed</dt><dd>{formatTimestamp(meta.analyzed_at)}</dd></div>
          <div><dt>Latency</dt><dd>{(meta.latency_ms / 1000).toFixed(1)}s</dd></div>
        </dl>
        {meta.notes?.length > 0 && (
          <ul className="analysis__notes">
            {meta.notes.map((note) => <li key={note}>{note}</li>)}
          </ul>
        )}
      </footer>
    </div>
  );
}
