import { useEffect, useState } from "react";

// Foundation skeleton: proves the frontend loads AND can reach the backend.
// The full alert dashboard (table of alerts + AI assessment) is built in the
// frontend sprint. Kept deliberately minimal but functional, not decorative.
export default function App() {
  const [health, setHealth] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetch("/api/health")
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then(setHealth)
      .catch((e) => setError(e.message));
  }, []);

  return (
    <main className="wrap">
      <h1>AI-Powered Security Alert Analyst</h1>
      <p className="subtitle">Project foundation — Sprint 1</p>

      <section className="card">
        <h2>Backend status</h2>
        {health && (
          <p className="ok">
            ● {health.status} — {health.app} ({health.environment})
          </p>
        )}
        {error && <p className="err">● cannot reach backend: {error}</p>}
        {!health && !error && <p className="muted">checking…</p>}
      </section>

      <p className="muted">
        Alert dashboard, AI classification, risk scores and recommended actions
        arrive in later sprints.
      </p>
    </main>
  );
}
