import { useCallback, useEffect, useRef, useState } from "react";
import { analyzeAlert, fetchStoredAnalysis } from "../api/alerts.js";

/**
 * Owns the assessment for one alert: loads a previously stored one, and runs a
 * new analysis on demand.
 *
 * Results only ever come from the backend. When no assessment exists the state
 * is "none" — the UI shows that plainly rather than inventing a verdict.
 */
export function useAlertAnalysis(alertId, { onAnalysed } = {}) {
  const [analysis, setAnalysis] = useState(null);
  const [status, setStatus] = useState("idle"); // idle | loading | analyzing | ready | none | error
  const [error, setError] = useState(null);
  const loadRef = useRef(null);
  const analyseRef = useRef(null);

  // Load the stored assessment whenever the selected alert changes.
  useEffect(() => {
    if (!alertId) {
      setAnalysis(null);
      setStatus("idle");
      setError(null);
      return undefined;
    }

    const controller = new AbortController();
    loadRef.current = controller;
    setStatus("loading");
    setError(null);
    setAnalysis(null);

    fetchStoredAnalysis(alertId, controller.signal)
      .then((data) => {
        setAnalysis(data);
        setStatus("ready");
      })
      .catch((requestError) => {
        if (controller.signal.aborted) return;
        if (requestError.code === "analysis_not_found") {
          setStatus("none"); // never analysed yet — an expected state, not an error
        } else {
          setError(requestError);
          setStatus("error");
        }
      });

    return () => controller.abort();
  }, [alertId]);

  const runAnalysis = useCallback(async () => {
    if (!alertId) return;
    analyseRef.current?.abort();
    const controller = new AbortController();
    analyseRef.current = controller;

    setStatus("analyzing");
    setError(null);
    try {
      const data = await analyzeAlert(alertId, controller.signal);
      setAnalysis(data);
      setStatus("ready");
      onAnalysed?.(data);
    } catch (requestError) {
      if (controller.signal.aborted) return;
      setError(requestError);
      setStatus("error");
    }
  }, [alertId, onAnalysed]);

  useEffect(() => () => analyseRef.current?.abort(), []);

  return { analysis, status, error, runAnalysis };
}
