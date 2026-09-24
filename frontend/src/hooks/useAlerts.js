import { useCallback, useEffect, useRef, useState } from "react";
import { fetchAlerts } from "../api/alerts.js";

const SEARCH_DEBOUNCE_MS = 250;

/**
 * Loads the alert list for the current filters. Filtering and search are done
 * by the backend; this hook only owns request lifecycle (debounce, abort,
 * loading/error state) so components stay presentational.
 */
export function useAlerts(filters) {
  const [alerts, setAlerts] = useState([]);
  const [total, setTotal] = useState(0);
  const [status, setStatus] = useState("loading"); // loading | ready | error
  const [error, setError] = useState(null);
  const requestRef = useRef(null);

  const load = useCallback(
    async (nextFilters, { quiet = false } = {}) => {
      requestRef.current?.abort();
      const controller = new AbortController();
      requestRef.current = controller;

      if (!quiet) setStatus("loading");
      try {
        const data = await fetchAlerts(nextFilters, controller.signal);
        setAlerts(data.items);
        setTotal(data.total);
        setStatus("ready");
        setError(null);
      } catch (requestError) {
        if (controller.signal.aborted) return; // superseded by a newer request
        setError(requestError);
        setStatus("error");
      }
    },
    [],
  );

  // Debounce only the free-text search; dropdown changes apply immediately.
  useEffect(() => {
    const delay = filters.q ? SEARCH_DEBOUNCE_MS : 0;
    const timer = setTimeout(() => load(filters), delay);
    return () => clearTimeout(timer);
  }, [filters, load]);

  useEffect(() => () => requestRef.current?.abort(), []);

  // Used after an analysis, to refresh verdict columns without a visible reload.
  const refreshQuietly = useCallback(() => load(filters, { quiet: true }), [filters, load]);

  return { alerts, total, status, error, retry: () => load(filters), refreshQuietly };
}
