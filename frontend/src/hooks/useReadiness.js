import { useEffect, useState } from "react";
import { fetchReadiness } from "../api/alerts.js";

/**
 * Backend dependency status, so the dashboard can warn up front that analysis
 * is unavailable instead of letting the analyst discover it on a failed click.
 */
export function useReadiness() {
  const [readiness, setReadiness] = useState(null);

  useEffect(() => {
    const controller = new AbortController();
    fetchReadiness(controller.signal)
      .then(setReadiness)
      .catch(() => setReadiness(null)); // list errors already surface a failed backend
    return () => controller.abort();
  }, []);

  return readiness;
}
