import { CATEGORIES, CLASSIFICATIONS, SEVERITIES } from "../lib/format.js";

/**
 * Search and filter controls. Every control is labelled and keyboard
 * reachable; the filters are applied by the backend, not in the browser.
 */
export function FilterBar({ filters, onChange, onReset, resultCount, totalCount, busy }) {
  const update = (key) => (event) => onChange({ ...filters, [key]: event.target.value });
  const hasFilters = Boolean(filters.q || filters.severity || filters.classification
    || filters.category);

  return (
    <section className="filters" aria-label="Search and filter alerts">
      <div className="filters__row">
        <div className="field field--grow">
          <label htmlFor="alert-search">Search</label>
          <input
            id="alert-search"
            type="search"
            value={filters.q}
            onChange={update("q")}
            placeholder="Alert ID, host, user, process, command line…"
            aria-describedby="alert-search-hint"
            autoComplete="off"
            spellCheck="false"
          />
          <p id="alert-search-hint" className="field__hint">
            Matches alert ID, hostname, username, process, command line and description.
          </p>
        </div>

        <div className="field">
          <label htmlFor="filter-severity">Severity</label>
          <select id="filter-severity" value={filters.severity} onChange={update("severity")}>
            <option value="">All severities</option>
            {SEVERITIES.map((severity) => (
              <option key={severity} value={severity}>{severity}</option>
            ))}
          </select>
        </div>

        <div className="field">
          <label htmlFor="filter-classification">AI classification</label>
          <select
            id="filter-classification"
            value={filters.classification}
            onChange={update("classification")}
            aria-describedby="filter-classification-hint"
          >
            <option value="">All classifications</option>
            {CLASSIFICATIONS.map((classification) => (
              <option key={classification} value={classification}>{classification}</option>
            ))}
          </select>
          <p id="filter-classification-hint" className="field__hint">
            Excludes alerts that have not been analysed.
          </p>
        </div>

        <div className="field">
          <label htmlFor="filter-category">Category</label>
          <select id="filter-category" value={filters.category} onChange={update("category")}>
            <option value="">All categories</option>
            {CATEGORIES.map((category) => (
              <option key={category} value={category}>{category}</option>
            ))}
          </select>
        </div>
      </div>

      <div className="filters__summary">
        <p aria-live="polite">
          {busy ? "Loading alerts…" : (
            <>
              <strong>{resultCount}</strong>
              {resultCount === totalCount ? " alerts" : ` of ${totalCount} alerts`}
              {hasFilters ? " matching filters" : ""}
            </>
          )}
        </p>
        {hasFilters && (
          <button type="button" className="button button--link" onClick={onReset}>
            Clear filters
          </button>
        )}
      </div>
    </section>
  );
}
