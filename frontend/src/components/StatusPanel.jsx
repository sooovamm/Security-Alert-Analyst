/**
 * Shared loading / empty / error presentation.
 *
 * Loading and empty states are announced politely; errors assertively. Error
 * text comes from the backend's message plus its request id, so a failure can
 * be traced in the server logs.
 */
export function StatusPanel({ variant = "info", title, children, action }) {
  const isError = variant === "error";
  return (
    <div
      className={`status-panel status-panel--${variant}`}
      role={isError ? "alert" : "status"}
      aria-live={isError ? "assertive" : "polite"}
    >
      {variant === "loading" && <span className="spinner" aria-hidden="true" />}
      <div>
        <p className="status-panel__title">{title}</p>
        {children && <div className="status-panel__body">{children}</div>}
        {action}
      </div>
    </div>
  );
}

export function ErrorPanel({ error, onRetry, title = "Something went wrong" }) {
  return (
    <StatusPanel
      variant="error"
      title={title}
      action={
        onRetry && (
          <button type="button" className="button button--secondary" onClick={onRetry}>
            Try again
          </button>
        )
      }
    >
      <p>{error?.message ?? "Unexpected error."}</p>
      {error?.requestId && (
        <p className="status-panel__meta">
          Request ID <code>{error.requestId}</code>
        </p>
      )}
    </StatusPanel>
  );
}
