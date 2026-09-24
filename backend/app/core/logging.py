"""Centralised logging configuration.

One place configures the root logger from `LOG_LEVEL` and `LOG_FORMAT`:

- `text` (default) — human-readable lines for local development.
- `json`  — one JSON object per line for log aggregators.

Every record carries the current `request_id` (set by the API middleware), so
logs from one request can be correlated. Every handler gets a
`SecretRedactingFilter` so a credential that slips into a message is scrubbed.
"""
import json
import logging
from contextvars import ContextVar

from app.core.config import get_settings
from app.core.redaction import SecretRedactingFilter

# Set per request by app.api.middleware; "-" outside a request (startup, CLI).
request_id_var: ContextVar[str] = ContextVar("request_id", default="-")

TEXT_FORMAT = "%(asctime)s %(levelname)-8s %(name)s [%(request_id)s]: %(message)s"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S%z"

# LogRecord attributes that are never part of the structured "extra" payload.
_STANDARD_ATTRS = frozenset(vars(logging.LogRecord("", 0, "", 0, "", (), None)))


def _ensure_request_id(record: logging.LogRecord) -> None:
    if not hasattr(record, "request_id"):
        record.request_id = request_id_var.get()


class TextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        _ensure_request_id(record)
        return super().format(record)


class JsonFormatter(logging.Formatter):
    """Line-delimited JSON. Extra keyword fields passed via `extra={...}` are
    merged into the object, which is what makes the logs queryable."""

    def format(self, record: logging.LogRecord) -> str:
        _ensure_request_id(record)
        payload = {
            "timestamp": self.formatTime(record, DATE_FORMAT),
            "level": record.levelname,
            "logger": record.name,
            "request_id": getattr(record, "request_id", None),
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _STANDARD_ATTRS and key not in payload:
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging() -> None:
    settings = get_settings()
    level = getattr(logging, settings.log_level.upper(), logging.INFO)

    root = logging.getLogger()
    root.setLevel(level)

    handler = next((h for h in root.handlers if getattr(h, "_analyst_handler", False)), None)
    if handler is None:
        handler = logging.StreamHandler()
        handler._analyst_handler = True  # type: ignore[attr-defined]
        root.addHandler(handler)
    handler.setLevel(level)
    handler.setFormatter(
        JsonFormatter() if settings.log_format.lower() == "json"
        else TextFormatter(TEXT_FORMAT, DATE_FORMAT)
    )

    secrets = [settings.openai_api_key]
    if settings.llm_api_key is not None:
        secrets.append(settings.llm_api_key.get_secret_value())
    for h in root.handlers:
        if not any(isinstance(f, SecretRedactingFilter) for f in h.filters):
            h.addFilter(SecretRedactingFilter(secrets))

    logging.getLogger("uvicorn.access").setLevel(level)
    # FAISS probes for AVX512 then AVX2 on import and logs a multi-line
    # ModuleNotFoundError for each miss at INFO. It is a successful fallback,
    # not a problem, and it reads like a crash in container logs.
    logging.getLogger("faiss.loader").setLevel(logging.WARNING)
