# Architecture (foundation)

Full architecture diagram, data-flow, and the 2–4 page technical design document
are produced in later sprints once the RAG pipeline and analysis engine exist.
This is the foundation view.

## Components

```
                       ┌──────────────────────┐
   browser  ─── / ───▶ │  frontend (nginx)    │   Vite + React SPA
                       │  serves SPA, proxies │
                       │  /api/ ─────────────▶│─────┐
                       └──────────────────────┘     │
                                                     ▼
                                        ┌──────────────────────────┐
                                        │  backend (FastAPI)        │
                                        │  /health, /health/ready   │
                                        │  (later: /analyze-alert)  │
                                        │                           │
                                        │  core/  config + logging  │
                                        │  rag/   (Sprint 2)        │
                                        │  llm/   (Sprint 3)        │
                                        │  services/ (Sprint 3)     │
                                        └────────────┬──────────────┘
                                                     │ reads (ro)
                                                     ▼
                                        ┌──────────────────────────┐
                                        │  data/                    │
                                        │   alerts/  knowledge/     │
                                        └──────────────────────────┘
```

## Foundation decisions

- **App factory + cached settings.** `create_app()` builds the FastAPI app;
  `get_settings()` is a cached `pydantic-settings` singleton reading env vars,
  so configuration has one source of truth and tests can override it.
- **Boots without secrets.** Nothing at import time requires the OpenAI key.
  Liveness (`/health`) is dependency-free; readiness (`/health/ready`) *reports*
  whether the key and data are present without failing.
- **Same-origin frontend.** nginx serves the SPA and reverse-proxies `/api/` to
  the backend, avoiding browser CORS complexity in production; a matching Vite
  dev proxy gives the same behaviour locally.
- **Data mounted read-only.** The alerts/knowledge corpus is mounted `:ro` into
  the backend container — the service reads it, never mutates it.
