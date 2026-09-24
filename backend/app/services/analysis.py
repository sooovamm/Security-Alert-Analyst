"""AI alert analysis engine.

Pipeline: alert + retrieved knowledge -> prompt -> LLM provider (with retry,
timeout and error mapping) -> safe parse + strict validation -> server-side
guardrails -> `AnalysisResult`.

Server-side guardrails run *after* validation, because a response can be
schema-valid and still untrustworthy:

- citations are checked against the chunks actually retrieved; invented IDs
  are dropped and metadata comes from the retrieval, not the model;
- confidence is capped when retrieval found no relevant knowledge;
- classification/risk-score inconsistencies are flagged;
- recommended actions that read as automated destructive/containment steps
  get a mandatory human-verification notice prepended and are flagged;
- alert text carrying instruction- or delimiter-shaped content forces human
  review, since an obeyed injection is indistinguishable from a clean verdict;
- `human_review_required` is computed here, never taken from the model.

The engine never executes anything the model says. Its output is advisory.
"""
from __future__ import annotations

import logging
import re
import time
from collections.abc import Callable
from typing import Protocol

from app.core.config import Settings, get_settings
from app.core.redaction import redact
from app.llm.base import LLMProvider, LLMRequest, LLMResponse
from app.llm.errors import (
    LLMConfigurationError,
    LLMError,
    LLMResponseError,
    LLMTimeoutError,
)
from app.rag.schemas import RagContext, RetrievalStatus
from app.schemas.alert import Alert
from app.schemas.analysis import (
    AnalysisResult,
    Classification,
    KnowledgeReference,
    LLMAnalysisOutput,
)
from app.services.prompts import (
    PROMPT_VERSION,
    SYSTEM_PROMPT,
    build_rag_query,
    build_user_prompt,
    contains_injection_markers,
)
from app.services.response_parser import MalformedResponseError, parse_analysis_response

logger = logging.getLogger(__name__)

INSUFFICIENT_KNOWLEDGE_CONFIDENCE_CAP = 60
LOW_CONFIDENCE_THRESHOLD = 50
HIGH_RISK_THRESHOLD = 70
MAX_BACKOFF_SECONDS = 10.0

HUMAN_GATE_NOTICE = (
    "[Advisory only - any containment or destructive step (isolation, blocking, "
    "deletion, account action) requires human analyst verification and approval "
    "before it is taken.] "
)

# Containment / destructive verbs, automation phrasing, and human-gate phrasing.
_DESTRUCTIVE_RE = re.compile(
    r"\b(isolat\w*|quarantin\w*|block\w*|disabl\w*|delet\w*|kill\w*|terminat\w*|wip(?:e|ing)\w*"
    r"|reimag\w*|shut\s*down|lock\w*\s+(?:out|the\s+account|account)|reset\w*\s+(?:the\s+)?"
    r"(?:password|credential)s?|revok\w*)\b",
    re.IGNORECASE,
)
_AUTOMATED_RE = re.compile(
    r"\b(automatic\w*|auto-\w+|immediately|without\s+(?:human\s+)?(?:review|approval|"
    r"verification|confirmation))\b",
    re.IGNORECASE,
)
_HUMAN_GATE_RE = re.compile(
    r"\b(human|analyst|approv\w*|verif\w*|confirm\w*|authori[sz]\w*|escalat\w*)\b",
    re.IGNORECASE,
)


# --- errors -------------------------------------------------------------------

class AnalysisError(Exception):
    """Base engine error. `str(exc)` is safe to log and to show to API clients."""


class AnalysisUnavailableError(AnalysisError):
    """LLM not configured or credentials rejected."""


class AnalysisTimeoutError(AnalysisError):
    """Every attempt timed out."""


class AnalysisProviderError(AnalysisError):
    """Provider/API failure (non-retryable, or retries exhausted)."""


class AnalysisResponseError(AnalysisError):
    """The model never produced a valid, schema-conformant response."""


# --- engine -------------------------------------------------------------------

class KnowledgeSource(Protocol):
    def build_context(self, query: str) -> RagContext: ...


class AlertAnalysisEngine:
    def __init__(
        self,
        provider: LLMProvider,
        settings: Settings,
        knowledge: KnowledgeSource | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.provider = provider
        self.settings = settings
        self.knowledge = knowledge
        self._sleep = sleep

    def analyze(self, alert: Alert, context: RagContext | None = None) -> AnalysisResult:
        if context is None:
            if self.knowledge is None:
                raise ValueError("either a RagContext or a knowledge source is required")
            context = self.knowledge.build_context(build_rag_query(alert))

        logger.info(
            "Analysis start alert_id=%s provider=%s model=%s knowledge_chunks=%d sufficient=%s",
            alert.alert_id, self.provider.name, self.provider.model,
            len(context.citations), context.sufficient,
        )
        started = time.monotonic()
        output, response, attempts = self._generate_validated(alert, context)
        latency_ms = int((time.monotonic() - started) * 1000)

        result = self._apply_guardrails(alert, context, output, response, attempts, latency_ms)
        logger.info(
            "Analysis done alert_id=%s classification=%s risk=%d confidence=%d attempts=%d "
            "latency_ms=%d warnings=%d tokens=%s",
            alert.alert_id, result.classification.value, result.risk_score,
            result.confidence_score, attempts, latency_ms, len(result.validation_warnings),
            response.usage.get("total_tokens", "n/a"),
        )
        return result

    # --- LLM call with retries ----------------------------------------------
    def _generate_validated(
        self, alert: Alert, context: RagContext
    ) -> tuple[LLMAnalysisOutput, LLMResponse, int]:
        max_attempts = 1 + self.settings.llm_max_retries
        correction: str | None = None
        last_kind: type[AnalysisError] = AnalysisProviderError
        last_message = "no attempts made"

        for attempt in range(1, max_attempts + 1):
            request = LLMRequest(
                system_prompt=SYSTEM_PROMPT,
                user_prompt=build_user_prompt(alert, context, correction=correction),
                temperature=self.settings.llm_temperature,
                max_output_tokens=self.settings.llm_max_output_tokens,
                timeout_seconds=self.settings.llm_timeout_seconds,
            )
            try:
                response = self.provider.generate(request)
                output = parse_analysis_response(response.content)
                return output, response, attempt
            except LLMConfigurationError as exc:
                self._log_failure(alert, attempt, max_attempts, exc)
                raise AnalysisUnavailableError(self._safe(exc)) from None
            except LLMTimeoutError as exc:
                last_kind, last_message = AnalysisTimeoutError, self._safe(exc)
                self._log_failure(alert, attempt, max_attempts, exc)
            except LLMResponseError as exc:
                last_kind, last_message = AnalysisResponseError, self._safe(exc)
                self._log_failure(alert, attempt, max_attempts, exc)
            except MalformedResponseError as exc:
                last_kind, last_message = AnalysisResponseError, exc.summary
                correction = exc.summary
                self._log_failure(alert, attempt, max_attempts, exc)
            except LLMError as exc:
                last_kind, last_message = AnalysisProviderError, self._safe(exc)
                self._log_failure(alert, attempt, max_attempts, exc)
                if not exc.retryable:
                    raise AnalysisProviderError(last_message) from None
            except Exception as exc:  # buggy provider implementation: fail closed
                self._log_failure(alert, attempt, max_attempts, exc)
                raise AnalysisProviderError(
                    f"unexpected provider failure ({type(exc).__name__})"
                ) from None

            if attempt < max_attempts:
                delay = min(
                    self.settings.llm_retry_backoff_seconds * (2 ** (attempt - 1)),
                    MAX_BACKOFF_SECONDS,
                )
                if delay > 0:
                    self._sleep(delay)

        raise last_kind(f"analysis failed after {max_attempts} attempt(s): {last_message}")

    def _safe(self, exc: BaseException) -> str:
        key = self.settings.llm_api_key.get_secret_value() if self.settings.llm_api_key else None
        return redact(str(exc), [key, self.settings.openai_api_key])

    def _log_failure(
        self, alert: Alert, attempt: int, max_attempts: int, exc: BaseException
    ) -> None:
        message = exc.summary if isinstance(exc, MalformedResponseError) else self._safe(exc)
        logger.warning(
            "Analysis attempt %d/%d failed alert_id=%s error=%s detail=%s",
            attempt, max_attempts, alert.alert_id, type(exc).__name__, message,
        )

    # --- post-validation guardrails -----------------------------------------
    def _apply_guardrails(
        self,
        alert: Alert,
        context: RagContext,
        output: LLMAnalysisOutput,
        response: LLMResponse,
        attempts: int,
        latency_ms: int,
    ) -> AnalysisResult:
        warnings: list[str] = []
        sufficient = context.sufficient and bool(context.citations)
        retrieval_failed = context.status is RetrievalStatus.failed
        if retrieval_failed:
            warnings.append(
                "Knowledge retrieval failed: this assessment is based on the alert data "
                "alone, with no supporting internal knowledge."
            )

        # 1. Citations must refer to chunks we actually supplied.
        available = {c.chunk_id: c for c in context.citations} if sufficient else {}
        cited: list[KnowledgeReference] = []
        unknown = 0
        for chunk_id in dict.fromkeys(output.retrieved_knowledge):  # de-dupe, keep order
            chunk = available.get(chunk_id)
            if chunk is None:
                unknown += 1
                continue
            cited.append(KnowledgeReference(
                chunk_id=chunk.chunk_id, title=chunk.title, category=chunk.category,
                source=chunk.source, score=chunk.score,
            ))
        if unknown:
            warnings.append(
                f"Model cited {unknown} knowledge reference(s) that were not retrieved; "
                "they were discarded."
            )

        # 2. Weak grounding caps confidence.
        confidence = output.confidence_score
        if not sufficient and confidence > INSUFFICIENT_KNOWLEDGE_CONFIDENCE_CAP:
            cause = "Knowledge retrieval failed" if retrieval_failed else (
                "No relevant knowledge was retrieved")
            warnings.append(
                f"{cause}; confidence capped from {confidence} "
                f"to {INSUFFICIENT_KNOWLEDGE_CONFIDENCE_CAP}."
            )
            confidence = INSUFFICIENT_KNOWLEDGE_CONFIDENCE_CAP

        # 3. Classification vs. risk consistency.
        risk = output.risk_score
        cls = output.classification
        if cls is Classification.benign and risk >= 40:
            warnings.append(f"Inconsistent output: 'Benign' with risk_score {risk} (>= 40).")
        elif cls is Classification.malicious and risk < 60:
            warnings.append(f"Inconsistent output: 'Malicious' with risk_score {risk} (< 60).")
        elif cls is Classification.suspicious and not 30 <= risk <= 75:
            warnings.append(
                f"Inconsistent output: 'Suspicious' with risk_score {risk} (expected 30-75)."
            )

        # 4. Recommended actions must stay advisory.
        action = output.recommended_action
        if needs_human_gate(action):
            warnings.append(
                "Recommended action contained containment/destructive steps without a "
                "human-verification condition; an advisory notice was added."
            )
            action = HUMAN_GATE_NOTICE + action

        # 5. Human review is decided server-side.
        reasons: list[str] = []
        if cls is not Classification.benign:
            reasons.append(f"classified as {cls.value}")
        if risk >= HIGH_RISK_THRESHOLD:
            reasons.append(f"high risk score ({risk})")
        if confidence < LOW_CONFIDENCE_THRESHOLD:
            reasons.append(f"low confidence ({confidence})")
        if retrieval_failed:
            reasons.append("knowledge retrieval failed")
        elif not sufficient:
            reasons.append("no relevant knowledge retrieved")
        if output.unsupported_claims:
            reasons.append("model reported unsupported claims")
        if warnings:
            reasons.append("output failed one or more consistency/safety checks")
        if contains_injection_markers(alert):
            # Input-side, so it is a review reason rather than an output warning.
            reasons.append("alert text contains possible prompt-injection content")

        return AnalysisResult(
            alert_id=alert.alert_id,
            classification=cls,
            risk_score=risk,
            confidence_score=confidence,
            reasoning=output.reasoning,
            recommended_action=action,
            evidence=list(output.evidence),
            unsupported_claims=list(output.unsupported_claims),
            retrieved_knowledge=cited,
            knowledge_sufficient=sufficient,
            human_review_required=bool(reasons),
            human_review_reasons=reasons,
            validation_warnings=warnings,
            provider=response.provider,
            model=response.model,
            prompt_version=PROMPT_VERSION,
            attempts=attempts,
            latency_ms=latency_ms,
        )


def needs_human_gate(action: str) -> bool:
    """True if `action` proposes containment/destructive steps either as an
    automated/immediate step or without any human-verification condition."""
    if not _DESTRUCTIVE_RE.search(action):
        return False
    return bool(_AUTOMATED_RE.search(action)) or not _HUMAN_GATE_RE.search(action)


def get_analysis_engine(settings: Settings | None = None) -> AlertAnalysisEngine:
    """Build the engine from configuration. Raises `AnalysisUnavailableError`
    if the LLM is not configured, so callers can return a clean 503."""
    from app.llm.factory import get_llm_provider

    settings = settings or get_settings()
    try:
        provider = get_llm_provider(settings)
    except LLMConfigurationError as exc:
        raise AnalysisUnavailableError(str(exc)) from None

    from app.rag.service import get_rag_service  # lazy: pulls in FAISS

    return AlertAnalysisEngine(provider, settings, knowledge=get_rag_service())
