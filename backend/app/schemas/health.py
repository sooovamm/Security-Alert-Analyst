"""Schemas for the health endpoints.

Alert and analysis schemas are introduced in the API sprint; this sprint only
needs the health contract so the endpoint returns a validated, typed body.
"""
from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str
    app: str
    environment: str


class ReadinessResponse(BaseModel):
    status: str
    llm_configured: bool
    data_present: bool
