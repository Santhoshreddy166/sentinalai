"""
main.py - FastAPI application entry point.

Run with:
    uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
"""

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routes import router, threat_router, soc_router, auth_router

# ------------------------------------------------------------------
# Logging Configuration
# ------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# ------------------------------------------------------------------
# Application Factory
# ------------------------------------------------------------------
app = FastAPI(
    title="SOC Analyst AI Backend",
    description=(
        "Backend API, Parsing Engine, and Threat Intelligence Aggregator "
        "for the AI-powered SOC Analyst tool.  "
        "Module 1 analyses URLs for suspicious indicators.  "
        "Module 2 parses uploaded log files into structured entries.  "
        "Module 3 enriches IOCs via external threat intelligence feeds.  "
        "All modules feed into the downstream AI Agent layer for "
        "correlation, anomaly detection, and incident summarisation."
    ),
    version="0.2.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ------------------------------------------------------------------
# Middleware
# ------------------------------------------------------------------
# CORS - permissive in dev; lock down origins in production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: restrict to frontend origin in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------------------
# Routers
# ------------------------------------------------------------------
app.include_router(router)
app.include_router(threat_router)
app.include_router(soc_router)
app.include_router(auth_router)


# ------------------------------------------------------------------
# Health Check
# ------------------------------------------------------------------
@app.get("/health", tags=["System"])
async def health_check():
    """Simple liveness probe."""
    return {"status": "healthy", "version": app.version}
