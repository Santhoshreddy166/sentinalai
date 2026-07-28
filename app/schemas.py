"""
schemas.py - Pydantic models for request / response validation.

Using strict Pydantic models guarantees that every response the API
returns is type-safe and self-documenting via the OpenAPI schema.

NOTE: This uses Pydantic v1 syntax for Python 3.6 compatibility.
"""

from typing import Dict, List, Optional

from pydantic import BaseModel, Field


# ------------------------------------------------------------------
# Module 1 - URL Analysis Schemas
# ------------------------------------------------------------------

class URLAnalysisRequest(BaseModel):
    """Incoming payload for the /api/analyze-url endpoint."""
    url: str = Field(
        ...,
        description="The URL to analyse for suspicious indicators.",
        example="https://free-prize.xyz/login/verify",
    )


class URLRiskIndicators(BaseModel):
    """Individual risk signals extracted from the URL string."""
    has_suspicious_tld: bool = Field(
        ..., description="True if the TLD appears on the known-abuse list."
    )
    suspicious_keywords_found: List[str] = Field(
        default=[],
        description="Phishing / social-engineering keywords detected in the URL path or query.",
    )
    has_ip_address_host: bool = Field(
        ..., description="True if the hostname is a raw IP address instead of a domain name."
    )
    excessive_subdomains: bool = Field(
        ..., description="True if the hostname has more than 3 subdomain levels (common in phishing)."
    )
    url_length_suspicious: bool = Field(
        ..., description="True if total URL length exceeds 200 characters.",
    )


class URLAnalysisResponse(BaseModel):
    """
    Full response returned by the URL analysis endpoint.

    +----------------------------------------------------------+
    |  AI AGENT INTEGRATION POINT                              |
    |  The `risk_score` and `indicators` fields will be        |
    |  consumed by the downstream AI Agent layer to generate   |
    |  a natural-language threat summary and recommend          |
    |  analyst actions (block, investigate, escalate).          |
    +----------------------------------------------------------+
    """
    url: str
    domain: str
    tld: str
    risk_score: float = Field(
        ..., ge=0.0, le=1.0,
        description="Composite heuristic risk score (0 = benign, 1 = highly suspicious).",
    )
    indicators: URLRiskIndicators
    metadata_placeholder: Optional[Dict] = Field(
        default=None,
        description=(
            "Reserved for real-time metadata fetched from WHOIS / VirusTotal / "
            "Google Safe Browsing in a future iteration."
        ),
    )


# ------------------------------------------------------------------
# Module 2 - Log Parsing Schemas
# ------------------------------------------------------------------

class ParsedLogEntry(BaseModel):
    """A single structured record extracted from a raw log line."""
    line_number: int = Field(..., description="1-based line index in the original file.")
    raw_line: str = Field(..., description="The original log line, trimmed.")
    timestamp: Optional[str] = Field(None, description="Extracted timestamp string.")
    source_ip: Optional[str] = Field(None, description="Source IPv4 address.")
    destination_ip: Optional[str] = Field(None, description="Destination IPv4 address (if present).")
    status_code: Optional[str] = Field(None, description="HTTP status code (e.g. '200', '403').")
    event_id: Optional[str] = Field(None, description="Windows Event ID (e.g. '4625').")


class LogUploadResponse(BaseModel):
    """
    Full response returned by the log-upload endpoint.

    +----------------------------------------------------------+
    |  AI AGENT INTEGRATION POINT                              |
    |  The `parsed_entries` list is the primary input for the  |
    |  AI Agent layer. The agent will:                         |
    |    1. Correlate IPs across entries to detect lateral      |
    |       movement or brute-force patterns.                  |
    |    2. Flag anomalous status-code distributions.           |
    |    3. Map Event IDs to MITRE ATT&CK techniques.          |
    |    4. Generate a human-readable incident summary.         |
    +----------------------------------------------------------+
    """
    filename: str
    total_lines: int = Field(..., description="Total lines in the uploaded file.")
    parsed_count: int = Field(..., description="Lines that yielded at least one structured field.")
    skipped_count: int = Field(..., description="Blank or unparsable lines.")
    parsed_entries: List[ParsedLogEntry]


# ------------------------------------------------------------------
# Module 3 - Threat Intelligence Schemas
# ------------------------------------------------------------------

class URLReputationRequest(BaseModel):
    """Incoming payload for the /api/threat-intel/url endpoint."""
    url: str = Field(
        ...,
        description="The URL to check against threat intelligence feeds.",
        example="https://suspicious-site.xyz/login",
    )


class IPReputationRequest(BaseModel):
    """Incoming payload for the /api/threat-intel/ip endpoint."""
    ip: str = Field(
        ...,
        description="The IPv4 address to check against threat intelligence feeds.",
        example="203.0.113.50",
    )


class ThreatIntelResponse(BaseModel):
    """
    Unified response wrapper for all threat intelligence lookups.

    +----------------------------------------------------------+
    |  AI AGENT INTEGRATION POINT                              |
    |  The `result` dict contains provider-specific fields     |
    |  that the AI Agent layer will merge with Module 1/2      |
    |  outputs to produce a unified threat assessment.         |
    |                                                          |
    |  Key fields the Agent consumes:                          |
    |    - aggregate_verdict: 'malicious' or 'clean'           |
    |    - aggregate_malicious_count (URL) or                  |
    |      aggregate_abuse_score (IP)                          |
    |    - sources[].threat_tags / threat_categories            |
    |    - is_known_botnet (IP only)                           |
    |    - data_source: 'live' or 'mock'                       |
    +----------------------------------------------------------+
    """
    query: str = Field(..., description="The URL or IP that was queried.")
    query_type: str = Field(..., description="'url' or 'ip'.")
    data_source: str = Field(
        ..., description="'live' if real API data was used, 'mock' if fallback data."
    )
    aggregate_verdict: str = Field(
        ..., description="Overall verdict: 'malicious' or 'clean'."
    )
    result: Dict = Field(
        ..., description="Full structured intelligence report with all source data."
    )


# ------------------------------------------------------------------
# Module 4 - Agentic AI SOC Analyst Schemas
# ------------------------------------------------------------------

class SOCAnalysisRequest(BaseModel):
    """
    Incoming payload for the /api/soc-analyze endpoint.

    Combines data from Modules 1-3 into a single request that
    the AI Agent layer consumes to produce the incident report.
    """
    input_data: Dict = Field(
        ...,
        description=(
            "Combined output from Module 1 (URL analysis) and/or Module 2 "
            "(parsed log entries). May include: url, domain, risk_score, "
            "indicators, parsed_entries, filename, total_lines."
        ),
    )
    intel_data: Optional[Dict] = Field(
        default=None,
        description=(
            "Threat intelligence enrichment from Module 3. Includes: "
            "aggregate_verdict, data_source, sources."
        ),
    )


class SOCAnalysisResponse(BaseModel):
    """
    Full response from the autonomous SOC analyst pipeline.

    +----------------------------------------------------------+
    |  AI AGENT OUTPUT                                         |
    |  This is the FINAL deliverable of the entire pipeline.   |
    |  The `report` field contains a complete markdown          |
    |  incident report with four standardised sections that    |
    |  the frontend renders directly for the SOC analyst.      |
    +----------------------------------------------------------+
    """
    report: str = Field(
        ..., description="Full markdown incident report with all four required sections."
    )
    engine: str = Field(
        ..., description="'crewai' if LLM agents were used, 'rule_based_fallback' otherwise."
    )
    severity: str = Field(
        ..., description="Assessed severity: CRITICAL, HIGH, MEDIUM, LOW, or UNKNOWN."
    )
    execution_time_s: float = Field(
        ..., description="Wall-clock time to generate the report in seconds."
    )


# ------------------------------------------------------------------
# Module 5 - Authentication Schemas
# ------------------------------------------------------------------

class SignUpRequest(BaseModel):
    """Incoming payload for the /api/auth/signup endpoint."""
    name: str = Field(
        ...,
        description="The user's display name.",
        min_length=1,
        max_length=100,
    )
    email: str = Field(
        ...,
        description="The user's email address.",
        example="analyst@example.com",
    )
    password: str = Field(
        ...,
        description="The user's password (min 6 characters).",
        min_length=6,
        max_length=128,
    )


class SignInRequest(BaseModel):
    """Incoming payload for the /api/auth/signin endpoint."""
    email: str = Field(
        ...,
        description="The user's email address.",
        example="analyst@example.com",
    )
    password: str = Field(
        ...,
        description="The user's password.",
    )


class AuthUserInfo(BaseModel):
    """User info returned after successful authentication."""
    id: str = Field(..., description="Unique user identifier.")
    name: str = Field(..., description="User display name.")
    email: str = Field(..., description="User email address.")


class AuthResponse(BaseModel):
    """Response returned by signup and signin endpoints."""
    token: str = Field(..., description="JWT bearer token for subsequent requests.")
    user: AuthUserInfo
