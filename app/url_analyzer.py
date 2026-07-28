"""
url_analyzer.py - Module 1 core logic: URL risk analysis.

This module performs static, string-level heuristics on a URL to produce
a composite risk score and a set of boolean/list indicators.  It does NOT
make outbound network requests; metadata enrichment (WHOIS, VirusTotal,
Safe Browsing) is stubbed and will be wired in a future iteration.

+----------------------------------------------------------------------+
|  AI AGENT INTEGRATION ROADMAP                                        |
|                                                                      |
|  The `analyze_url()` function returns a URLAnalysisResponse that     |
|  the Agent layer will consume as follows:                            |
|                                                                      |
|    1. risk_score >= 0.6  ->  Agent auto-flags for analyst review.    |
|    2. risk_score >= 0.8  ->  Agent recommends immediate blocking.    |
|    3. indicators dict    ->  Agent cites specific reasons in its     |
|                              natural-language explanation.            |
|    4. metadata_placeholder -> Once populated, the Agent will cross-  |
|                               reference WHOIS age, registrar rep,    |
|                               and VT community score.                |
+----------------------------------------------------------------------+
"""

import ipaddress
import logging
from typing import List

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse  # type: ignore[no-redef]

from app.config import SUSPICIOUS_TLDS, SUSPICIOUS_URL_KEYWORDS
from app.schemas import URLAnalysisRequest, URLAnalysisResponse, URLRiskIndicators

logger = logging.getLogger(__name__)


def _extract_tld(hostname):
    # type: (str) -> str
    """Return the top-level domain (e.g. '.xyz') from a hostname."""
    parts = hostname.rsplit(".", 1)
    return ".{}".format(parts[-1]) if len(parts) >= 2 else ""


def _is_ip_host(hostname):
    # type: (str) -> bool
    """Check whether the hostname is a raw IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _has_excessive_subdomains(hostname, threshold=3):
    # type: (str, int) -> bool
    """
    A hostname like 'a.b.c.d.example.com' has 4 subdomain levels.
    Phishing kits often stack subdomains to mimic legitimate brands.
    """
    # Remove a potential trailing dot (FQDN notation).
    hostname = hostname.rstrip(".")
    # Subtract 2 for the registrable domain (domain + TLD).
    subdomain_levels = hostname.count(".") - 1
    return subdomain_levels > threshold


def _find_suspicious_keywords(url_string):
    # type: (str) -> List[str]
    """Return all suspicious keywords present anywhere in the URL."""
    lower = url_string.lower()
    return sorted(kw for kw in SUSPICIOUS_URL_KEYWORDS if kw in lower)


def _compute_risk_score(indicators, url_length):
    # type: (URLRiskIndicators, int) -> float
    """
    Compute a simple weighted heuristic score in [0.0, 1.0].

    Weights are intentionally conservative; the AI Agent layer will
    apply its own contextual reasoning on top of these raw signals.
    """
    score = 0.0

    if indicators.has_suspicious_tld:
        score += 0.30
    if indicators.has_ip_address_host:
        score += 0.25
    if indicators.excessive_subdomains:
        score += 0.15
    if indicators.url_length_suspicious:
        score += 0.10

    # Each keyword adds a small increment, capped at 0.20.
    keyword_contribution = min(len(indicators.suspicious_keywords_found) * 0.05, 0.20)
    score += keyword_contribution

    return round(min(score, 1.0), 2)


def analyze_url(request):
    # type: (URLAnalysisRequest) -> URLAnalysisResponse
    """
    Perform a full static analysis on the supplied URL.

    Parameters
    ----------
    request : URLAnalysisRequest
        Validated request containing the target URL.

    Returns
    -------
    URLAnalysisResponse
        Structured result ready for the AI Agent layer.
    """
    url_string = str(request.url)
    parsed = urlparse(url_string)
    hostname = parsed.hostname or ""
    tld = _extract_tld(hostname)

    logger.info("Analysing URL: %s (host=%s, tld=%s)", url_string, hostname, tld)

    indicators = URLRiskIndicators(
        has_suspicious_tld=tld.lower() in SUSPICIOUS_TLDS,
        suspicious_keywords_found=_find_suspicious_keywords(url_string),
        has_ip_address_host=_is_ip_host(hostname),
        excessive_subdomains=_has_excessive_subdomains(hostname),
        url_length_suspicious=len(url_string) > 200,
    )

    risk_score = _compute_risk_score(indicators, len(url_string))

    return URLAnalysisResponse(
        url=url_string,
        domain=hostname,
        tld=tld,
        risk_score=risk_score,
        indicators=indicators,
        # -- PLACEHOLDER ------------------------------------------------
        # In a future iteration this will be populated by calling:
        #   - WHOIS lookup (domain age, registrar)
        #   - VirusTotal API (community score, detections)
        #   - Google Safe Browsing API (threat match)
        # The AI Agent will use this metadata to refine its verdict.
        metadata_placeholder=None,
    )
