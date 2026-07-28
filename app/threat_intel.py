"""
threat_intel.py - Module 3: Threat Intelligence Aggregator.

This module provides two core functions for enriching IOCs (Indicators
of Compromise) with external threat intelligence:

    1. check_url_reputation(url)  - Domain / URL reputation via
       VirusTotal and URLScan.io APIs.
    2. check_ip_reputation(ip)    - IP reputation via AbuseIPDB
       and known-botnet feeds.

DESIGN PHILOSOPHY
-----------------
Each function follows a "live-first, mock-fallback" pattern:

    - If a valid API key is configured, make a real HTTP call to the
      external provider and normalise the response into our schema.
    - If no key is set or the call fails, return deterministic mock
      data that exercises the same schema so the AI Agent layer can
      be developed and tested without live credentials.

+----------------------------------------------------------------------+
|  AI AGENT INTEGRATION ROADMAP                                        |
|                                                                      |
|  The dictionaries returned by these functions are passed directly    |
|  to the AI Agent layer, which will:                                  |
|                                                                      |
|    1. Merge URL reputation + static heuristics (Module 1) into a    |
|       unified threat verdict with confidence score.                  |
|    2. Merge IP reputation + log correlation (Module 2) to identify  |
|       whether an attacker IP is part of a known campaign.            |
|    3. Auto-generate MITRE ATT&CK mappings from threat tags.         |
|    4. Compose a natural-language incident brief for the SOC analyst. |
+----------------------------------------------------------------------+
"""

import hashlib
import logging
import os
import time
from typing import Any, Dict, List, Optional

import requests

from app.config import (
    ABUSEIPDB_API_KEY,
    VIRUSTOTAL_API_KEY,
    URLSCANIO_API_KEY,
    THREAT_INTEL_TIMEOUT_SECONDS,
    KNOWN_BOTNET_CIDRS,
)

logger = logging.getLogger(__name__)


# ======================================================================
#  INTERNAL HELPERS
# ======================================================================

def _is_ip_in_cidr(ip_str, cidr_str):
    # type: (str, str) -> bool
    """Check if an IPv4 address falls within a CIDR range (pure-Python)."""
    import struct
    import socket

    try:
        network_str, prefix_len_str = cidr_str.split("/")
        prefix_len = int(prefix_len_str)

        ip_int = struct.unpack("!I", socket.inet_aton(ip_str))[0]
        net_int = struct.unpack("!I", socket.inet_aton(network_str))[0]

        mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
        return (ip_int & mask) == (net_int & mask)
    except Exception:
        return False


def _safe_get(url, headers=None, params=None, timeout=None):
    # type: (str, Optional[Dict], Optional[Dict], Optional[int]) -> Optional[Dict]
    """
    Fire a GET request and return parsed JSON, or None on any failure.
    Catches all exceptions so callers never crash — they just fall back
    to mock data.
    """
    timeout = timeout or THREAT_INTEL_TIMEOUT_SECONDS
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.Timeout:
        logger.warning("Threat-intel request timed out: %s", url)
        return None
    except requests.exceptions.RequestException as exc:
        logger.warning("Threat-intel request failed: %s — %s", url, exc)
        return None
    except ValueError:
        logger.warning("Threat-intel response was not valid JSON: %s", url)
        return None


# ======================================================================
#  1. URL REPUTATION
# ======================================================================

def _virustotal_url_lookup(url_string):
    # type: (str) -> Optional[Dict[str, Any]]
    """
    Query VirusTotal API v3 for URL analysis.
    Endpoint: GET /api/v3/urls/{url_id}
    Docs: https://docs.virustotal.com/reference/url-info
    """
    if not VIRUSTOTAL_API_KEY:
        return None

    # VT uses a base64url-encoded URL (no padding) as the resource ID.
    import base64
    url_id = base64.urlsafe_b64encode(url_string.encode()).decode().rstrip("=")

    data = _safe_get(
        "https://www.virustotal.com/api/v3/urls/{}".format(url_id),
        headers={"x-apikey": VIRUSTOTAL_API_KEY},
    )
    if not data:
        return None

    try:
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "provider": "virustotal",
            "malicious_count": stats.get("malicious", 0),
            "suspicious_count": stats.get("suspicious", 0),
            "harmless_count": stats.get("harmless", 0),
            "undetected_count": stats.get("undetected", 0),
            "threat_names": attrs.get("threat_names", []),
            "reputation_score": attrs.get("reputation", 0),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "categories": attrs.get("categories", {}),
        }
    except Exception as exc:
        logger.warning("Failed to parse VirusTotal response: %s", exc)
        return None


def _urlscanio_lookup(url_string):
    # type: (str) -> Optional[Dict[str, Any]]
    """
    Search URLScan.io for existing scans of this URL.
    Endpoint: GET /api/v1/search/?q=page.url:"<url>"
    Docs: https://urlscan.io/docs/api/
    """
    if not URLSCANIO_API_KEY:
        return None

    data = _safe_get(
        "https://urlscan.io/api/v1/search/",
        headers={"API-Key": URLSCANIO_API_KEY},
        params={"q": 'page.url:"{}"'.format(url_string)},
    )
    if not data:
        return None

    try:
        results = data.get("results", [])
        if not results:
            return {
                "provider": "urlscan.io",
                "scan_found": False,
                "verdicts": [],
                "tags": [],
            }

        latest = results[0]
        return {
            "provider": "urlscan.io",
            "scan_found": True,
            "scan_id": latest.get("_id"),
            "verdicts": latest.get("verdicts", {}).get("overall", {}).get("categories", []),
            "tags": latest.get("tags", []),
            "page_domain": latest.get("page", {}).get("domain"),
            "page_ip": latest.get("page", {}).get("ip"),
            "page_country": latest.get("page", {}).get("country"),
        }
    except Exception as exc:
        logger.warning("Failed to parse URLScan.io response: %s", exc)
        return None


def _generate_url_mock_data(url_string):
    # type: (str) -> Dict[str, Any]
    """
    Generate deterministic mock threat-intel data for a URL.

    The mock is seeded from a hash of the URL so the same URL always
    produces the same mock result — useful for reproducible testing.
    """
    url_hash = int(hashlib.md5(url_string.encode()).hexdigest()[:8], 16)

    # Derive plausible values from the hash.
    malicious_count = url_hash % 15
    is_malicious = malicious_count > 5

    mock_tags = []  # type: List[str]
    tag_pool = ["phishing", "malware", "spam", "c2", "scam", "suspicious",
                "credential-harvesting", "drive-by-download"]
    for i, tag in enumerate(tag_pool):
        if (url_hash >> i) & 1:
            mock_tags.append(tag)

    return {
        "provider": "mock",
        "source_note": "Mock data — no API keys configured. Set VIRUSTOTAL_API_KEY "
                       "and/or URLSCANIO_API_KEY environment variables for live lookups.",
        "malicious_count": malicious_count,
        "suspicious_count": (url_hash % 7),
        "harmless_count": 60 - malicious_count,
        "undetected_count": 12,
        "is_malicious": is_malicious,
        "threat_tags": mock_tags[:4],
        "threat_classification": "malicious" if is_malicious else "clean",
        "domain_age_days": (url_hash % 3650),
        "registrar": "Mock Registrar Inc.",
        "ssl_valid": not is_malicious,
        "categories": {"mock_engine": "phishing" if is_malicious else "uncategorized"},
    }


def check_url_reputation(url_string):
    # type: (str) -> Dict[str, Any]
    """
    Check a URL against external threat intelligence feeds.

    Tries VirusTotal and URLScan.io in order. If neither API key is
    configured or both calls fail, returns deterministic mock data.

    Parameters
    ----------
    url_string : str
        The full URL to check (e.g. "https://evil.xyz/phish").

    Returns
    -------
    dict
        Structured intelligence report ready for the AI Agent layer.

    +--------------------------------------------------------------+
    |  AI AGENT INTEGRATION POINT                                  |
    |                                                              |
    |  This dict is merged with Module 1's heuristic analysis to   |
    |  produce a unified threat verdict. The Agent will weight     |
    |  external intel higher than local heuristics when available. |
    +--------------------------------------------------------------+
    """
    logger.info("Checking URL reputation: %s", url_string)

    results = {}  # type: Dict[str, Any]
    results["query"] = url_string
    results["timestamp"] = time.time()
    results["sources"] = []  # type: List[Dict[str, Any]]

    # --- Attempt VirusTotal ---
    vt_data = _virustotal_url_lookup(url_string)
    if vt_data:
        results["sources"].append(vt_data)
        logger.info("VirusTotal returned data for %s", url_string)

    # --- Attempt URLScan.io ---
    us_data = _urlscanio_lookup(url_string)
    if us_data:
        results["sources"].append(us_data)
        logger.info("URLScan.io returned data for %s", url_string)

    # --- Fallback to mock ---
    if not results["sources"]:
        logger.info("No live API keys configured — returning mock data for %s", url_string)
        mock = _generate_url_mock_data(url_string)
        results["sources"].append(mock)
        results["data_source"] = "mock"
    else:
        results["data_source"] = "live"

    # --- Compute aggregate verdict ---
    total_malicious = sum(
        s.get("malicious_count", 0) for s in results["sources"]
    )
    results["aggregate_malicious_count"] = total_malicious
    results["aggregate_verdict"] = "malicious" if total_malicious > 5 else "clean"

    return results


# ======================================================================
#  2. IP REPUTATION
# ======================================================================

def _abuseipdb_lookup(ip_address):
    # type: (str) -> Optional[Dict[str, Any]]
    """
    Query AbuseIPDB for an IP address.
    Endpoint: GET /api/v2/check
    Docs: https://docs.abuseipdb.com/#check-endpoint
    """
    if not ABUSEIPDB_API_KEY:
        return None

    data = _safe_get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json",
        },
        params={
            "ipAddress": ip_address,
            "maxAgeInDays": "90",
            "verbose": "",
        },
    )
    if not data:
        return None

    try:
        info = data.get("data", {})
        return {
            "provider": "abuseipdb",
            "abuse_confidence_score": info.get("abuseConfidenceScore", 0),
            "total_reports": info.get("totalReports", 0),
            "country_code": info.get("countryCode"),
            "isp": info.get("isp"),
            "domain": info.get("domain"),
            "is_tor": info.get("isTor", False),
            "is_whitelisted": info.get("isWhitelisted", False),
            "last_reported_at": info.get("lastReportedAt"),
            "usage_type": info.get("usageType"),
        }
    except Exception as exc:
        logger.warning("Failed to parse AbuseIPDB response: %s", exc)
        return None


def _check_known_botnets(ip_address):
    # type: (str) -> Dict[str, Any]
    """
    Check if the IP falls within any known botnet / malicious CIDR ranges.

    The CIDR list in config.py is a curated sample; in production this
    would be refreshed from threat feeds (e.g. Emerging Threats, Feodo
    Tracker, Spamhaus DROP/EDROP).
    """
    matched_networks = []  # type: List[str]

    for cidr, label in KNOWN_BOTNET_CIDRS.items():
        if _is_ip_in_cidr(ip_address, cidr):
            matched_networks.append(label)

    return {
        "provider": "local_botnet_db",
        "matched_networks": matched_networks,
        "is_known_malicious": len(matched_networks) > 0,
    }


def _generate_ip_mock_data(ip_address):
    # type: (str) -> Dict[str, Any]
    """
    Generate deterministic mock threat-intel data for an IP address.
    Seeded from the IP hash for reproducibility.
    """
    ip_hash = int(hashlib.md5(ip_address.encode()).hexdigest()[:8], 16)

    abuse_score = ip_hash % 101  # 0-100
    total_reports = ip_hash % 500
    is_malicious = abuse_score > 50

    mock_categories = []  # type: List[str]
    category_pool = [
        "brute-force", "port-scan", "web-attack", "spam",
        "ssh-abuse", "DDoS", "botnet-drone", "phishing-host",
    ]
    for i, cat in enumerate(category_pool):
        if (ip_hash >> i) & 1:
            mock_categories.append(cat)

    return {
        "provider": "mock",
        "source_note": "Mock data — no API keys configured. Set ABUSEIPDB_API_KEY "
                       "environment variable for live lookups.",
        "abuse_confidence_score": abuse_score,
        "total_reports": total_reports,
        "is_malicious": is_malicious,
        "threat_categories": mock_categories[:3],
        "country_code": ["US", "RU", "CN", "BR", "DE", "NL"][ip_hash % 6],
        "isp": "Mock ISP Corp.",
        "is_tor": (ip_hash % 10) == 0,
        "is_vpn": (ip_hash % 8) == 0,
        "is_proxy": (ip_hash % 12) == 0,
        "last_reported_at": "2024-07-09T12:00:00Z",
    }


def check_ip_reputation(ip_address):
    # type: (str) -> Dict[str, Any]
    """
    Check an IP address against threat intelligence feeds and local
    botnet CIDR databases.

    Tries AbuseIPDB first, then always checks the local botnet DB.
    Falls back to mock data if no API key is available.

    Parameters
    ----------
    ip_address : str
        The IPv4 address to check (e.g. "203.0.113.50").

    Returns
    -------
    dict
        Structured intelligence report ready for the AI Agent layer.

    +--------------------------------------------------------------+
    |  AI AGENT INTEGRATION POINT                                  |
    |                                                              |
    |  This dict is merged with Module 2's parsed log entries to   |
    |  determine whether source/destination IPs in the logs belong |
    |  to known malicious infrastructure. The Agent will:          |
    |    - Flag any IP with abuse_confidence_score > 75            |
    |    - Highlight IPs matched to botnet CIDRs                   |
    |    - Correlate repeated bad-IP appearances across log lines  |
    |    - Generate IOC (Indicator of Compromise) reports          |
    +--------------------------------------------------------------+
    """
    logger.info("Checking IP reputation: %s", ip_address)

    results = {}  # type: Dict[str, Any]
    results["query"] = ip_address
    results["timestamp"] = time.time()
    results["sources"] = []  # type: List[Dict[str, Any]]

    # --- Attempt AbuseIPDB ---
    abuse_data = _abuseipdb_lookup(ip_address)
    if abuse_data:
        results["sources"].append(abuse_data)
        logger.info("AbuseIPDB returned data for %s", ip_address)

    # --- Always check local botnet DB ---
    botnet_data = _check_known_botnets(ip_address)
    results["sources"].append(botnet_data)
    if botnet_data["is_known_malicious"]:
        logger.warning(
            "IP %s matched known malicious networks: %s",
            ip_address, botnet_data["matched_networks"],
        )

    # --- Mock fallback if no live API data ---
    has_live_api_data = any(
        s.get("provider") not in ("local_botnet_db", "mock")
        for s in results["sources"]
    )
    if not has_live_api_data:
        logger.info("No live API keys configured — adding mock data for %s", ip_address)
        mock = _generate_ip_mock_data(ip_address)
        results["sources"].append(mock)
        results["data_source"] = "mock"
    else:
        results["data_source"] = "live"

    # --- Compute aggregate verdict ---
    max_abuse_score = max(
        (s.get("abuse_confidence_score", 0) for s in results["sources"]),
        default=0,
    )
    is_botnet = botnet_data["is_known_malicious"]
    results["aggregate_abuse_score"] = max_abuse_score
    results["is_known_botnet"] = is_botnet
    results["aggregate_verdict"] = (
        "malicious" if (max_abuse_score > 50 or is_botnet) else "clean"
    )

    return results
