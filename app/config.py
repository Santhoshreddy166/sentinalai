"""
config.py - Centralised application constants and configuration.

All tunables (allowed extensions, suspicious TLD lists, regex patterns)
live here so they can be changed in one place without touching business logic.
"""

from typing import Dict, FrozenSet

# ------------------------------------------------------------------
# Module 1 - URL Analysis Configuration
# ------------------------------------------------------------------

# Top-Level Domains historically associated with abuse / phishing campaigns.
# Source: Spamhaus, SURBL, and industry threat-intel feeds.
SUSPICIOUS_TLDS = frozenset({
    ".xyz", ".top", ".buzz", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".club", ".work", ".link", ".click", ".surf", ".rest",
    ".icu", ".cam", ".monster", ".loan", ".racing", ".review",
    ".win", ".bid", ".stream", ".download", ".accountant",
})  # type: FrozenSet[str]

# Keywords that frequently appear in phishing / malware URLs.
SUSPICIOUS_URL_KEYWORDS = frozenset({
    "login", "verify", "secure", "update", "confirm", "account",
    "banking", "signin", "password", "wallet", "invoice",
    "suspended", "unusual", "alert", "free", "prize",
})  # type: FrozenSet[str]

# ------------------------------------------------------------------
# Module 2 - Log Upload Configuration
# ------------------------------------------------------------------

# Maximum upload size in bytes (10 MB).
MAX_UPLOAD_SIZE_BYTES = 10 * 1024 * 1024  # type: int

# Allowed file extensions for log uploads.
ALLOWED_LOG_EXTENSIONS = frozenset({".log", ".txt"})  # type: FrozenSet[str]

# ------------------------------------------------------------------
# Regex Patterns for Log Line Extraction
# ------------------------------------------------------------------
# These patterns cover the most common log formats encountered in SOC work:
#   - Syslog / CEF / LEEF style timestamps
#   - Windows Event Log exported as text
#   - Apache / Nginx combined-log format
#   - Generic firewall deny / allow lines

LOG_PATTERNS = {
    # ISO-8601 or syslog-style timestamps
    # Matches: 2024-07-09T12:34:56, Jul  9 12:34:56, 09/Jul/2024:12:34:56
    "timestamp": (
        r"(?P<timestamp>"
        r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"        # ISO-8601
        r"|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"  # Syslog
        r"|\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}"  # CLF
        r")"
    ),

    # IPv4 addresses (source / destination)
    "ipv4": r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",

    # HTTP status codes (3-digit, starting with 1-5)
    "http_status": r"(?:HTTP/\d\.\d[\"']?\s+|\" )(?P<status>[1-5]\d{2})",

    # Windows Event IDs (e.g., "Event ID: 4625" or "EventID=4625")
    "event_id": r"[Ee]vent\s*[Ii][Dd][=:\s]+(?P<event_id>\d{1,5})",
}  # type: Dict[str, str]

# ------------------------------------------------------------------
# Module 3 - Threat Intelligence Configuration
# ------------------------------------------------------------------

import os

# API keys — loaded from environment variables for security.
# When unset, the threat_intel module falls back to mock data.
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")  # type: str
URLSCANIO_API_KEY = os.environ.get("URLSCANIO_API_KEY", "")    # type: str
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")    # type: str

# Timeout for external threat-intel HTTP requests (seconds).
THREAT_INTEL_TIMEOUT_SECONDS = 10  # type: int

# Curated list of known-malicious CIDR ranges.
# Sources: Spamhaus DROP/EDROP, Feodo Tracker, Emerging Threats.
# In production, this would be refreshed from a scheduled feed.
KNOWN_BOTNET_CIDRS = {
    # Spamhaus DROP samples
    "5.188.10.0/24":    "Bulletproof hosting (RU)",
    "45.148.10.0/24":   "Cobalt Strike C2 infrastructure",
    "91.243.44.0/24":   "Emotet distribution network",
    "193.233.20.0/24":  "Raccoon Stealer C2",
    "194.165.16.0/24":  "RedLine Stealer infrastructure",
    # Feodo Tracker ranges
    "103.43.75.0/24":   "Dridex botnet node",
    "185.215.113.0/24": "TrickBot C2 cluster",
    "198.98.56.0/24":   "Known bulletproof hosting",
    # Common scanner / brute-force sources
    "45.227.254.0/24":  "SSH brute-force farm",
    "185.156.73.0/24":  "Mirai botnet scanner range",
}  # type: Dict[str, str]
