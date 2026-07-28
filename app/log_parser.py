"""
log_parser.py - Module 2 core logic: Log file parsing engine.

This module reads uploaded log file content, applies regex-based
extraction to isolate structured fields (timestamps, IPs, status codes,
Event IDs), and returns a clean list of ParsedLogEntry objects.

Two parsing strategies are provided:
  1. `parse_log_lines_regex`  - Pure regex, zero external dependencies.
  2. `parse_log_lines_pandas` - Uses Pandas for tabular cleaning and
                                 deduplication on large files.

The caller (router) can choose either; the default pipeline uses regex
for files under 1 MB and Pandas for larger uploads.

+----------------------------------------------------------------------+
|  AI AGENT INTEGRATION ROADMAP                                        |
|                                                                      |
|  The list[ParsedLogEntry] produced here is the *primary feed*        |
|  into the AI Agent layer.  The Agent will:                           |
|                                                                      |
|    1. Group entries by source_ip to detect brute-force / spray       |
|       patterns (e.g. many 4625 events from one IP).                  |
|    2. Detect time-window anomalies (burst of 403s in 10 seconds).    |
|    3. Cross-reference Event IDs with a MITRE ATT&CK mapping table.  |
|    4. Produce a ranked list of Indicators of Compromise (IOCs).      |
|    5. Draft an incident summary in natural language for the analyst. |
+----------------------------------------------------------------------+
"""

import logging
import re
from typing import List, Optional, Sequence, Tuple

import pandas as pd

from app.config import LOG_PATTERNS
from app.schemas import ParsedLogEntry

logger = logging.getLogger(__name__)

# Pre-compile patterns once at module load for performance.
_RE_TIMESTAMP = re.compile(LOG_PATTERNS["timestamp"])
_RE_IPV4 = re.compile(LOG_PATTERNS["ipv4"])
_RE_HTTP_STATUS = re.compile(LOG_PATTERNS["http_status"])
_RE_EVENT_ID = re.compile(LOG_PATTERNS["event_id"])


# ------------------------------------------------------------------
# Strategy 1 - Pure Regex Parsing
# ------------------------------------------------------------------

def _extract_ips(line):
    # type: (str) -> Tuple[Optional[str], Optional[str]]
    """
    Extract up to two IPv4 addresses from a log line.

    Convention:
      - First IP found  -> source_ip
      - Second IP found -> destination_ip
    """
    matches = _RE_IPV4.findall(line)
    src = matches[0] if len(matches) >= 1 else None
    dst = matches[1] if len(matches) >= 2 else None
    return src, dst


def _parse_single_line(line_number, raw_line):
    # type: (int, str) -> Optional[ParsedLogEntry]
    """
    Apply all regex patterns to a single line and return a ParsedLogEntry,
    or None if the line is blank / yields no structured data.
    """
    stripped = raw_line.strip()
    if not stripped:
        return None

    # Timestamp
    ts_match = _RE_TIMESTAMP.search(stripped)
    timestamp = ts_match.group("timestamp") if ts_match else None

    # IPs
    source_ip, destination_ip = _extract_ips(stripped)

    # HTTP status code
    status_match = _RE_HTTP_STATUS.search(stripped)
    status_code = status_match.group("status") if status_match else None

    # Windows Event ID
    eid_match = _RE_EVENT_ID.search(stripped)
    event_id = eid_match.group("event_id") if eid_match else None

    # Only return an entry if at least one field was extracted.
    if not any([timestamp, source_ip, destination_ip, status_code, event_id]):
        return None

    return ParsedLogEntry(
        line_number=line_number,
        raw_line=stripped,
        timestamp=timestamp,
        source_ip=source_ip,
        destination_ip=destination_ip,
        status_code=status_code,
        event_id=event_id,
    )


def parse_log_lines_regex(lines):
    # type: (Sequence[str]) -> List[ParsedLogEntry]
    """
    Parse an iterable of raw log lines using compiled regex patterns.

    Parameters
    ----------
    lines : Sequence[str]
        Raw lines read from the uploaded file (preserving order).

    Returns
    -------
    List[ParsedLogEntry]
        Only lines that yielded at least one structured field.
    """
    entries = []  # type: List[ParsedLogEntry]
    for idx, line in enumerate(lines, start=1):
        entry = _parse_single_line(idx, line)
        if entry is not None:
            entries.append(entry)

    logger.info(
        "Regex parser: %d / %d lines produced structured entries.",
        len(entries),
        len(lines),
    )
    return entries


# ------------------------------------------------------------------
# Strategy 2 - Pandas-Assisted Parsing (for large files)
# ------------------------------------------------------------------

def parse_log_lines_pandas(lines):
    # type: (Sequence[str]) -> List[ParsedLogEntry]
    """
    Parse log lines into a Pandas DataFrame for vectorised cleaning,
    then convert back to ParsedLogEntry objects.

    This strategy is preferred for files > 1 MB where Pandas' C-backed
    string operations outperform pure-Python loops.

    Parameters
    ----------
    lines : Sequence[str]
        Raw lines read from the uploaded file.

    Returns
    -------
    List[ParsedLogEntry]
        Cleaned, deduplicated entries.
    """
    # Build a DataFrame of raw lines.
    df = pd.DataFrame({
        "line_number": list(range(1, len(lines) + 1)),
        "raw_line": [l.strip() for l in lines],
    })

    # Drop blank lines early.
    df = df[df["raw_line"].str.len() > 0].copy()

    if df.empty:
        return []

    # Vectorised extraction using Pandas .str.extract().
    df["timestamp"] = df["raw_line"].str.extract(
        LOG_PATTERNS["timestamp"], expand=False
    )

    # For IPs, use findall and unpack into two columns.
    ip_series = df["raw_line"].str.findall(LOG_PATTERNS["ipv4"])
    df["source_ip"] = ip_series.apply(lambda m: m[0] if len(m) >= 1 else None)
    df["destination_ip"] = ip_series.apply(lambda m: m[1] if len(m) >= 2 else None)

    df["status_code"] = df["raw_line"].str.extract(
        LOG_PATTERNS["http_status"], expand=False
    )
    df["event_id"] = df["raw_line"].str.extract(
        LOG_PATTERNS["event_id"], expand=False
    )

    # Keep only rows with at least one extracted field.
    extraction_cols = ["timestamp", "source_ip", "destination_ip", "status_code", "event_id"]
    df = df.dropna(subset=extraction_cols, how="all")

    # Replace NaN with None for clean Pydantic serialization.
    for col in extraction_cols:
        df[col] = df[col].where(df[col].notna(), other=None)

    # Drop exact-duplicate parsed rows (same IP, same timestamp, etc.).
    df = df.drop_duplicates(subset=extraction_cols, keep="first")

    logger.info(
        "Pandas parser: %d rows retained after cleaning.",
        len(df),
    )

    entries = [
        ParsedLogEntry(**row)
        for row in df.to_dict(orient="records")
    ]
    return entries
