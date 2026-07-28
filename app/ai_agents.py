"""
ai_agents.py - Module 4: Agentic AI Security Analyst Layer.

This module orchestrates two specialised security agents to analyse
incident data from Modules 1-3 and produce a structured SOC report.

DUAL-MODE ARCHITECTURE
----------------------
  Mode A (CrewAI):    When the `crewai` package is available (Python 3.10+),
                      this module instantiates real CrewAI Agent/Task/Crew
                      objects backed by an LLM for autonomous reasoning.

  Mode B (Fallback):  When CrewAI is unavailable (Python <3.10 or missing
                      dependency), a rule-based analysis engine produces the
                      same structured report using deterministic heuristics.

Both modes return an identical markdown report with these exact headers:

    ### Incident Summary & Status
    ### 1. Why & How Did It Occur?
    ### 2. How to Stop and Contain It?
    ### 3. How to Prevent It in the Future?

ENTRY POINT
-----------
    run_autonomous_soc(input_data, intel_data) -> dict

+----------------------------------------------------------------------+
|  AI AGENT INTEGRATION POINT                                          |
|                                                                      |
|  This is the CORE intelligence layer. It consumes:                   |
|    - input_data:  Parsed log entries (Module 2) and/or URL analysis  |
|                   results (Module 1).                                |
|    - intel_data:  Threat intelligence enrichment (Module 3).         |
|                                                                      |
|  And produces a complete incident report that the frontend will      |
|  render for the SOC analyst.                                         |
+----------------------------------------------------------------------+
"""

import logging
import time
from collections import Counter
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Detect CrewAI availability
# ------------------------------------------------------------------
CREWAI_AVAILABLE = False
try:
    from crewai import Agent, Task, Crew, Process
    CREWAI_AVAILABLE = True
    logger.info("CrewAI detected - using LLM-backed agent pipeline.")
except ImportError:
    logger.info(
        "CrewAI not available (requires Python 3.10+). "
        "Using rule-based fallback analysis engine."
    )


# ======================================================================
#  MODE A: CrewAI Pipeline (Python 3.10+ with crewai installed)
# ======================================================================

def _build_crewai_pipeline(input_data, intel_data):
    # type: (Dict[str, Any], Dict[str, Any]) -> str
    """
    Build and run a CrewAI Crew with two sequential agents.

    This function is only called when CrewAI is available.
    It requires an LLM API key (e.g. OPENAI_API_KEY) in the environment.
    """
    if not CREWAI_AVAILABLE:
        raise RuntimeError("CrewAI is not installed.")

    # -- Serialise context for the agents -------------------------
    context_block = _format_context_for_agents(input_data, intel_data)

    # -- Agent 1: Forensic Triage Agent ---------------------------
    forensic_agent = Agent(
        role="Forensic Triage Analyst",
        goal=(
            "Reconstruct the incident timeline and discover the root cause. "
            "Determine HOW the attack was executed and WHY it succeeded."
        ),
        backstory=(
            "You are an expert digital forensics responder with 15+ years "
            "of experience in enterprise SOC operations. You specialise in "
            "log correlation, phishing campaign architecture, lateral "
            "movement detection, and MITRE ATT&CK technique identification. "
            "You reconstruct attack chains from raw evidence with surgical "
            "precision."
        ),
        verbose=True,
        allow_delegation=False,
    )

    # -- Agent 2: Playbook & Mitigation Agent ---------------------
    playbook_agent = Agent(
        role="Playbook & Mitigation Advisor",
        goal=(
            "Formulate immediate containment actions and long-term prevention "
            "protocols based on the Forensic Triage Analyst's findings."
        ),
        backstory=(
            "You are a seasoned CISO advisor with deep expertise in network "
            "hardening, zero-trust architecture, and defensive configuration "
            "strategies. You translate forensic findings into actionable "
            "containment playbooks and strategic prevention roadmaps that "
            "map to CIS Controls and NIST CSF."
        ),
        verbose=True,
        allow_delegation=False,
    )

    # -- Task 1: Forensic Analysis --------------------------------
    forensic_task = Task(
        description=(
            "Analyse the following security event data and threat intelligence "
            "to reconstruct the incident timeline and identify root cause.\n\n"
            "{context}\n\n"
            "Produce your findings under these headers:\n"
            "### Incident Summary & Status\n"
            "### 1. Why & How Did It Occur?\n"
        ).format(context=context_block),
        agent=forensic_agent,
        expected_output=(
            "A detailed forensic analysis with incident timeline, attack "
            "vector identification, and root cause determination."
        ),
    )

    # -- Task 2: Playbook & Mitigation ----------------------------
    playbook_task = Task(
        description=(
            "Based on the forensic analysis above, create a complete incident "
            "response report. Use the forensic findings and add containment "
            "and prevention sections.\n\n"
            "Your FINAL output must be a single markdown document with ALL "
            "of these exact headers (include the emoji):\n\n"
            "### Incident Summary & Status\n"
            "### 1. Why & How Did It Occur?\n"
            "### 2. How to Stop and Contain It?\n"
            "### 3. How to Prevent It in the Future?\n"
        ),
        agent=playbook_agent,
        expected_output=(
            "A complete SOC incident report in markdown format with all four "
            "required sections filled with specific, actionable information."
        ),
    )

    # -- Crew: Sequential execution -------------------------------
    crew = Crew(
        agents=[forensic_agent, playbook_agent],
        tasks=[forensic_task, playbook_task],
        process=Process.sequential,
        verbose=True,
    )

    result = crew.kickoff()

    # CrewAI returns a CrewOutput object; extract the string.
    return str(result)


# ======================================================================
#  MODE B: Rule-Based Fallback Engine (any Python version)
# ======================================================================

def _analyse_log_patterns(input_data):
    # type: (Dict[str, Any]) -> Dict[str, Any]
    """
    Perform statistical analysis on parsed log entries to identify
    attack patterns, anomalies, and high-risk indicators.
    """
    entries = input_data.get("parsed_entries", [])
    if not entries:
        return {
            "total_events": 0,
            "attack_patterns": [],
            "timeline": [],
            "high_risk_ips": [],
            "event_id_summary": {},
        }

    # -- IP frequency analysis ------------------------------------
    src_ip_counter = Counter()  # type: Counter
    dst_ip_counter = Counter()  # type: Counter
    status_counter = Counter()  # type: Counter
    event_id_counter = Counter()  # type: Counter
    timestamps = []  # type: List[str]

    for entry in entries:
        if isinstance(entry, dict):
            src = entry.get("source_ip")
            dst = entry.get("destination_ip")
            status = entry.get("status_code")
            eid = entry.get("event_id")
            ts = entry.get("timestamp")
        else:
            src = getattr(entry, "source_ip", None)
            dst = getattr(entry, "destination_ip", None)
            status = getattr(entry, "status_code", None)
            eid = getattr(entry, "event_id", None)
            ts = getattr(entry, "timestamp", None)

        if src:
            src_ip_counter[src] += 1
        if dst:
            dst_ip_counter[dst] += 1
        if status:
            status_counter[status] += 1
        if eid:
            event_id_counter[eid] += 1
        if ts:
            timestamps.append(ts)

    # -- Detect attack patterns -----------------------------------
    attack_patterns = []  # type: List[str]

    # Brute-force detection: same source IP with multiple 401/403 or 4625 events
    for ip, count in src_ip_counter.most_common(10):
        if count >= 3:
            # Count failed auths from this IP
            failed_from_ip = sum(
                1 for e in entries
                if (e.get("source_ip") if isinstance(e, dict) else getattr(e, "source_ip", None)) == ip
                and (
                    (e.get("status_code") if isinstance(e, dict) else getattr(e, "status_code", None)) in ("401", "403")
                    or (e.get("event_id") if isinstance(e, dict) else getattr(e, "event_id", None)) == "4625"
                )
            )
            if failed_from_ip >= 3:
                attack_patterns.append(
                    "BRUTE_FORCE: {} failed authentication attempts from IP {} "
                    "(MITRE ATT&CK: T1110 - Brute Force)".format(failed_from_ip, ip)
                )

    # Credential stuffing: Event ID 4625 spike
    if event_id_counter.get("4625", 0) >= 3:
        attack_patterns.append(
            "CREDENTIAL_ATTACK: {} failed logon events (Event ID 4625) detected "
            "(MITRE ATT&CK: T1110.001 - Password Guessing)".format(event_id_counter["4625"])
        )

    # Account creation after compromise: 4720 following 4625
    if event_id_counter.get("4720", 0) > 0 and event_id_counter.get("4625", 0) > 0:
        attack_patterns.append(
            "PERSISTENCE: Account creation (Event ID 4720) detected after failed "
            "logon attempts — possible post-compromise persistence "
            "(MITRE ATT&CK: T1136.001 - Create Account: Local Account)"
        )

    # Scanning / recon: multiple destination IPs from one source
    for ip, count in src_ip_counter.most_common(5):
        targets = set()
        for e in entries:
            if (e.get("source_ip") if isinstance(e, dict) else getattr(e, "source_ip", None)) == ip:
                dst = e.get("destination_ip") if isinstance(e, dict) else getattr(e, "destination_ip", None)
                if dst:
                    targets.add(dst)
        if len(targets) >= 3:
            attack_patterns.append(
                "SCANNING: IP {} contacted {} unique destinations — possible "
                "network reconnaissance (MITRE ATT&CK: T1046 - Network Service Discovery)".format(
                    ip, len(targets)
                )
            )

    # HTTP error spike
    error_codes = sum(v for k, v in status_counter.items() if k and k.startswith(("4", "5")))
    if error_codes >= 5:
        attack_patterns.append(
            "HTTP_ANOMALY: {} HTTP 4xx/5xx errors detected — possible web "
            "application attack (MITRE ATT&CK: T1190 - Exploit Public-Facing Application)".format(
                error_codes
            )
        )

    # Identify high-risk IPs (most frequent sources of bad events)
    high_risk_ips = [ip for ip, count in src_ip_counter.most_common(5) if count >= 2]

    return {
        "total_events": len(entries),
        "attack_patterns": attack_patterns,
        "timeline": sorted(set(timestamps))[:20],
        "high_risk_ips": high_risk_ips,
        "src_ip_freq": dict(src_ip_counter.most_common(10)),
        "dst_ip_freq": dict(dst_ip_counter.most_common(10)),
        "status_distribution": dict(status_counter),
        "event_id_summary": dict(event_id_counter),
    }


def _analyse_url_data(input_data):
    # type: (Dict[str, Any]) -> Dict[str, Any]
    """Extract URL analysis signals from Module 1 output."""
    url = input_data.get("url", "")
    risk_score = input_data.get("risk_score", 0)
    indicators = input_data.get("indicators", {})
    domain = input_data.get("domain", "")

    findings = []  # type: List[str]

    if isinstance(indicators, dict):
        if indicators.get("has_suspicious_tld"):
            findings.append("Domain uses a suspicious TLD commonly associated with abuse")
        if indicators.get("has_ip_address_host"):
            findings.append("URL uses a raw IP address instead of a domain name — "
                          "common in phishing infrastructure")
        if indicators.get("excessive_subdomains"):
            findings.append("Excessive subdomain levels detected — common technique "
                          "to mimic legitimate brands")
        keywords = indicators.get("suspicious_keywords_found", [])
        if keywords:
            findings.append("Phishing keywords detected in URL: {}".format(", ".join(keywords)))

    return {
        "url": url,
        "domain": domain,
        "risk_score": risk_score,
        "findings": findings,
    }


def _analyse_intel_data(intel_data):
    # type: (Dict[str, Any]) -> Dict[str, Any]
    """Extract threat intelligence signals from Module 3 output."""
    if not intel_data:
        return {"available": False, "findings": []}

    findings = []  # type: List[str]
    verdict = intel_data.get("aggregate_verdict", "unknown")
    sources = intel_data.get("sources", [])
    if isinstance(intel_data.get("result"), dict):
        sources = intel_data["result"].get("sources", sources)

    for src in sources:
        provider = src.get("provider", "unknown")

        # URL reputation signals
        mal_count = src.get("malicious_count", 0)
        if mal_count > 0:
            findings.append("{} engine(s) on {} flagged this as malicious".format(
                mal_count, provider
            ))

        threat_tags = src.get("threat_tags", []) or src.get("threat_names", [])
        if threat_tags:
            findings.append("Threat tags from {}: {}".format(
                provider, ", ".join(threat_tags)
            ))

        # IP reputation signals
        abuse_score = src.get("abuse_confidence_score", 0)
        if abuse_score > 50:
            findings.append("AbuseIPDB confidence score: {}% — high abuse probability".format(
                abuse_score
            ))

        categories = src.get("threat_categories", [])
        if categories:
            findings.append("Threat categories: {}".format(", ".join(categories)))

        matched_nets = src.get("matched_networks", [])
        if matched_nets:
            findings.append("CRITICAL: IP matched known malicious networks: {}".format(
                ", ".join(matched_nets)
            ))

        if src.get("is_tor"):
            findings.append("IP is associated with Tor exit node")
        if src.get("is_vpn"):
            findings.append("IP is associated with VPN/proxy service")

    return {
        "available": True,
        "verdict": verdict,
        "findings": findings,
        "data_source": intel_data.get("data_source", "unknown"),
    }


def _build_fallback_report(input_data, intel_data):
    # type: (Dict[str, Any], Dict[str, Any]) -> str
    """
    Generate a structured SOC report using rule-based analysis.

    This is the fallback when CrewAI is unavailable. It analyses the
    actual data from Modules 1-3 and produces a meaningful report.
    """
    # -- Gather all analysis results ------------------------------
    log_analysis = _analyse_log_patterns(input_data)
    url_analysis = _analyse_url_data(input_data)
    intel_analysis = _analyse_intel_data(intel_data)

    attack_patterns = log_analysis.get("attack_patterns", [])
    url_findings = url_analysis.get("findings", [])
    intel_findings = intel_analysis.get("findings", [])
    high_risk_ips = log_analysis.get("high_risk_ips", [])
    event_summary = log_analysis.get("event_id_summary", {})
    status_dist = log_analysis.get("status_distribution", {})
    timeline = log_analysis.get("timeline", [])

    # -- Determine severity ----------------------------------------
    severity = "LOW"
    if attack_patterns:
        severity = "MEDIUM"
    if any("PERSISTENCE" in p for p in attack_patterns):
        severity = "HIGH"
    if any("CRITICAL" in f for f in intel_findings):
        severity = "CRITICAL"
    if intel_analysis.get("verdict") == "malicious":
        severity = max(severity, "HIGH")

    # -- Build the report ------------------------------------------
    sections = []  # type: List[str]

    # ── Section 0: Incident Summary ──
    sections.append("### \U0001f4d1 Incident Summary & Status\n")
    sections.append("| Field | Value |")
    sections.append("|---|---|")
    sections.append("| **Severity** | {} |".format(severity))
    sections.append("| **Status** | Under Investigation |")
    sections.append("| **Total Events Analysed** | {} |".format(log_analysis["total_events"]))
    sections.append("| **Attack Patterns Detected** | {} |".format(len(attack_patterns)))
    sections.append("| **High-Risk IPs Identified** | {} |".format(len(high_risk_ips)))
    sections.append("| **Threat Intel Verdict** | {} |".format(
        intel_analysis.get("verdict", "N/A")
    ))
    sections.append("| **Analysis Engine** | Rule-Based Fallback (CrewAI unavailable) |")

    if url_analysis["url"]:
        sections.append("| **Target URL** | `{}` |".format(url_analysis["url"]))
        sections.append("| **Domain** | `{}` |".format(url_analysis["domain"]))
        sections.append("| **URL Risk Score** | {:.0%} |".format(url_analysis["risk_score"]))

    if timeline:
        sections.append("\n**Observed Timeline Window:** `{}` to `{}`".format(
            timeline[0], timeline[-1]
        ))

    # ── Section 1: Root Cause Analysis ──
    sections.append("\n### \U0001f50d 1. Why & How Did It Occur?\n")

    if attack_patterns:
        sections.append("**Detected Attack Patterns:**\n")
        for i, pattern in enumerate(attack_patterns, 1):
            sections.append("{}. **{}**".format(i, pattern))
    else:
        sections.append("No definitive attack patterns detected in the available data.\n")

    if url_findings:
        sections.append("\n**URL Analysis Findings:**\n")
        for finding in url_findings:
            sections.append("- {}".format(finding))

    if intel_findings:
        sections.append("\n**Threat Intelligence Findings:**\n")
        for finding in intel_findings:
            sections.append("- {}".format(finding))

    if event_summary:
        sections.append("\n**Windows Event ID Breakdown:**\n")
        sections.append("| Event ID | Count | Significance |")
        sections.append("|---|---|---|")
        event_descriptions = {
            "4624": "Successful Logon",
            "4625": "Failed Logon Attempt",
            "4720": "User Account Created",
            "4722": "User Account Enabled",
            "4723": "Password Change Attempted",
            "4724": "Password Reset Attempted",
            "4725": "User Account Disabled",
            "4726": "User Account Deleted",
            "4740": "Account Locked Out",
            "4767": "Account Unlocked",
            "1102": "Audit Log Cleared",
        }
        for eid, count in sorted(event_summary.items(), key=lambda x: x[1], reverse=True):
            desc = event_descriptions.get(eid, "Other Security Event")
            sections.append("| {} | {} | {} |".format(eid, count, desc))

    if status_dist:
        sections.append("\n**HTTP Status Code Distribution:**\n")
        sections.append("| Status | Count | Interpretation |")
        sections.append("|---|---|---|")
        status_meanings = {
            "200": "OK - Successful access",
            "301": "Redirect - Possible URL manipulation",
            "400": "Bad Request - Malformed input",
            "401": "Unauthorized - Failed authentication",
            "403": "Forbidden - Access denied",
            "404": "Not Found - Directory/path enumeration",
            "500": "Server Error - Possible exploitation",
        }
        for code, count in sorted(status_dist.items(), key=lambda x: x[1], reverse=True):
            meaning = status_meanings.get(code, "Other")
            sections.append("| {} | {} | {} |".format(code, count, meaning))

    if high_risk_ips:
        sections.append("\n**High-Risk Source IPs:**\n")
        for ip in high_risk_ips:
            freq = log_analysis.get("src_ip_freq", {}).get(ip, 0)
            sections.append("- `{}` ({} events)".format(ip, freq))

    # ── Section 2: Containment ──
    sections.append("\n### \U0001f6e1\ufe0f 2. How to Stop and Contain It?\n")
    sections.append("**Immediate Actions (First 30 Minutes):**\n")

    action_num = 1

    if high_risk_ips:
        sections.append(
            "{}. **Block malicious IPs at the perimeter firewall:**".format(action_num)
        )
        for ip in high_risk_ips:
            sections.append("   - `iptables -A INPUT -s {} -j DROP`".format(ip))
            sections.append("   - Add `{}` to the EDR/SIEM blocklist".format(ip))
        action_num += 1

    if any("4625" in p for p in attack_patterns):
        sections.append(
            "{}. **Enable account lockout policy:**\n"
            "   - Lock accounts after 5 failed attempts for 30 minutes\n"
            "   - `net accounts /lockoutthreshold:5 /lockoutduration:30`".format(action_num)
        )
        action_num += 1

    if any("4720" in p for p in attack_patterns):
        sections.append(
            "{}. **Audit newly created accounts:**\n"
            "   - Review all accounts created in the past 24 hours\n"
            "   - Disable any accounts not authorised by IT\n"
            "   - `Get-ADUser -Filter * -Properties WhenCreated | "
            "Where-Object {{$_.WhenCreated -ge (Get-Date).AddDays(-1)}}`".format(action_num)
        )
        action_num += 1

    if url_analysis["url"]:
        sections.append(
            "{}. **Block the malicious URL/domain:**\n"
            "   - Add `{}` to web proxy deny list\n"
            "   - Update DNS sinkhole to redirect the domain\n"
            "   - Notify email security to quarantine messages containing this URL".format(
                action_num, url_analysis["domain"] or url_analysis["url"]
            )
        )
        action_num += 1

    sections.append(
        "{}. **Preserve forensic evidence:**\n"
        "   - Take memory dumps of affected systems\n"
        "   - Export full event logs before rotation\n"
        "   - Document the incident timeline".format(action_num)
    )

    # ── Section 3: Prevention ──
    sections.append("\n### \U0001f52e 3. How to Prevent It in the Future?\n")
    sections.append("**Long-Term Prevention Roadmap:**\n")

    prevention = [
        (
            "Enforce Multi-Factor Authentication (MFA)",
            "Deploy MFA across all user accounts, especially privileged/admin accounts. "
            "This eliminates the effectiveness of brute-force and credential stuffing attacks."
        ),
        (
            "Implement Network Segmentation",
            "Isolate critical assets (domain controllers, databases) into dedicated VLANs. "
            "Apply micro-segmentation with zero-trust network access (ZTNA) policies."
        ),
        (
            "Deploy Advanced Threat Detection",
            "Implement behavioural analytics (UEBA) to detect anomalous login patterns, "
            "impossible travel, and automated attack tools. Integrate SIEM with SOAR for "
            "automated response playbooks."
        ),
        (
            "Harden Authentication Infrastructure",
            "Enforce strong password policies (14+ characters, complexity rules). "
            "Implement account lockout after repeated failures. Deploy Privileged Access "
            "Management (PAM) for admin accounts."
        ),
        (
            "Security Awareness Training",
            "Conduct monthly phishing simulation exercises. Train employees to recognise "
            "social engineering tactics. Establish a clear reporting procedure for "
            "suspicious URLs and emails."
        ),
        (
            "Continuous Vulnerability Management",
            "Schedule weekly vulnerability scans. Patch critical CVEs within 48 hours. "
            "Maintain a software inventory and baseline configuration. Subscribe to "
            "threat intelligence feeds for proactive defence."
        ),
    ]

    for i, (title, detail) in enumerate(prevention, 1):
        sections.append("{}. **{}**\n   {}\n".format(i, title, detail))

    return "\n".join(sections)


# ======================================================================
#  FORMAT HELPERS
# ======================================================================

def _format_context_for_agents(input_data, intel_data):
    # type: (Dict[str, Any], Dict[str, Any]) -> str
    """
    Serialise the input data into a text block that can be consumed
    by CrewAI agents as task context.
    """
    lines = ["## Security Event Data\n"]

    # URL analysis data
    if input_data.get("url"):
        lines.append("### URL Analysis (Module 1)")
        lines.append("- URL: {}".format(input_data.get("url", "")))
        lines.append("- Domain: {}".format(input_data.get("domain", "")))
        lines.append("- Risk Score: {}".format(input_data.get("risk_score", 0)))
        indicators = input_data.get("indicators", {})
        if indicators:
            lines.append("- Indicators: {}".format(indicators))
        lines.append("")

    # Log entries
    entries = input_data.get("parsed_entries", [])
    if entries:
        lines.append("### Parsed Log Entries (Module 2)")
        lines.append("Total entries: {}".format(len(entries)))
        for entry in entries[:30]:  # Limit to first 30 for context window
            if isinstance(entry, dict):
                lines.append("  - [{}] src={} dst={} status={} event_id={}".format(
                    entry.get("timestamp", "?"),
                    entry.get("source_ip", "-"),
                    entry.get("destination_ip", "-"),
                    entry.get("status_code", "-"),
                    entry.get("event_id", "-"),
                ))
            else:
                lines.append("  - [{}] src={} dst={} status={} event_id={}".format(
                    getattr(entry, "timestamp", "?"),
                    getattr(entry, "source_ip", "-"),
                    getattr(entry, "destination_ip", "-"),
                    getattr(entry, "status_code", "-"),
                    getattr(entry, "event_id", "-"),
                ))
        lines.append("")

    # Threat intelligence
    if intel_data:
        lines.append("### Threat Intelligence (Module 3)")
        lines.append("- Verdict: {}".format(intel_data.get("aggregate_verdict", "unknown")))
        lines.append("- Data source: {}".format(intel_data.get("data_source", "unknown")))
        sources = intel_data.get("sources", [])
        if isinstance(intel_data.get("result"), dict):
            sources = intel_data["result"].get("sources", sources)
        for src in sources:
            lines.append("- Provider {}: {}".format(
                src.get("provider", "?"), src
            ))
        lines.append("")

    return "\n".join(lines)


# ======================================================================
#  PUBLIC API
# ======================================================================

def run_autonomous_soc(input_data, intel_data=None):
    # type: (Dict[str, Any], Optional[Dict[str, Any]]) -> Dict[str, Any]
    """
    Run the autonomous SOC analyst pipeline.

    This is the main entry point called by the FastAPI endpoint.

    Parameters
    ----------
    input_data : dict
        Combined data from Module 1 (URL analysis) and/or Module 2
        (parsed log entries). Expected keys:
            - url, domain, risk_score, indicators (from Module 1)
            - parsed_entries, filename, total_lines (from Module 2)

    intel_data : dict, optional
        Threat intelligence enrichment from Module 3. Expected keys:
            - aggregate_verdict, data_source, sources/result

    Returns
    -------
    dict
        {
            "report": str,         # Full markdown report
            "engine": str,         # "crewai" or "rule_based_fallback"
            "severity": str,       # Assessed severity level
            "execution_time_s": float,
        }
    """
    if intel_data is None:
        intel_data = {}

    start_time = time.time()
    logger.info("Starting autonomous SOC analysis (engine=%s)",
                "crewai" if CREWAI_AVAILABLE else "rule_based_fallback")

    try:
        if CREWAI_AVAILABLE:
            report = _build_crewai_pipeline(input_data, intel_data)
            engine = "crewai"
        else:
            report = _build_fallback_report(input_data, intel_data)
            engine = "rule_based_fallback"
    except Exception as exc:
        logger.exception("CrewAI pipeline failed — falling back to rule-based engine.")
        report = _build_fallback_report(input_data, intel_data)
        engine = "rule_based_fallback (crewai_error)"

    elapsed = round(time.time() - start_time, 3)
    logger.info("SOC analysis complete in %.3fs (engine=%s)", elapsed, engine)

    # Extract severity from the report
    severity = "UNKNOWN"
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if level in report:
            severity = level
            break

    return {
        "report": report,
        "engine": engine,
        "severity": severity,
        "execution_time_s": elapsed,
    }
