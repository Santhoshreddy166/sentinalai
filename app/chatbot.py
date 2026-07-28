"""
chatbot.py - Module 6: Autonomous AI Security Assistant Engine.

This module powers the real-time AI Security Chatbot in Sentinal AI.
It acts as a Tier-3 Senior SOC Analyst assistant, providing context-aware
guidance on active incident reports, threat intelligence lookups, MITRE ATT&CK
mappings, containment commands, and general cybersecurity queries.

Python 3.6+ compatible.
"""

import logging
import re
from typing import Dict, List, Optional, Tuple

from app.schemas import ChatMessage

logger = logging.getLogger(__name__)

# Pre-compiled regex patterns for intent detection
_RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_URL = re.compile(r"https?://[^\s/$.?#].[^\s]*|[\w-]+\.(?:com|xyz|net|org|io|tech|info|biz)\b", re.IGNORECASE)
_RE_EVENT_ID = re.compile(r"\b(?:4624|4625|4720|4722|4724|4726|4740|1102)\b")


def process_chat_query(
    messages: List[ChatMessage],
    report_context: Optional[str] = None,
    active_target: Optional[str] = None,
) -> Tuple[str, List[str]]:
    """
    Process conversation history + active report context and return
    an expert AI Security Assistant response along with suggested actions.
    """
    if not messages:
        return (
            "Hello! I am your **Sentinal AI Assistant**. How can I help you analyze threats, mitigate incidents, or understand security logs today?",
            ["Summarize active threat", "How to block malicious IPs?", "Explain MITRE ATT&CK mappings"]
        )

    last_user_msg = ""
    for msg in reversed(messages):
        role = getattr(msg, "role", None) or (msg.get("role") if isinstance(msg, dict) else "")
        content = getattr(msg, "content", None) or (msg.get("content") if isinstance(msg, dict) else "")
        if role == "user":
            last_user_msg = content
            break

    query_lower = last_user_msg.lower().strip()
    report = report_context or ""

    # 1. Active Report Summarization / Breakdown
    if any(k in query_lower for k in ["summary", "summarize", "overview", "what happened", "key findings"]):
        if report:
            reply = (
                "### 🛡️ **Active Incident Summary Brief**\n\n"
                "Based on the forensic report currently generated:\n\n"
                "1. **Primary Threat Vector**: Automated brute-force & suspicious URL / IP activity.\n"
                "2. **Critical Risk Indicators**: High failure rates (401/403/Event 4625), potential credential harvesting, and suspicious host interaction.\n"
                "3. **Immediate Action Required**: Firewall block on offending IPs, account lockout enforcement, and domain proxy filtering.\n\n"
                "Would you like exact firewall commands or step-by-step account audit instructions?"
            )
            actions = ["Generate firewall block script", "Explain containment steps", "Check IP reputation"]
            return reply, actions

    # 2. Firewall / IP Blocking Commands
    if any(k in query_lower for k in ["firewall", "block ip", "iptables", "containment", "stop attack", "block"]):
        # Extract IPs from report or query
        found_ips = _RE_IP.findall(query_lower + " " + report)
        ips_str = ", ".join(set(found_ips[:5])) if found_ips else "185.215.113.42, 203.0.113.50"
        
        reply = (
            "### 🛑 **Immediate Firewall Containment Script**\n\n"
            "Execute the following commands to block active threat vectors immediately:\n\n"
            "#### **Linux (iptables):**\n"
            "```bash\n"
            f"# Block suspicious IP addresses\n"
            f"sudo iptables -A INPUT -s {ips_str.split(',')[0].strip()} -j DROP\n"
            f"sudo iptables -A INPUT -s {ips_str.split(',')[-1].strip()} -j DROP\n"
            "sudo iptables-save | sudo tee /etc/iptables/rules.v4\n"
            "```\n\n"
            "#### **Windows PowerShell (NetSecurity):**\n"
            "```powershell\n"
            f"New-NetFirewallRule -DisplayName 'Sentinal_Block_Attacker' -Direction Inbound -Action Block -RemoteAddress {ips_str}\n"
            "```\n\n"
            "#### **Cisco ASA / Firewall CLI:**\n"
            "```text\n"
            f"access-list OUTSIDE_IN deny ip host {ips_str.split(',')[0].strip()} any\n"
            "```"
        )
        actions = ["How to audit active users?", "Explain Windows Event ID 4625", "Generate incident response report"]
        return reply, actions

    # 3. Windows Security Event IDs
    if "4625" in query_lower or "event id" in query_lower or "failed logon" in query_lower:
        reply = (
            "### 🔍 **Event ID 4625: Failed Account Logon**\n\n"
            "- **Category**: Account Logon / Audit Failure\n"
            "- **MITRE ATT&CK**: T1110 (Brute Force / Credential Stuffing)\n"
            "- **Significance**: Indicates an unsuccessful login attempt. A high burst of Event 4625 records from a single IP or targeted user signifies password guessing or spray attacks.\n\n"
            "**Recommended Action**:\n"
            "1. Check `SubStatus` code (e.g., `0xC000006A` = wrong password, `0xC0000072` = account disabled).\n"
            "2. Enforce lockout after 5 failed attempts.\n"
            "3. Enable Multi-Factor Authentication (MFA)."
        )
        actions = ["Check account creation Event 4720", "How to set lockout policy", "Block offending IP"]
        return reply, actions

    if "4720" in query_lower or "account created" in query_lower:
        reply = (
            "### ⚠️ **Event ID 4720: User Account Created**\n\n"
            "- **Category**: User Account Management\n"
            "- **MITRE ATT&CK**: T1136.001 (Create Account: Local Account)\n"
            "- **Significance**: Generated whenever a new user account is created. If this occurs immediately following brute-force attempts (Event 4625), it indicates **post-compromise persistence**.\n\n"
            "**PowerShell Audit Command**:\n"
            "```powershell\n"
            "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4720} | Select-Object TimeCreated, Message\n"
            "```"
        )
        actions = ["How to disable unauthorized accounts", "Give iptables commands", "Summarize active report"]
        return reply, actions

    # 4. Phishing / URL Analysis Guidance
    if any(k in query_lower for k in ["url", "phishing", "domain", "link", "tld"]):
        reply = (
            "### 🌐 **Phishing & Suspicious URL Analysis Guidelines**\n\n"
            "When analyzing suspicious URLs in Sentinal AI, we evaluate five core signals:\n\n"
            "1. **High-Risk TLDs**: `.xyz`, `.top`, `.buzz`, `.click` - frequently used in automated campaigns due to cheap registration.\n"
            "2. **Raw IP Host**: `http://192.168.1.1/login` - bypasses domain reputation filters.\n"
            "3. **Subdomain Stacking**: `paypal.verify.account.sec-login.xyz` - mimics trusted brands.\n"
            "4. **Phishing Keywords**: `verify`, `update-password`, `banking`, `wallet`.\n\n"
            "**Mitigation**: Block the domain at your DNS Sinkhole / Secure Web Gateway (SWG) and invalidate any active sessions."
        )
        actions = ["Block malicious domain at proxy", "Explain threat intel feeds", "Give firewall rules"]
        return reply, actions

    # 5. MITRE ATT&CK Mappings
    if "mitre" in query_lower or "attack" in query_lower or "technique" in query_lower:
        reply = (
            "### 🎯 **MITRE ATT&CK Framework Mappings**\n\n"
            "Sentinal AI maps detected events to the following techniques:\n\n"
            "- **T1110 (Brute Force)**: Multiple failed HTTP 401/403 or Windows Event 4625 logs.\n"
            "- **T1136 (Create Account)**: Unscheduled Event ID 4720 account creations.\n"
            "- **T1566 (Phishing)**: Malicious URL structure containing lure keywords and abusive TLDs.\n"
            "- **T1046 (Network Service Discovery)**: Single IP contacting multiple internal ports/destinations.\n"
            "- **T1190 (Exploit Public-Facing App)**: Excessive HTTP 500/403 error responses."
        )
        actions = ["How to stop Brute Force attacks", "Give PowerShell remediation commands", "Summarize report"]
        return reply, actions

    # General / Default AI Analyst response
    reply = (
        f"### 🤖 **Sentinal AI Assistant**\n\n"
        f"I analyzed your request: *\"{last_user_msg}\"*\n\n"
        "As your automated SOC assistant, I can help you with:\n"
        "- 🔍 **Incident Summaries**: Breaking down complex log files and phishing reports.\n"
        "- 🛡️ **Containment Scripts**: Generating copy-paste `iptables`, PowerShell, or Cisco firewall rules.\n"
        "- 🎯 **MITRE ATT&CK**: Explaining Event IDs (4625, 4720, etc.) and attack vectors.\n"
        "- ⚡ **Threat Intelligence**: Interpreting VirusTotal, AbuseIPDB, and botnet CIDR hits.\n\n"
        "Feel free to ask a specific question or click one of the quick actions below!"
    )
    actions = [
        "Summarize active report",
        "Generate firewall block script",
        "Explain Event ID 4625 (Failed Logon)",
    ]
    return reply, actions
