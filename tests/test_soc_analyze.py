"""Smoke test for Module 4: SOC Analysis endpoint."""
import json
import urllib.request
import urllib.error
import sys


def post_json(url, payload):
    """POST a JSON payload and return (status_code, parsed_body)."""
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
    )
    try:
        resp = urllib.request.urlopen(req)
        return resp.getcode(), json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


BASE = "http://127.0.0.1:8000"
passed = 0
failed = 0

print("=" * 60)
print("TEST 1: POST /api/soc-analyze (Rule-based Fallback)")
print("=" * 60)

# Provide some fake data matching Module 1 & 2 outputs
payload = {
    "input_data": {
        "url": "https://evil.xyz",
        "domain": "evil.xyz",
        "risk_score": 0.8,
        "indicators": {
            "has_suspicious_tld": True
        },
        "parsed_entries": [
            {"source_ip": "1.2.3.4", "status_code": "403"},
            {"source_ip": "1.2.3.4", "status_code": "403"},
            {"source_ip": "1.2.3.4", "status_code": "403"},
            {"source_ip": "5.6.7.8", "event_id": "4625"},
            {"source_ip": "5.6.7.8", "event_id": "4625"},
            {"source_ip": "5.6.7.8", "event_id": "4625"},
            {"source_ip": "5.6.7.8", "event_id": "4720"}
        ]
    },
    "intel_data": {
        "aggregate_verdict": "malicious",
        "data_source": "mock",
        "sources": [
            {"provider": "mock", "abuse_confidence_score": 90, "threat_categories": ["brute-force"]}
        ]
    }
}

status, body = post_json(BASE + "/api/soc-analyze", payload)
print("Status:", status)
if status != 200:
    print("Error:", body)
    sys.exit(1)

print("Engine:", body.get("engine"))
print("Severity:", body.get("severity"))
print("Report Preview:\n")
try:
    print(body.get("report", "")[:1000])
except UnicodeEncodeError:
    print(body.get("report", "")[:1000].encode('ascii', 'ignore').decode('ascii'))
print("\n... (truncated)\n")

assert status == 200, "Expected 200, got {}".format(status)
assert "rule_based_fallback" in body["engine"]
assert body["severity"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
assert "Incident Summary" in body["report"]
assert "Why & How" in body["report"]
assert "How to Stop and Contain It" in body["report"]
assert "How to Prevent It" in body["report"]

print("\n>> PASS\n")
passed += 1

print("=" * 60)
print("RESULTS: {}/1 passed".format(passed))
print("=" * 60)
