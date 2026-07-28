"""Smoke tests for Module 3: Threat Intelligence endpoints."""
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


# ------------------------------------------------------------------
# Test 1: URL Reputation (mock fallback — no API keys set)
# ------------------------------------------------------------------
print("=" * 60)
print("TEST 1: POST /api/threat-intel/url (mock fallback)")
print("=" * 60)
status, body = post_json(
    BASE + "/api/threat-intel/url",
    {"url": "https://evil-phishing.xyz/steal-creds"},
)
print("Status:", status)
print("Verdict:", body.get("aggregate_verdict"))
print("Data source:", body.get("data_source"))
print("Sources:", len(body.get("result", {}).get("sources", [])))
print(json.dumps(body, indent=2)[:800], "...")

assert status == 200, "Expected 200, got {}".format(status)
assert body["query_type"] == "url"
assert body["data_source"] == "mock"
assert body["aggregate_verdict"] in ("malicious", "clean")
assert len(body["result"]["sources"]) >= 1
print("\n>> PASS\n")
passed += 1


# ------------------------------------------------------------------
# Test 2: IP Reputation — clean IP (mock fallback)
# ------------------------------------------------------------------
print("=" * 60)
print("TEST 2: POST /api/threat-intel/ip (mock fallback)")
print("=" * 60)
status, body = post_json(
    BASE + "/api/threat-intel/ip",
    {"ip": "203.0.113.50"},
)
print("Status:", status)
print("Verdict:", body.get("aggregate_verdict"))
print("Data source:", body.get("data_source"))
print("Is known botnet:", body.get("result", {}).get("is_known_botnet"))
print(json.dumps(body, indent=2)[:800], "...")

assert status == 200, "Expected 200, got {}".format(status)
assert body["query_type"] == "ip"
assert body["aggregate_verdict"] in ("malicious", "clean")
print("\n>> PASS\n")
passed += 1


# ------------------------------------------------------------------
# Test 3: IP Reputation — known botnet CIDR match
# ------------------------------------------------------------------
print("=" * 60)
print("TEST 3: POST /api/threat-intel/ip (botnet CIDR match)")
print("=" * 60)
status, body = post_json(
    BASE + "/api/threat-intel/ip",
    {"ip": "185.215.113.42"},  # Falls within TrickBot C2 CIDR
)
print("Status:", status)
print("Verdict:", body.get("aggregate_verdict"))
print("Is known botnet:", body.get("result", {}).get("is_known_botnet"))

# Find the local_botnet_db source
botnet_source = None
for src in body.get("result", {}).get("sources", []):
    if src.get("provider") == "local_botnet_db":
        botnet_source = src
        break

print("Botnet match:", botnet_source)

assert status == 200, "Expected 200, got {}".format(status)
assert body["result"]["is_known_botnet"] is True, "Expected botnet match!"
assert botnet_source is not None
assert "TrickBot" in str(botnet_source.get("matched_networks", []))
print("\n>> PASS\n")
passed += 1


# ------------------------------------------------------------------
# Test 4: Invalid IP validation
# ------------------------------------------------------------------
print("=" * 60)
print("TEST 4: POST /api/threat-intel/ip (invalid IP -> 422)")
print("=" * 60)
status, body = post_json(
    BASE + "/api/threat-intel/ip",
    {"ip": "not-an-ip"},
)
print("Status:", status)
print("Detail:", body.get("detail"))

assert status == 422, "Expected 422, got {}".format(status)
print("\n>> PASS\n")
passed += 1


# ------------------------------------------------------------------
# Test 5: Deterministic mock — same URL always returns same result
# ------------------------------------------------------------------
print("=" * 60)
print("TEST 5: Mock determinism (same URL -> same result)")
print("=" * 60)
_, body1 = post_json(BASE + "/api/threat-intel/url", {"url": "https://test.xyz"})
_, body2 = post_json(BASE + "/api/threat-intel/url", {"url": "https://test.xyz"})
# Compare the sources (excluding timestamp)
src1 = body1["result"]["sources"][0]
src2 = body2["result"]["sources"][0]
assert src1.get("malicious_count") == src2.get("malicious_count"), "Mock data not deterministic!"
assert src1.get("threat_tags") == src2.get("threat_tags"), "Mock data not deterministic!"
print("Both calls returned identical mock data.")
print("\n>> PASS\n")
passed += 1


# ------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------
print("=" * 60)
total = passed + failed
print("RESULTS: {}/{} passed, {} failed".format(passed, total, failed))
print("=" * 60)

if failed:
    sys.exit(1)
