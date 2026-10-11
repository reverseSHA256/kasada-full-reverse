"""
Extract full details from the HAR - especially the real x-kpsdk tokens.
"""

import json
import base64

with open(r"E:\kasada fully reverse\www.twitch.tv.har", "r", encoding="utf-8") as f:
    har = json.load(f)

entries = har["log"]["entries"]

# Find entry 29 (the one with kpsdk headers)
entry = entries[29]
url = entry["request"]["url"]
method = entry["request"]["method"]
status = entry["response"]["status"]

print(f"Request: {method} {url}")
print(f"Status: {status}")
print()

# Extract all request headers
print("=" * 80)
print("ALL REQUEST HEADERS:")
print("=" * 80)
for h in entry["request"]["headers"]:
    val = h["value"]
    if len(val) > 120:
        print(f"  {h['name']}: {val[:117]}...")
    else:
        print(f"  {h['name']}: {val}")

# Extract kpsdk headers specifically
print()
print("=" * 80)
print("KPSDK HEADERS (FULL):")
print("=" * 80)
kpsdk_headers = {}
for h in entry["request"]["headers"]:
    if "x-kpsdk" in h["name"].lower():
        kpsdk_headers[h["name"]] = h["value"]
        print(f"\n{h['name']}:")
        print(f"  {h['value']}")

# Parse CD token
print()
print("=" * 80)
print("CD TOKEN PARSED:")
print("=" * 80)
cd_raw = kpsdk_headers.get("x-kpsdk-cd", "")
try:
    cd = json.loads(cd_raw)
    print(json.dumps(cd, indent=2))
except:
    print(f"Raw: {cd_raw[:500]}")

# Analyze CT token
print()
print("=" * 80)
print("CT TOKEN ANALYSIS:")
print("=" * 80)
ct = kpsdk_headers.get("x-kpsdk-ct", "")
print(f"Length: {len(ct)} chars")
print(f"First 100: {ct[:100]}")
print(f"Last 50: {ct[-50:]}")

# Try base64 decode
try:
    ct_bytes = base64.b64decode(ct)
    print(f"Base64 decoded: {len(ct_bytes)} bytes")
    print(f"First 32 bytes hex: {ct_bytes[:32].hex()}")
except:
    print("Not valid base64")

# Analyze H token (HMAC)
print()
print("=" * 80)
print("H TOKEN (HMAC) ANALYSIS:")
print("=" * 80)
h_val = kpsdk_headers.get("x-kpsdk-h", "")
print(f"Value: {h_val}")
print(f"Length: {len(h_val)} chars")
try:
    h_bytes = base64.b64decode(h_val)
    print(f"Decoded: {len(h_bytes)} bytes")
    print(f"Hex: {h_bytes.hex()}")
except:
    print("Not valid base64")

# Request body
print()
print("=" * 80)
print("REQUEST BODY:")
print("=" * 80)
if entry["request"].get("postData"):
    body = entry["request"]["postData"].get("text", "")
    print(f"Content-Type: {entry['request']['postData'].get('mimeType', 'unknown')}")
    print(f"Body ({len(body)} chars): {body[:500]}")
else:
    print("No body")

# Response
print()
print("=" * 80)
print("RESPONSE:")
print("=" * 80)
print(f"Status: {entry['response']['status']} {entry['response']['statusText']}")
resp_content = entry["response"]["content"]
if resp_content.get("text"):
    print(f"Body ({len(resp_content['text'])} chars): {resp_content['text'][:500]}")

# Now look at ALL entries for the full flow
print()
print("=" * 80)
print("FULL REQUEST TIMELINE:")
print("=" * 80)
for i, e in enumerate(entries):
    url = e["request"]["url"]
    method = e["request"]["method"]
    status = e["response"]["status"]
    has_kpsdk = any("x-kpsdk" in h["name"].lower() for h in e["request"]["headers"])
    marker = " <<<" if has_kpsdk else ""
    # Filter for twitch passport/login related
    if "passport" in url or "kpsdk" in url.lower() or "tl" in url.split("/")[-1:] or "149e9513" in url:
        print(f"  [{i:2d}] {method:4s} {status} {url[:100]}{marker}")
    elif "integrity" in url.lower() or "gql" in url.lower():
        print(f"  [{i:2d}] {method:4s} {status} {url[:100]}{marker}")
