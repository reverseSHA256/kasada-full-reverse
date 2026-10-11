"""
Parse the Twitch HAR file to extract:
1. The /tl request/response (CT token, dynamicConfig)
2. The actual x-kpsdk-cd, x-kpsdk-h, x-kpsdk-ct headers used
3. The p.js script URL and content
4. Any /149e9513... endpoint requests
"""

import json

with open(r"E:\kasada fully reverse\www.twitch.tv.har", "r", encoding="utf-8") as f:
    har = json.load(f)

entries = har["log"]["entries"]
print(f"Total HAR entries: {len(entries)}")
print()

# Categorize entries
kasada_entries = []
tl_entries = []
pjs_entries = []
kpsdk_header_entries = []

for i, entry in enumerate(entries):
    url = entry["request"]["url"]
    req_headers = {h["name"].lower(): h["value"] for h in entry["request"]["headers"]}
    
    # /tl requests
    if "/tl" in url and "kpsdk" in url.lower() or "/tl" in url:
        tl_entries.append((i, entry))
    
    # p.js script
    if "p.js" in url or "/fp/" in url:
        pjs_entries.append((i, entry))
    
    # Requests with x-kpsdk headers
    if any("x-kpsdk" in h["name"].lower() for h in entry["request"]["headers"]):
        kpsdk_header_entries.append((i, entry))
    
    # Any kasada-related URL
    if "kpsdk" in url.lower() or "149e9513" in url or "2d206a39" in url:
        kasada_entries.append((i, entry))

print(f"Kasada-related entries: {len(kasada_entries)}")
print(f"/tl entries: {len(tl_entries)}")
print(f"p.js entries: {len(pjs_entries)}")
print(f"Entries with x-kpsdk headers: {len(kpsdk_header_entries)}")
print()

# Print Kasada URLs
print("=" * 80)
print("KASADA-RELATED URLs:")
print("=" * 80)
for i, entry in kasada_entries:
    url = entry["request"]["url"]
    method = entry["request"]["method"]
    status = entry["response"]["status"]
    print(f"  [{i}] {method} {status} {url[:120]}")
print()

# Print /tl entries details
print("=" * 80)
print("/TL ENTRIES:")
print("=" * 80)
for i, entry in tl_entries:
    url = entry["request"]["url"]
    method = entry["request"]["method"]
    status = entry["response"]["status"]
    print(f"\n  [{i}] {method} {status} {url[:120]}")
    
    # Response headers
    resp_headers = {h["name"].lower(): h["value"] for h in entry["response"]["headers"]}
    for k, v in resp_headers.items():
        if "kpsdk" in k.lower() or "ct" in k.lower():
            print(f"    Resp hdr: {k}: {v[:100]}")
    
    # Response body
    resp_content = entry["response"]["content"]
    if resp_content.get("text"):
        body = resp_content["text"]
        if len(body) > 200:
            print(f"    Resp body: {body[:200]}... ({len(body)} chars)")
        else:
            print(f"    Resp body: {body}")
    
    # Request headers
    req_headers = {h["name"].lower(): h["value"] for h in entry["request"]["headers"]}
    for k, v in req_headers.items():
        if "kpsdk" in k.lower():
            print(f"    Req hdr: {k}: {v[:100]}")

# Print entries with x-kpsdk headers
print()
print("=" * 80)
print("REQUESTS WITH x-kpsdk HEADERS:")
print("=" * 80)
for i, entry in kpsdk_header_entries[:10]:
    url = entry["request"]["url"]
    method = entry["request"]["method"]
    status = entry["response"]["status"]
    print(f"\n  [{i}] {method} {status} {url[:100]}")
    
    req_headers = entry["request"]["headers"]
    for h in req_headers:
        if "x-kpsdk" in h["name"].lower():
            val = h["value"]
            if len(val) > 80:
                print(f"    {h['name']}: {val[:77]}...")
            else:
                print(f"    {h['name']}: {val}")

# Check for p.js content
print()
print("=" * 80)
print("P.JS ENTRIES:")
print("=" * 80)
for i, entry in pjs_entries:
    url = entry["request"]["url"]
    resp_content = entry["response"]["content"]
    body_size = len(resp_content.get("text", ""))
    print(f"  [{i}] {url[:100]}")
    print(f"       Body size: {body_size} chars")
