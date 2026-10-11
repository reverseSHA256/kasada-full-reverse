"""Check the /mfc response in the HAR for x-kpsdk-h and x-kpsdk-fc headers."""
import json

with open('../01_source/www.twitch.tv.har', 'r', encoding='utf-8') as f:
    har = json.load(f)

entries = har['log']['entries']
print("=" * 80)
print("Looking for /mfc requests and x-kpsdk-h in responses")
print("=" * 80)

for i, e in enumerate(entries):
    url = e['request']['url']
    req_headers = {h['name'].lower(): h['value'] for h in e['request']['headers']}
    resp_headers = {h['name'].lower(): h['value'] for h in e['response']['headers']}
    
    # Check if this is a /mfc request or has kpsdk response headers
    has_kpsdk_resp = any('kpsdk' in h['name'].lower() for h in e['response']['headers'])
    has_kpsdk_req = any('kpsdk' in h['name'].lower() for h in e['request']['headers'])
    
    if '/mfc' in url or has_kpsdk_resp:
        print(f"\nEntry {i}: {e['request']['method']} {url[:100]}")
        if has_kpsdk_resp:
            print("  Response kpsdk headers:")
            for h in e['response']['headers']:
                if 'kpsdk' in h['name'].lower():
                    print(f"    {h['name']}: {h['value'][:100]}")
        if has_kpsdk_req:
            print("  Request kpsdk headers:")
            for h in e['request']['headers']:
                if 'kpsdk' in h['name'].lower():
                    print(f"    {h['name']}: {h['value'][:100]}")

print("\n" + "=" * 80)
print("Now checking: does request x-kpsdk-h match any previous response x-kpsdk-h?")
print("=" * 80)

# Collect all response x-kpsdk-h values
resp_h_values = []
req_h_values = []

for i, e in enumerate(entries):
    for h in e['response']['headers']:
        if h['name'].lower() == 'x-kpsdk-h':
            resp_h_values.append((i, h['value']))
    for h in e['request']['headers']:
        if h['name'].lower() == 'x-kpsdk-h':
            req_h_values.append((i, h['value']))

print(f"\nResponse x-kpsdk-h values ({len(resp_h_values)}):")
for idx, val in resp_h_values:
    print(f"  Entry {idx}: {val}")

print(f"\nRequest x-kpsdk-h values ({len(req_h_values)}):")
for idx, val in req_h_values:
    print(f"  Entry {idx}: {val}")

# Check if any request value matches a previous response value
for req_idx, req_val in req_h_values:
    for resp_idx, resp_val in resp_h_values:
        if resp_idx < req_idx and resp_val == req_val:
            print(f"\n  MATCH! Request entry {req_idx} uses response from entry {resp_idx}")
            print(f"    Value: {req_val}")
