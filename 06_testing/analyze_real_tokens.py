"""
Analyze the real Twitch Kasada tokens vs our solver output.

Public archive: login credentials and captured authentication headers were
replaced with placeholders. Historical comparisons require private fixtures.
"""

import json
import base64
import hashlib
import hmac as hmac_lib

# Real tokens from HAR
REAL_CD = {"workTime":1783001197516,"id":"8fe05a7065dedaa8c7e5a3b05b0a41cb","answers":[11,1],"duration":101.7,"d":1233,"st":1783001182942,"rst":1783001184175}
REAL_CT = "REDACTED_CT_TOKEN"
REAL_H = "REDACTED_H_TOKEN"
REAL_BODY = '{"username":"example_user","password":"example_password","undelete_user":false,"client_id":"kimne78kx3ncx6brgo4mv6wki5h1ko"}'

print("=" * 80)
print("REAL CD TOKEN ANALYSIS")
print("=" * 80)
print()
print(f"Real CD: {json.dumps(REAL_CD)}")
print()
print(f"  workTime: {REAL_CD['workTime']}")
print(f"    → This is {REAL_CD['workTime']} ms = Unix timestamp in ms!")
print(f"    → As date: {REAL_CD['workTime'] / 1000:.0f} unix seconds")
print()
print(f"  id: {REAL_CD['id']}")
print(f"    → 32 hex chars = 16 bytes random ID")
print()
print(f"  answers: {REAL_CD['answers']}")
print(f"    → 2 answers (matches xqn=2 rounds)")
print(f"    → Values are [11, 1] - these are timing values per answer (ms)")
print()
print(f"  duration: {REAL_CD['duration']}")
print(f"    → 101.7 ms total mining duration")
print()
print(f"  d: {REAL_CD['d']}")
print(f"    → 1233 - This is NOT the difficulty (10)!")
print(f"    → This is likely the total number of attempts/iterations!")
print()
print(f"  st: {REAL_CD['st']}")
print(f"    → Start timestamp: {REAL_CD['st']} ms")
print()
print(f"  rst: {REAL_CD['rst']}")
print(f"    → Round start timestamp: {REAL_CD['rst']} ms")
print(f"    → Delta from st: {REAL_CD['rst'] - REAL_CD['st']} ms")
print()

# Key insight: workTime is not duration, it's a timestamp!
# workTime = 1783001197516 (same order as st = 1783001182942)
# workTime - st = 1783001197516 - 1783001182942 = 14574 ms
print(f"  workTime - st = {REAL_CD['workTime'] - REAL_CD['st']} ms")
print(f"  workTime - rst = {REAL_CD['workTime'] - REAL_CD['rst']} ms")
print()

print("=" * 80)
print("REAL H TOKEN (HMAC) ANALYSIS")
print("=" * 80)
print()
print(f"Value: {REAL_H}")
print(f"Length: {len(REAL_H)} chars")
print()

# Try different base64 padding
for padding in ['', '=', '==']:
    try:
        decoded = base64.b64decode(REAL_H + padding)
        print(f"  base64({REAL_H}{padding}): {len(decoded)} bytes → {decoded.hex()}")
    except:
        pass

# Try base64url
try:
    decoded = base64.urlsafe_b64decode(REAL_H + "==")
    print(f"  base64url({REAL_H}==): {len(decoded)} bytes → {decoded.hex()}")
except:
    pass

print()
print(f"  If this is HMAC-SHA1: expect 20 bytes (28 chars in base64)")
print(f"  If this is HMAC-SHA256: expect 32 bytes (44 chars in base64)")
print(f"  Actual: 30 chars → with padding '==' would be 32 chars")
print()

# 30 chars is unusual. Let me check if there's a prefix
# "REDACTED_H_TOKEN"
# If we strip "0" prefix: "1F47DxTPakzMm2tqdC3JSScDjKyQ=" = 29 chars
# Actually "REDACTED_H_TOKEN" is 30 chars
# Base64: 28 chars = 21 bytes (not standard), 32 chars = 24 bytes, 24 chars = 18 bytes
# 30 chars... let's try adding padding
print("  Trying to decode with various approaches:")
test_vals = [
    REAL_H,
    REAL_H + "=",
    REAL_H + "==",
]
for tv in test_vals:
    try:
        d = base64.b64decode(tv)
        print(f"    '{tv}' → {len(d)} bytes: {d.hex()}")
    except Exception as ex:
        print(f"    '{tv}' → ERROR: {ex}")

print()
# The value "REDACTED_H_TOKEN" has trailing = so it IS padded already
# base64 with trailing = means the output is exactly right
# "REDACTED_H_TOKEN" = 30 chars with 1 padding
# Actual data: (30-1)*6/8 = ~21.75... hmm
# Actually for base64: 30 chars including padding of '=' means 29 meaningful chars
# Wait: "REDACTED_H_TOKEN" is 30 chars, with 1 '=' padding
# That means 29 base64 chars + 1 padding = encodes (29*6-padding)/8 bits
# Groups of 4: "01F4" "7DxT" "Pakz" "Mm2t" "qdC3" "JSSc" "DjKy" "Q="
# That's 7 full groups + "Q=" = 7*3 + 1 = 22 bytes!
# Wait: "01F4|7DxT|Pakz|Mm2t|qdC3|JSSc|DjKy|Q===" no...
# Let me just count properly:
# base64 groups of 4 chars → 3 bytes each
# "REDACTED_H_TOKEN" has 30 chars / 4 = 7.5 groups
# 7 full groups (28 chars) = 21 bytes + "Q=" (2 chars) = 1 more byte
# Total: 22 bytes

# HMAC-SHA1 produces 20 bytes (160 bits) → base64 = 28 chars (with ==)
# Our 22 bytes is unusual... unless there's a version prefix!

print()
print("IMPORTANT INSIGHT:")
print("  The HMAC value is 22 bytes when decoded.")
print("  HMAC-SHA1 = 20 bytes → TOO SHORT")
print("  But 22 = 2 byte prefix + 20 byte HMAC-SHA1!")
print("  OR: the HMAC is truncated SHA-256 (first 22 bytes)")
print()

# Let's try decoding
try:
    h_bytes = base64.b64decode(REAL_H)
    print(f"  Decoded: {h_bytes.hex()}")
    print(f"  Length: {len(h_bytes)} bytes")
    print(f"  First 2 bytes: {h_bytes[:2].hex()} (possible version/type prefix)")
    print(f"  Remaining {len(h_bytes)-2} bytes: {h_bytes[2:].hex()} (HMAC value)")
except Exception as e:
    # Maybe URL-safe base64
    try:
        h_bytes = base64.urlsafe_b64decode(REAL_H + "=")
        print(f"  URL-safe decoded: {h_bytes.hex()}")
        print(f"  Length: {len(h_bytes)} bytes")
    except:
        print(f"  Cannot decode: {e}")

print()
print("=" * 80)
print("COMPARING OUR SOLVER VS REAL")
print("=" * 80)
print()
print("Our CD format:")
print('  {"workTime":75,"id":"69cab4038ee89372","answers":[0],"d":10,"st":1783004876847,"rst":...}')
print()
print("Real CD format:")
print(f'  {json.dumps(REAL_CD)}')
print()
print("DIFFERENCES:")
print("  1. workTime: We use duration in ms, real uses a TIMESTAMP (ms since epoch)")
print("  2. id: We generate 16 hex chars, real uses 32 hex chars (matches)")
print("  3. answers: Real has [11, 1] - timing per attempt round")
print("  4. duration: Real has 101.7 - we don't include this field!")
print("  5. d: Real has 1233 - number of ATTEMPTS, not difficulty!")
print("     We output difficulty (10), real outputs attempt count")
print("  6. st/rst: Both are timestamps (same pattern)")
print()
print("KEY CORRECTIONS NEEDED:")
print("  - workTime should be timestamp when PoW completed (ms since epoch)")
print("  - d should be number of total nonces tried, not difficulty")
print("  - duration should be floating point total time in ms")
print("  - answers timing: [11, 1] = time per successful round in ms")
print("     (first answer took 11ms to find, second took 1ms)")

print()
print("=" * 80)
print("HMAC VERIFICATION ATTEMPT")
print("=" * 80)
print()

# Try to reproduce the HMAC with our key
ykj = bytes.fromhex("7ae9906d03439b1173e98ddb9342a718a535ab115a7f27138cd183737d7f7afe")
cd_str = json.dumps(REAL_CD, separators=(',', ':'))

# Various message formats to try
messages = [
    # Format 1: CT + CD
    REAL_CT + cd_str,
    # Format 2: CT + CD + method + path
    REAL_CT + cd_str + "POST" + "/protected_login",
    # Format 3: method + path + CT + CD
    "POST" + "/protected_login" + REAL_CT + cd_str,
    # Format 4: CT + CD + body
    REAL_CT + cd_str + REAL_BODY,
    # Format 5: Just CD
    cd_str,
    # Format 6: CT + CD + method + url + body
    REAL_CT + cd_str + "POST" + "https://passport.twitch.tv/protected_login" + REAL_BODY,
]

print(f"Target HMAC: {REAL_H}")
try:
    target_bytes = base64.b64decode(REAL_H)
    print(f"Target hex: {target_bytes.hex()}")
except:
    pass

print()
for i, msg in enumerate(messages):
    # HMAC-SHA256
    h = hmac_lib.new(ykj, msg.encode('utf-8'), hashlib.sha256).digest()
    b64_full = base64.b64encode(h).decode()
    b64_trunc22 = base64.b64encode(h[:22]).decode()
    b64_trunc20 = base64.b64encode(h[:20]).decode()

    # HMAC-SHA1
    h1 = hmac_lib.new(ykj, msg.encode('utf-8'), hashlib.sha1).digest()
    b64_sha1 = base64.b64encode(h1).decode()

    match = ""
    if b64_full == REAL_H: match = " <<< MATCH (SHA256)!"
    elif b64_trunc22 == REAL_H: match = " <<< MATCH (SHA256 trunc 22)!"
    elif b64_trunc20 == REAL_H: match = " <<< MATCH (SHA256 trunc 20)!"
    elif b64_sha1 == REAL_H: match = " <<< MATCH (SHA1)!"

    print(f"  Format {i+1}:")
    print(f"    SHA256:      {b64_full[:30]}...{match}")
    print(f"    SHA256[22]:  {b64_trunc22}{match}")
    print(f"    SHA1:        {b64_sha1}{match}")
    if match:
        print(f"    MESSAGE: {msg[:100]}...")
    print()
