"""
Crack the HMAC format. The value "REDACTED_H_TOKEN" is unusual.
30 chars is not valid base64 length. Possibilities:
1. Custom base64 variant
2. The '=' is part of the value, not padding
3. Hex encoding of some sort
4. Multiple parts (prefix + HMAC)

Public archive: login credentials and captured authentication headers were
replaced with placeholders. Historical comparisons require private fixtures.
"""

import base64
import hashlib
import hmac as hmac_lib

REAL_H = "REDACTED_H_TOKEN"
REAL_CT = "REDACTED_CT_TOKEN"
REAL_CD_STR = '{"workTime":1783001197516,"id":"8fe05a7065dedaa8c7e5a3b05b0a41cb","answers":[11,1],"duration":101.7,"d":1233,"st":1783001182942,"rst":1783001184175}'
REAL_BODY = '{"username":"example_user","password":"example_password","undelete_user":false,"client_id":"kimne78kx3ncx6brgo4mv6wki5h1ko"}'

# The HMAC from the KASADA_COMPLETE_REVERSING_GUIDE:
# "HMAC-SHA1 (20 bytes, base64-encoded) binding CT + CD + request details"
# HMAC-SHA1 = 20 bytes = base64 encoded = 28 chars (with == padding)
# But "REDACTED_H_TOKEN" is 30 chars...

# WAIT - what if the '=' at the end IS base64 padding and the value is actually:
# "REDACTED_H_TOKEN" treated as 30 chars
# But standard base64: groups of 4
# 01F4 | 7DxT | Pakz | Mm2t | qdC3 | JSSc | DjKy | Q=
# That's 7 full groups + "Q=" (which is invalid - needs "Q===" or "Qx==" format)
# "Q=" as last group is only 2 chars, needs to be padded to 4: "Q===" ? No...
# Actually "Q=" could be interpreted as the last group being "Q===" truncated

# ACTUALLY: What if the base64 string doesn't include the trailing = as padding?
# What if "01F47DxTPakzMm2tqdC3JSScDjKyQ" is the actual 29-char value (without the =)?
# And the = is just the last character of the base64 encoding?
# Standard: "REDACTED_H_TOKEN" → pad it to multiple of 4?
# 30 chars... pad with "==" → "REDACTED_H_TOKEN==" (33) no...
# Actually 30 chars needs 2 more padding → "REDACTED_H_TOKEN=="  no, need to reach 32
# 30 → next multiple of 4 = 32, need 2 padding → "REDACTED_H_TOKEN=="
# But we already have one = ... so maybe just add one more?

print("Trying different interpretations of the HMAC value:")
print()

# Interpretation 1: The = is padding, string is 29 data chars + 1 pad
# This decodes to: ceil(29 * 6 / 8) = 22 bytes... but Python rejects it
# Let's force it:
import binascii

# Method: manually decode base64
B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def manual_b64_decode(s):
    """Manually decode base64, handling non-standard lengths."""
    # Remove padding
    s = s.rstrip('=')
    # Convert to bits
    bits = ''
    for c in s:
        if c in B64_CHARS:
            bits += format(B64_CHARS.index(c), '06b')
        else:
            print(f"  Invalid char: '{c}'")
            return None
    # Convert to bytes
    result = bytearray()
    for i in range(0, len(bits) - 7, 8):
        result.append(int(bits[i:i+8], 2))
    return bytes(result)

h_decoded = manual_b64_decode(REAL_H)
if h_decoded:
    print(f"1. Manual base64 decode:")
    print(f"   Input: {REAL_H}")
    print(f"   Output: {len(h_decoded)} bytes")
    print(f"   Hex: {h_decoded.hex()}")
    print(f"   Prefix: {h_decoded[:2].hex()} (possible type byte)")
    print(f"   Rest ({len(h_decoded)-1} bytes): {h_decoded[1:].hex()}")
    print()

# Interpretation 2: It's base64 but with the wrong padding
# Add proper padding
padded = REAL_H.rstrip('=')
padded += '=' * (4 - len(padded) % 4) if len(padded) % 4 else ''
try:
    d = base64.b64decode(padded)
    print(f"2. With corrected padding ({padded}):")
    print(f"   {len(d)} bytes: {d.hex()}")
except Exception as e:
    print(f"2. Corrected padding failed: {e}")
print()

# Now let's try to reproduce it
# Key insight from the guide: HMAC-SHA1 with 20 bytes
# The real value decodes to 22 bytes
# 22 bytes = possibly 2 byte prefix (version?) + 20 bytes HMAC-SHA1

# OR: it's 21 bytes (29 base64 chars without padding decode to 21.75 → 21 bytes)
# HMAC-SHA1 produces 20 bytes, +1 byte prefix = 21 bytes?

ykj = bytes.fromhex("7ae9906d03439b1173e98ddb9342a718a535ab115a7f27138cd183737d7f7afe")

# The HMAC message format - from the bytecode the key is used with sha256
# But the guide says HMAC-SHA1... Let's try both

print("=" * 80)
print("TRYING TO REPRODUCE HMAC")
print("=" * 80)
print()

# The x-kpsdk-h header might use a DIFFERENT key or format
# Let's look at the h_decoded bytes:
if h_decoded:
    print(f"Target bytes: {h_decoded.hex()}")
    print(f"Target length: {len(h_decoded)} bytes")

    # If first byte is a version/type indicator:
    first_byte = h_decoded[0]
    print(f"First byte: 0x{first_byte:02x} = {first_byte}")
    # 0xd3 doesn't look like a version byte

    # Maybe the whole thing is the HMAC value (no prefix)
    # 22 bytes could be a truncated HMAC-SHA256 (take first 22 of 32 bytes)
    # Or it's actually 21 bytes (the manual decode might have an extra byte)

print()
print("Trying various message formats with SHA1 and SHA256:")
print()

# Key could be the raw hex bytes or the UTF-8 string
keys_to_try = [
    ("hex bytes", ykj),
    ("utf8 string", b"7ae9906d03439b1173e98ddb9342a718a535ab115a7f27138cd183737d7f7afe"),
    # The rpk key
    ("rpk", b"CV7o9fRC/gx24wn2"),
    # The jpk key (base64 decoded)
    ("jpk decoded", base64.b64decode("CV7o9fRC/gx24wn2aw7QVuED7ds=")),
]

# Message candidates
method = "POST"
path = "/protected_login"
full_url = "https://passport.twitch.tv/protected_login"

messages_to_try = [
    ("CT+CD", REAL_CT + REAL_CD_STR),
    ("CD+CT", REAL_CD_STR + REAL_CT),
    ("CT+CD+body", REAL_CT + REAL_CD_STR + REAL_BODY),
    ("method+path+CT+CD", method + path + REAL_CT + REAL_CD_STR),
    ("CT+CD+method+path", REAL_CT + REAL_CD_STR + method + path),
    ("CT+CD+method+path+body", REAL_CT + REAL_CD_STR + method + path + REAL_BODY),
    ("path+method+body+CT+CD", path + method + REAL_BODY + REAL_CT + REAL_CD_STR),
    ("body", REAL_BODY),
    ("CT", REAL_CT),
    ("method+fullurl+body", method + full_url + REAL_BODY),
    ("CT+method+path+body+CD", REAL_CT + method + path + REAL_BODY + REAL_CD_STR),
]

target_hex = h_decoded.hex() if h_decoded else ""

for key_name, key in keys_to_try:
    for msg_name, msg in messages_to_try:
        # SHA1
        h1 = hmac_lib.new(key, msg.encode('utf-8'), hashlib.sha1).digest()
        # SHA256
        h256 = hmac_lib.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

        # Compare various truncations
        for digest, alg in [(h1, "SHA1"), (h256, "SHA256")]:
            # Try full, truncated to 22, 21, 20 bytes
            for trunc in [len(digest), 22, 21, 20]:
                truncated = digest[:trunc]
                # Encode as base64
                b64 = base64.b64encode(truncated).decode()
                if b64 == REAL_H:
                    print(f"  MATCH! key={key_name} msg={msg_name} alg={alg} trunc={trunc}")
                    print(f"    b64: {b64}")
                    found = True
                # Also try without padding
                b64_nopad = b64.rstrip('=')
                if b64_nopad + '=' == REAL_H:
                    print(f"  MATCH (nopad+1)! key={key_name} msg={msg_name} alg={alg} trunc={trunc}")
                    found = True

print("No exact match found with standard HMAC approaches.")
print()
print("NEXT STEPS:")
print("  - The HMAC might use a derived key (not directly ykj)")
print("  - The message format might include timestamps or other session data")
print("  - The encoding might not be standard base64")
print("  - Need to trace the exact HMAC computation in bytecode (addr 25008+)")
