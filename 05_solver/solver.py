"""
Kasada Token Solver
====================
Accepts a target site URL + Kasada path, solves the challenge,
and returns all required headers as JSON.

Usage:
    python solver.py --site https://passport.twitch.tv --path /149e9513-01fa-4fb0-aad4-566afd725d1b/2d206a39-8ed7-437e-a3be-862e0f06eea3

    # With proxy:
    python solver.py --site https://passport.twitch.tv --path /149e9513-... --proxy http://user:pass@host:port

    # With custom Chrome version:
    python solver.py --site https://passport.twitch.tv --path /149e9513-... --chrome 136

Output (stdout JSON):
    {
      "success": true,
      "type": "kasada",
      "headers": {
        "x-kpsdk-ct": "...",
        "x-kpsdk-cd": "{...JSON-encoded proof...}",
        "x-kpsdk-v": "j-1.2.522",
        "x-kpsdk-h": "..."
      }
    }

Requirements:
    pip install wreq
"""

import asyncio
import argparse
import hashlib
import json
import time
import random
import base64
import sys
from urllib.parse import urlparse

from wreq import Client, Emulation, Jar


# =============================================================================
# CONSTANTS
# =============================================================================

VERSION = "j-1.2.522"
XOR_KEY = "c139db69-c5a0-413e-8b58-90785319bc49"
POW_SEED = "tp-v2-input"
POW_DIFFICULTY = 10
POW_ROUNDS = 2

CHROME_MAP = {
    "120": Emulation.Chrome120,
    "123": Emulation.Chrome123,
    "124": Emulation.Chrome124,
    "126": Emulation.Chrome126,
    "127": Emulation.Chrome127,
    "128": Emulation.Chrome128,
    "129": Emulation.Chrome129,
    "130": Emulation.Chrome130,
    "131": Emulation.Chrome131,
    "132": Emulation.Chrome132,
    "133": Emulation.Chrome133,
    "134": Emulation.Chrome134,
    "135": Emulation.Chrome135,
    "136": Emulation.Chrome136,
    "137": Emulation.Chrome137,
    "138": Emulation.Chrome138,
    "139": Emulation.Chrome139,
    "140": Emulation.Chrome140,
    "141": Emulation.Chrome141,
    "142": Emulation.Chrome142,
    "143": Emulation.Chrome143,
    "144": Emulation.Chrome144,
    "145": Emulation.Chrome145,
    "146": Emulation.Chrome146,
    "147": Emulation.Chrome147,
}


# =============================================================================
# CORE FUNCTIONS
# =============================================================================

def xor_encrypt(plaintext: str, key: str = XOR_KEY) -> str:
    key_len = len(key)
    return ''.join(chr(ord(c) ^ ord(key[i % key_len])) for i, c in enumerate(plaintext))


def encode_payload(data: dict) -> str:
    json_str = json.dumps(data, separators=(',', ':'))
    encrypted = xor_encrypt(json_str)
    return base64.b64encode(encrypted.encode('latin-1')).decode('ascii')


def build_fingerprint(user_agent: str) -> dict:
    now = int(time.time() * 1000)
    return {
        "userAgent": user_agent,
        "platform": "Win32",
        "language": "en-US",
        "languages": ["en-US", "en"],
        "cookieEnabled": True,
        "doNotTrack": None,
        "hardwareConcurrency": 8,
        "deviceMemory": 8,
        "maxTouchPoints": 0,
        "screenWidth": 1920,
        "screenHeight": 1080,
        "outerWidth": 1920,
        "outerHeight": 1040,
        "colorDepth": 24,
        "pixelRatio": 1,
        "webglVendor": "Google Inc. (NVIDIA)",
        "webglRenderer": "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)",
        "webglVersion": "WebGL 1.0 (OpenGL ES 2.0 Chromium)",
        "canvasHash": hashlib.md5(f"canvas-{user_agent}".encode()).hexdigest(),
        "timezone": "America/New_York",
        "timezoneOffset": 300,
        "timestamp": now,
        "webdriver": False,
        "chrome": True,
        "version": VERSION,
    }


def solve_pow() -> dict:
    start_time = time.time()
    start_ms = int(start_time * 1000)

    for attempt in range(1, 200000):
        nonce = ''.join(random.choice('0123456789abcdef') for _ in range(32))
        nonce_prefix = nonce[:16]

        rst = time.time()
        current = POW_SEED
        for _ in range(POW_ROUNDS):
            current = hashlib.sha256((current + nonce_prefix).encode()).hexdigest()

        # Check leading zero bits
        hash_bytes = bytes.fromhex(current)
        full_bytes = POW_DIFFICULTY // 8
        remaining_bits = POW_DIFFICULTY % 8
        ok = True
        for i in range(full_bytes):
            if hash_bytes[i] != 0:
                ok = False
                break
        if ok and remaining_bits > 0 and full_bytes < len(hash_bytes):
            if hash_bytes[full_bytes] & (0xFF << (8 - remaining_bits)) != 0:
                ok = False

        if ok:
            work_time = int(time.time() * 1000)
            round_ms = int((time.time() - rst) * 1000)
            duration = round((time.time() - start_time) * 1000, 1)
            return {
                "workTime": work_time,
                "id": nonce,
                "answers": [round_ms, 1],
                "duration": duration,
                "d": attempt,
                "st": start_ms,
                "rst": int(rst * 1000),
            }

    raise RuntimeError("PoW failed")


# =============================================================================
# SOLVER
# =============================================================================

async def solve(site: str, path: str, proxy: str = None, chrome: str = "131") -> dict:
    """
    Solve Kasada challenge and return headers.

    Args:
        site: Target site URL (e.g. "https://passport.twitch.tv")
        path: Kasada path (e.g. "/149e9513-.../2d206a39-...")
        proxy: Optional proxy URL
        chrome: Chrome version for TLS emulation (default "131")

    Returns:
        {
            "success": True/False,
            "type": "kasada",
            "headers": { ... } or None,
            "error": "..." (if failed)
        }
    """
    emulation = CHROME_MAP.get(chrome, Emulation.Chrome131)
    site = site.rstrip('/')
    path = path.rstrip('/')

    ua = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome}.0.0.0 Safari/537.36"

    # Create client
    client_kwargs = {"emulation": emulation, "cookie_provider": Jar()}
    if proxy:
        client_kwargs["proxy"] = proxy
    client = Client(**client_kwargs)

    parsed = urlparse(site)
    base = f"{parsed.scheme}://{parsed.netloc}"
    tl_url = f"{base}{path}/tl"
    mfc_url = f"{base}{path}/mfc"

    try:
        # Step 1: POST /tl -> CT
        fingerprint = build_fingerprint(ua)
        body = encode_payload(fingerprint)

        resp = await client.post(tl_url, headers={
            "User-Agent": ua,
            "Content-Type": "text/plain",
            "x-kpsdk-v": VERSION,
            "Origin": site,
            "Referer": site + "/",
        }, body=body)

        if "200" not in str(resp.status):
            return {"success": False, "type": "kasada", "headers": None, "error": f"/tl returned {resp.status}"}

        ct_raw = resp.headers.get("x-kpsdk-ct")
        ct = ct_raw.decode() if isinstance(ct_raw, bytes) else ct_raw
        if not ct:
            return {"success": False, "type": "kasada", "headers": None, "error": "No x-kpsdk-ct in /tl response"}

        # Step 2: GET /mfc -> H
        resp = await client.get(mfc_url, headers={
            "User-Agent": ua,
            "x-kpsdk-v": VERSION,
            "x-kpsdk-h": "01",
            "x-kpsdk-ct": ct,
            "Origin": site,
            "Referer": site + "/",
        })

        if "200" not in str(resp.status):
            return {"success": False, "type": "kasada", "headers": None, "error": f"/mfc returned {resp.status}"}

        h_raw = resp.headers.get("x-kpsdk-h")
        h_value = h_raw.decode() if isinstance(h_raw, bytes) else h_raw
        if not h_value:
            return {"success": False, "type": "kasada", "headers": None, "error": "No x-kpsdk-h in /mfc response"}

        # Step 3: Solve PoW -> CD
        pow_result = solve_pow()
        cd = json.dumps(pow_result, separators=(',', ':'))

        return {
            "success": True,
            "type": "kasada",
            "headers": {
                "x-kpsdk-ct": ct,
                "x-kpsdk-cd": cd,
                "x-kpsdk-v": VERSION,
                "x-kpsdk-h": h_value,
            }
        }

    except Exception as e:
        return {"success": False, "type": "kasada", "headers": None, "error": str(e)}


# =============================================================================
# CLI
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="Kasada Token Solver")
    parser.add_argument("--site", required=True, help="Target site URL (e.g. https://passport.twitch.tv)")
    parser.add_argument("--path", required=True, help="Kasada path (UUID-based path)")
    parser.add_argument("--proxy", default=None, help="Proxy URL (e.g. http://user:pass@host:port)")
    parser.add_argument("--chrome", default="131", help="Chrome version for TLS (default: 131)")
    args = parser.parse_args()

    result = asyncio.run(solve(args.site, args.path, args.proxy, args.chrome))
    print(json.dumps(result, indent=2))

    if not result["success"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
