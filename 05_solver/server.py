"""
Kasada Token Solver - HTTP Server
===================================
An HTTP server that accepts Kasada solving tasks and returns
the required x-kpsdk-* headers as JSON.

Works on ANY Kasada-protected site — auto-detects version by
fetching p.js from the target.

Run:
    python server.py                  # default port 8080
    python server.py --port 3000     # custom port

Endpoints:
    POST /solve
        Body: {
            "type": "kasada",
            "url": "https://...",
            "user_agent": "Mozilla/5.0 ...",
            "ua_version": 131,
            "kasada_config": {
                "p_js_path": "/uuid1/uuid2/p.js",
                "fp_host": "passport.twitch.tv",
                "tl_host": "gql.twitch.tv",
                "cd_constant": "..." (optional)
            },
            "proxy": "http://..."
        }
        Returns: {
            "success": true,
            "type": "kasada",
            "headers": {
                "x-kpsdk-ct": "...",
                "x-kpsdk-cd": "{...}",
                "x-kpsdk-v": "j-1.2.xxx",
                "x-kpsdk-h": "..."
            }
        }

    GET /health
        Returns: {"status": "ok"}

Requirements:
    pip install wreq fastapi uvicorn
"""

import asyncio
import hashlib
import json
import re
import time
import random
import base64
from urllib.parse import urlparse

import uvicorn
from fastapi import FastAPI, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from wreq import Client, Emulation, Jar


# =============================================================================
# DEFAULTS (overridden by auto-detection from p.js)
# =============================================================================

DEFAULT_VERSION = "j-1.2.522"
DEFAULT_XOR_KEY = "c139db69-c5a0-413e-8b58-90765319bc49"
POW_SEED = "tp-v2-input"
POW_DIFFICULTY = 10
POW_ROUNDS = 2

CHROME_MAP = {
    "100": Emulation.Chrome100, "101": Emulation.Chrome101,
    "104": Emulation.Chrome104, "105": Emulation.Chrome105,
    "106": Emulation.Chrome106, "107": Emulation.Chrome107,
    "108": Emulation.Chrome108, "109": Emulation.Chrome109,
    "110": Emulation.Chrome110, "114": Emulation.Chrome114,
    "116": Emulation.Chrome116, "117": Emulation.Chrome117,
    "118": Emulation.Chrome118, "119": Emulation.Chrome119,
    "120": Emulation.Chrome120, "123": Emulation.Chrome123,
    "124": Emulation.Chrome124, "126": Emulation.Chrome126,
    "127": Emulation.Chrome127, "128": Emulation.Chrome128,
    "129": Emulation.Chrome129, "130": Emulation.Chrome130,
    "131": Emulation.Chrome131, "132": Emulation.Chrome132,
    "133": Emulation.Chrome133, "134": Emulation.Chrome134,
    "135": Emulation.Chrome135, "136": Emulation.Chrome136,
    "137": Emulation.Chrome137, "138": Emulation.Chrome138,
    "139": Emulation.Chrome139, "140": Emulation.Chrome140,
    "141": Emulation.Chrome141, "142": Emulation.Chrome142,
    "143": Emulation.Chrome143, "144": Emulation.Chrome144,
    "145": Emulation.Chrome145, "146": Emulation.Chrome146,
    "147": Emulation.Chrome147,
}

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/131.0.0.0 Safari/537.36")


# =============================================================================
# CONFIG DETECTION
# =============================================================================

async def detect_kasada_config(client: Client, pjs_url: str) -> dict:
    """
    Fetch p.js from the target and extract:
    - Version string (e.g. "j-1.2.522")
    - XOR key (UUID format)

    Falls back to defaults if detection fails.
    """
    config = {
        "version": DEFAULT_VERSION,
        "xor_key": DEFAULT_XOR_KEY,
    }

    try:
        resp = await client.get(pjs_url, headers={"User-Agent": DEFAULT_UA})

        if "200" not in str(resp.status):
            return config

        text = await resp.text()

        # Extract version: look for "j-1.2.xxx" pattern
        version_match = re.search(r'j-1\.2\.(\d+)', text)
        if version_match:
            config["version"] = version_match.group(0)

        # Extract XOR key: look for UUID pattern (36 chars with dashes)
        uuid_match = re.search(
            r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})',
            text
        )
        if uuid_match:
            config["xor_key"] = uuid_match.group(1)

    except Exception:
        pass  # Use defaults

    return config


# =============================================================================
# CORE LOGIC
# =============================================================================

def xor_encrypt(plaintext: str, key: str) -> str:
    key_len = len(key)
    return ''.join(chr(ord(c) ^ ord(key[i % key_len])) for i, c in enumerate(plaintext))


def encode_payload(data: dict, xor_key: str) -> str:
    json_str = json.dumps(data, separators=(',', ':'))
    encrypted = xor_encrypt(json_str, xor_key)
    return base64.b64encode(encrypted.encode('latin-1')).decode('ascii')


def build_fingerprint(user_agent: str, version: str) -> dict:
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
        "version": version,
    }


def solve_pow(seed: str = POW_SEED, difficulty: int = POW_DIFFICULTY,
              rounds: int = POW_ROUNDS) -> dict:
    start_time = time.time()
    start_ms = int(start_time * 1000)

    for attempt in range(1, 200000):
        nonce = ''.join(random.choice('0123456789abcdef') for _ in range(32))
        nonce_prefix = nonce[:16]

        rst = time.time()
        current = seed
        for _ in range(rounds):
            current = hashlib.sha256((current + nonce_prefix).encode()).hexdigest()

        # Check leading zero bits
        hash_bytes = bytes.fromhex(current)
        full_bytes = difficulty // 8
        remaining_bits = difficulty % 8
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


async def solve_kasada(
    url: str,
    p_js_path: str,
    fp_host: str,
    tl_host: str,
    user_agent: str = None,
    ua_version: int = 131,
    cd_constant: str = None,
    proxy: str = None,
) -> dict:
    """
    Solve Kasada challenge for ANY site.

    Args:
        url: The Kasada-protected origin URL
        p_js_path: Path to p.js (e.g. /uuid1/uuid2/p.js)
        fp_host: Hostname serving the fingerprint page
        tl_host: Hostname for the /tl token endpoint
        user_agent: UA string (must match what you'll replay with)
        ua_version: Chrome major version (80-300)
        cd_constant: Optional hex string for CD PoW constant
        proxy: Optional proxy URL
    """
    ua = user_agent or DEFAULT_UA
    chrome_str = str(ua_version)
    emulation = CHROME_MAP.get(chrome_str, Emulation.Chrome131)

    # Parse the URL to get scheme
    parsed = urlparse(url)
    scheme = parsed.scheme or "https"

    # Build URLs using the provided hosts
    # p_js_path may or may not include /p.js at the end
    base_path = p_js_path.rstrip('/')
    if base_path.endswith('/p.js'):
        base_path = base_path[:-len('/p.js')]
    
    # base_path is now just the UUID path (e.g. /149e9513-.../2d206a39-...)
    pjs_url = f"{scheme}://{fp_host}{base_path}/p.js"
    tl_url = f"{scheme}://{tl_host}{base_path}/tl"
    mfc_url = f"{scheme}://{tl_host}{base_path}/mfc"

    # Create wreq client with TLS impersonation
    client_kwargs = {"emulation": emulation, "cookie_provider": Jar()}
    if proxy:
        client_kwargs["proxy"] = proxy
    client = Client(**client_kwargs)

    # Origin/Referer for requests
    origin = f"{scheme}://{fp_host}"
    referer = origin + "/"

    try:
        # Step 0: Auto-detect version & XOR key from p.js
        t0 = time.time()
        kasada_config = await detect_kasada_config(client, pjs_url)
        version = kasada_config["version"]
        xor_key = kasada_config["xor_key"]
        t_pjs = time.time() - t0

        # Step 1: POST /tl -> CT
        t1 = time.time()
        fingerprint = build_fingerprint(ua, version)
        body = encode_payload(fingerprint, xor_key)

        resp = await client.post(tl_url, headers={
            "User-Agent": ua,
            "Content-Type": "text/plain",
            "x-kpsdk-v": version,
            "Origin": origin,
            "Referer": referer,
        }, body=body)

        if "200" not in str(resp.status):
            return {"success": False, "type": "kasada", "headers": None,
                    "error": f"/tl returned {resp.status}"}

        ct_raw = resp.headers.get("x-kpsdk-ct")
        ct = ct_raw.decode() if isinstance(ct_raw, bytes) else ct_raw
        if not ct:
            return {"success": False, "type": "kasada", "headers": None,
                    "error": "No x-kpsdk-ct in /tl response"}
        t_tl = time.time() - t1

        # Step 2: GET /mfc -> H
        t2 = time.time()
        resp = await client.get(mfc_url, headers={
            "User-Agent": ua,
            "x-kpsdk-v": version,
            "x-kpsdk-h": "01",
            "x-kpsdk-ct": ct,
            "Origin": origin,
            "Referer": referer,
        })

        if "200" not in str(resp.status):
            return {"success": False, "type": "kasada", "headers": None,
                    "error": f"/mfc returned {resp.status}"}

        h_raw = resp.headers.get("x-kpsdk-h")
        h_value = h_raw.decode() if isinstance(h_raw, bytes) else h_raw
        if not h_value:
            return {"success": False, "type": "kasada", "headers": None,
                    "error": "No x-kpsdk-h in /mfc response"}
        t_mfc = time.time() - t2

        # Step 3: Solve PoW -> CD
        t3 = time.time()
        pow_seed = cd_constant if cd_constant else POW_SEED
        pow_result = solve_pow(seed=pow_seed)
        cd = json.dumps(pow_result, separators=(',', ':'))
        t_pow = time.time() - t3

        total = t_pjs + t_tl + t_mfc + t_pow

        return {
            "success": True,
            "type": "kasada",
            "headers": {
                "x-kpsdk-ct": ct,
                "x-kpsdk-cd": cd,
                "x-kpsdk-v": version,
                "x-kpsdk-h": h_value,
            },
            "response_time": f"{total:.2f}s ({int(total * 1000)}ms)"
        }

    except Exception as e:
        return {"success": False, "type": "kasada", "headers": None, "error": str(e)}


# =============================================================================
# HTTP SERVER
# =============================================================================

app = FastAPI(title="Kasada Solver", version="1.0.0")


class KasadaConfig(BaseModel):
    p_js_path: str = Field(..., description="Path to p.js (e.g. /149e9513-.../2d206a39-.../p.js)")
    fp_host: str = Field(..., description="Hostname serving the fingerprint page")
    tl_host: str = Field(..., description="Hostname for the /tl token endpoint")
    cd_constant: str = Field(None, description="Optional hex string for CD PoW constant")


class SolveRequest(BaseModel):
    type: str = Field("kasada", description="Must be 'kasada'")
    url: str = Field(..., description="The Kasada-protected origin URL")
    user_agent: str = Field(None, description="UA string (use same one you'll replay with)")
    ua_version: int = Field(131, description="Major Chrome version (80-300)")
    kasada_config: KasadaConfig = Field(..., description="Site-specific paths and hosts")
    proxy: str = Field(None, description="Optional proxy URL")


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/solve")
async def solve_get(
    url: str = Query(..., description="Target site URL"),
    p_js_path: str = Query(..., description="Path to p.js (e.g. /uuid1/uuid2/p.js)"),
    fp_host: str = Query(..., description="Hostname serving p.js"),
    tl_host: str = Query(..., description="Hostname for /tl endpoint"),
    user_agent: str = Query(None, description="UA string"),
    ua_version: int = Query(131, description="Chrome major version"),
    cd_constant: str = Query(None, description="Optional PoW constant"),
    proxy: str = Query(None, description="Optional proxy URL"),
):
    result = await solve_kasada(
        url=url,
        p_js_path=p_js_path,
        fp_host=fp_host,
        tl_host=tl_host,
        user_agent=user_agent,
        ua_version=ua_version,
        cd_constant=cd_constant,
        proxy=proxy,
    )
    return PlainTextResponse(json.dumps(result, indent=2), media_type="application/json")


@app.post("/solve")
async def solve_post(req: SolveRequest):
    if req.type not in ("kasada", "kasada-bypass"):
        result = {"success": False, "type": req.type, "headers": None,
                  "error": f"Type must be 'kasada', got '{req.type}'"}
        return PlainTextResponse(json.dumps(result, indent=2), media_type="application/json")

    cfg = req.kasada_config
    result = await solve_kasada(
        url=req.url,
        p_js_path=cfg.p_js_path,
        fp_host=cfg.fp_host,
        tl_host=cfg.tl_host,
        user_agent=req.user_agent,
        ua_version=req.ua_version,
        cd_constant=cfg.cd_constant,
        proxy=req.proxy,
    )
    return PlainTextResponse(json.dumps(result, indent=2), media_type="application/json")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Kasada Solver HTTP Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8080, help="Port to bind (default: 8080)")
    args = parser.parse_args()

    print(f"Kasada Solver server starting on http://{args.host}:{args.port}")
    print(f"  POST /solve   - Kasada solve request")
    print(f"  GET  /health  - Health check")
    print()
    print(f"Example request:")
    print(f'  curl -X POST http://localhost:{args.port}/solve \\')
    print(f'    -H "Content-Type: application/json" \\')
    print(f'    -d \'{{"type":"kasada","url":"https://passport.twitch.tv",')
    print(f'         "kasada_config":{{"p_js_path":"/149e9513-.../2d206a39-.../p.js",')
    print(f'                            "fp_host":"passport.twitch.tv",')
    print(f'                            "tl_host":"passport.twitch.tv"}}}}\'')
    print()

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
