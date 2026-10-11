"""
Example: Bypass Kasada on Twitch login endpoint
=================================================
Tested & working as of 2025-07-01.

This demonstrates a full Kasada bypass:
  1. Acquires CT token via /tl (fingerprint submission)
  2. Gets x-kpsdk-h from /mfc
  3. Solves PoW for CD token
  4. Makes protected request with all headers
  5. Gets application-level response (past Kasada!)

Requirements:
  pip install wreq
"""
import asyncio
import json
from kasada_full_solver import KasadaSolver, Emulation


async def main():
    # Initialize solver
    solver = KasadaSolver(
        target_url="https://passport.twitch.tv",
        kasada_path="/149e9513-01fa-4fb0-aad4-566afd725d1b/2d206a39-8ed7-437e-a3be-862e0f06eea3",
        # proxy="http://user:pass@residential-proxy:port",  # recommended for production
        # emulation=Emulation.Chrome131,  # default
    )
    
    # Perform Kasada handshake (CT + x-kpsdk-h)
    success = await solver.init_session()
    if not success:
        print("Failed to initialize Kasada session")
        return
    
    # Make a protected request (fresh CD generated per-request)
    resp = await solver.protected_request(
        method="POST",
        url="https://passport.twitch.tv/protected_login",
        body=json.dumps({
            "username": "test_user",
            "password": "test_pass",
            "client_id": "kimne78kx3ncx6brgo4mv6wki5h1ko",
        }),
        headers={"Content-Type": "application/json"}
    )
    
    status = str(resp.status)
    body = await resp.text()
    
    print(f"\nResult: {status}")
    print(f"Body: {body}")
    
    if "403" in status:
        print("\n[BLOCKED] Kasada rejected the request")
    else:
        print(f"\n[PASSED] Got through Kasada! (status={status})")
        # 400 = bad credentials (expected for test)
        # 200 = login successful
        # 429 = rate limited but past kasada


asyncio.run(main())
