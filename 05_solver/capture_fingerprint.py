"""
Kasada Fingerprint Capture Tool
=================================
Captures the REAL fingerprint format sent to /tl by intercepting
browser traffic through a local proxy.

Two modes:
  1. PROXY MODE: Run as mitmproxy addon to auto-capture & decode
  2. MANUAL MODE: Paste a captured /tl body from browser DevTools

Usage (Proxy Mode):
    # Install mitmproxy: pip install mitmproxy
    mitmdump -s capture_fingerprint.py --set block_global=false

    # Then configure browser to use proxy localhost:8080
    # Browse to the target site
    # The decoded fingerprint will be saved to fingerprint_captured.json

Usage (Manual Mode - DevTools):
    1. Open DevTools > Network tab
    2. Browse to the Kasada-protected site
    3. Find the POST request to /tl (look for the kasada UUID path)
    4. Copy the request body (it's a base64 string)
    5. Run: python capture_fingerprint.py <paste_body_here>
    
    Or interactively:
    python capture_fingerprint.py
"""

import json
import base64
import sys
import os
from datetime import datetime

XOR_KEY = "c139db69-c5a0-413e-8b58-90785319bc49"
OUTPUT_FILE = "fingerprint_captured.json"


def xor_cipher(text: str, key: str = XOR_KEY) -> str:
    """XOR cipher (symmetric)."""
    key_len = len(key)
    return ''.join(chr(ord(c) ^ ord(key[i % key_len])) for i, c in enumerate(text))


def decode_tl_body(body: str) -> dict:
    """
    Decode a /tl request body.
    
    The format is: base64(xor(JSON.stringify(fingerprint), XOR_KEY))
    """
    # Handle potential URL encoding
    if '%' in body:
        from urllib.parse import unquote
        body = unquote(body)
    
    # Strip whitespace
    body = body.strip()
    
    # Base64 decode
    # Add padding if needed
    padding = 4 - (len(body) % 4)
    if padding != 4:
        body += '=' * padding
    
    decoded_bytes = base64.b64decode(body)
    encrypted_str = decoded_bytes.decode('latin-1')
    
    # XOR decrypt
    json_str = xor_cipher(encrypted_str, XOR_KEY)
    
    # Parse JSON
    return json.loads(json_str)


def save_fingerprint(fingerprint: dict, source: str = "unknown"):
    """Save captured fingerprint to file."""
    output = {
        "captured_at": datetime.now().isoformat(),
        "source": source,
        "field_count": len(fingerprint),
        "fields": list(fingerprint.keys()),
        "fingerprint": fingerprint,
    }
    
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    
    print(f"\n[+] Fingerprint saved to {OUTPUT_FILE}")
    print(f"    Fields ({len(fingerprint)}):")
    for key, val in fingerprint.items():
        val_str = str(val)
        if len(val_str) > 60:
            val_str = val_str[:57] + "..."
        print(f"      {key}: {val_str}")


def generate_builder_code(fingerprint: dict):
    """Generate Python code for FingerprintBuilder from captured data."""
    print("\n" + "=" * 60)
    print("GENERATED FingerprintBuilder.build() code:")
    print("=" * 60)
    print()
    print("    def build(self) -> dict:")
    print("        now = int(time.time() * 1000)")
    print("        return {")
    
    for key, val in fingerprint.items():
        if isinstance(val, str):
            # Check if it's a dynamic value
            if key in ('timestamp', 'time', 'st', 'ts'):
                print(f"            \"{key}\": now,")
            elif 'userAgent' in key or 'user_agent' in key:
                print(f"            \"{key}\": self.user_agent,")
            else:
                print(f"            \"{key}\": \"{val}\",")
        elif isinstance(val, bool):
            print(f"            \"{key}\": {val},")
        elif isinstance(val, (int, float)):
            print(f"            \"{key}\": {val},")
        elif isinstance(val, list):
            print(f"            \"{key}\": {json.dumps(val)},")
        elif isinstance(val, dict):
            print(f"            \"{key}\": {json.dumps(val)},")
        elif val is None:
            print(f"            \"{key}\": None,")
        else:
            print(f"            \"{key}\": {repr(val)},")
    
    print("        }")
    print()


# =============================================================================
# MITMPROXY ADDON MODE
# =============================================================================

try:
    from mitmproxy import http
    
    class KasadaCapture:
        """mitmproxy addon that captures and decodes /tl requests."""
        
        def request(self, flow: http.HTTPFlow):
            if '/tl' in flow.request.url and flow.request.method == 'POST':
                body = flow.request.get_text()
                if body and len(body) > 50:  # Likely base64 encoded fingerprint
                    try:
                        fingerprint = decode_tl_body(body)
                        print(f"\n{'='*60}")
                        print(f"[CAPTURED] /tl fingerprint from {flow.request.url}")
                        print(f"{'='*60}")
                        save_fingerprint(fingerprint, source=flow.request.url)
                        generate_builder_code(fingerprint)
                    except Exception as e:
                        print(f"[ERROR] Failed to decode /tl body: {e}")
                        print(f"  Body preview: {body[:100]}...")
        
        def response(self, flow: http.HTTPFlow):
            if '/tl' in flow.request.url:
                ct = flow.response.headers.get('x-kpsdk-ct', '')
                st = flow.response.headers.get('x-kpsdk-st', '')
                if ct:
                    print(f"\n[/tl RESPONSE]")
                    print(f"  CT: {ct}")
                    print(f"  ST: {st}")
            
            if '/mfc' in flow.request.url:
                h = flow.response.headers.get('x-kpsdk-h', '')
                fc = flow.response.headers.get('x-kpsdk-fc', '')
                if h:
                    print(f"\n[/mfc RESPONSE]")
                    print(f"  H: {h}")
                    if fc:
                        print(f"  FC: {fc[:60]}...")
    
    addons = [KasadaCapture()]
    print("[*] Kasada Capture addon loaded for mitmproxy")

except ImportError:
    pass  # Not running under mitmproxy


# =============================================================================
# CLI MODE
# =============================================================================

if __name__ == "__main__":
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        
        if arg == "--help" or arg == "-h":
            print(__doc__)
            sys.exit(0)
        
        if os.path.isfile(arg):
            # It's a file - read it
            with open(arg, 'r') as f:
                body = f.read().strip()
        else:
            # It's the body itself
            body = arg
        
        try:
            fingerprint = decode_tl_body(body)
            save_fingerprint(fingerprint, source="cli_argument")
            generate_builder_code(fingerprint)
        except Exception as e:
            print(f"[ERROR] Failed to decode: {e}")
            print(f"  Make sure you're passing the raw base64 /tl request body")
            sys.exit(1)
    else:
        # Interactive mode
        print("=" * 60)
        print("KASADA FINGERPRINT CAPTURE")
        print("=" * 60)
        print()
        print("Paste the /tl request body (base64 string from DevTools):")
        print("(Press Enter twice when done)")
        print()
        
        lines = []
        while True:
            try:
                line = input()
                if line:
                    lines.append(line)
                else:
                    if lines:
                        break
            except EOFError:
                break
        
        body = ''.join(lines).strip()
        if body:
            try:
                fingerprint = decode_tl_body(body)
                save_fingerprint(fingerprint, source="interactive_input")
                generate_builder_code(fingerprint)
            except Exception as e:
                print(f"\n[ERROR] Failed to decode: {e}")
                print(f"  Body length: {len(body)}")
                print(f"  Preview: {body[:80]}...")
        else:
            print("No input provided.")
