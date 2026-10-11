"""
Kasada Request Interceptor / Decoder
======================================
Tool to capture and decode actual Kasada /tl request bodies
to learn the exact fingerprint format.

Usage:
    1. MITM proxy mode: Run this as a mitmproxy addon to auto-decode
    2. Manual mode: Paste a captured body to decode it
    3. HAR mode: Extract from a HAR file

The /tl body format:
    base64(xor_encrypt(JSON.stringify(fingerprint), XOR_KEY))
    
Where XOR_KEY = "c139db69-c5a0-413e-8b58-90785319bc49" (from bytecode addr 5466)
"""

import json
import base64
import sys
from typing import Optional

XOR_KEY = "c139db69-c5a0-413e-8b58-90785319bc49"


def xor_cipher(text: str, key: str = XOR_KEY) -> str:
    """XOR cipher (encrypt = decrypt since XOR is symmetric)."""
    key_len = len(key)
    return ''.join(chr(ord(c) ^ ord(key[i % key_len])) for i, c in enumerate(text))


def decode_tl_body(body: str) -> Optional[dict]:
    """
    Decode a /tl request body.
    
    Args:
        body: The raw request body (base64 encoded string)
    
    Returns:
        Decoded JSON object, or None if decoding fails
    """
    try:
        # Step 1: Base64 decode
        decoded_bytes = base64.b64decode(body)
        encrypted_str = decoded_bytes.decode('latin-1')
        
        # Step 2: XOR decrypt
        json_str = xor_cipher(encrypted_str, XOR_KEY)
        
        # Step 3: JSON parse
        return json.loads(json_str)
    except Exception as e:
        print(f"Decode failed: {e}")
        # Try alternative: maybe it's URL-encoded first
        try:
            from urllib.parse import unquote
            body = unquote(body)
            decoded_bytes = base64.b64decode(body)
            encrypted_str = decoded_bytes.decode('latin-1')
            json_str = xor_cipher(encrypted_str, XOR_KEY)
            return json.loads(json_str)
        except:
            pass
        return None


def encode_tl_body(data: dict) -> str:
    """
    Encode data into /tl request body format.
    
    Args:
        data: The fingerprint JSON object
    
    Returns:
        Base64-encoded, XOR-encrypted string
    """
    json_str = json.dumps(data, separators=(',', ':'))
    encrypted = xor_cipher(json_str, XOR_KEY)
    return base64.b64encode(encrypted.encode('latin-1')).decode('ascii')


def extract_from_har(har_path: str) -> list:
    """
    Extract and decode all /tl request bodies from a HAR file.
    
    Returns list of decoded fingerprint objects.
    """
    results = []
    
    with open(har_path, 'r', encoding='utf-8') as f:
        har = json.load(f)
    
    for entry in har['log']['entries']:
        url = entry['request']['url']
        if '/tl' in url or 'kpsdk' in url.lower():
            method = entry['request']['method']
            
            # Get request body
            post_data = entry['request'].get('postData', {})
            body = post_data.get('text', '')
            
            if body:
                print(f"\nFound: {method} {url}")
                print(f"  Body length: {len(body)} chars")
                
                decoded = decode_tl_body(body)
                if decoded:
                    print(f"  Decoded successfully!")
                    print(f"  Fields: {list(decoded.keys())}")
                    results.append({
                        'url': url,
                        'method': method,
                        'decoded': decoded,
                    })
                else:
                    print(f"  Failed to decode")
                    print(f"  Body preview: {body[:100]}...")
    
    return results


def interactive_mode():
    """Interactive mode for manual decoding."""
    print("=" * 60)
    print("KASADA /tl BODY DECODER")
    print(f"XOR Key: {XOR_KEY}")
    print("=" * 60)
    print()
    print("Paste a captured /tl request body (base64 string).")
    print("Or enter 'q' to quit.")
    print()
    
    while True:
        body = input("Body> ").strip()
        if body.lower() in ('q', 'quit', 'exit'):
            break
        if not body:
            continue
        
        decoded = decode_tl_body(body)
        if decoded:
            print(f"\nDecoded ({len(decoded)} fields):")
            print(json.dumps(decoded, indent=2, ensure_ascii=False))
        else:
            print("\nFailed to decode. Make sure it's the raw base64 body.")
        print()


# Mitmproxy addon (if running under mitmdump/mitmproxy)
try:
    from mitmproxy import http
    
    class KasadaDecoder:
        """mitmproxy addon that auto-decodes Kasada /tl requests."""
        
        def request(self, flow: http.HTTPFlow):
            if '/tl' in flow.request.url and flow.request.method == 'POST':
                body = flow.request.get_text()
                if body:
                    decoded = decode_tl_body(body)
                    if decoded:
                        print(f"\n{'='*60}")
                        print(f"[KASADA /tl] Decoded fingerprint:")
                        print(json.dumps(decoded, indent=2))
                        print(f"{'='*60}\n")
        
        def response(self, flow: http.HTTPFlow):
            if '/tl' in flow.request.url:
                ct = flow.response.headers.get('x-kpsdk-ct', '')
                if ct:
                    print(f"\n[KASADA /tl] Got CT: {ct[:50]}...")
            
            if '/mfc' in flow.request.url:
                h = flow.response.headers.get('x-kpsdk-h', '')
                fc = flow.response.headers.get('x-kpsdk-fc', '')
                if h:
                    print(f"\n[KASADA /mfc] Got H: {h}")
                if fc:
                    print(f"[KASADA /mfc] Got FC: {fc[:50]}...")
    
    addons = [KasadaDecoder()]

except ImportError:
    pass  # Not running under mitmproxy


if __name__ == "__main__":
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if arg.endswith('.har'):
            print(f"Extracting from HAR: {arg}")
            results = extract_from_har(arg)
            if results:
                for r in results:
                    print(f"\n{'='*60}")
                    print(json.dumps(r['decoded'], indent=2))
            else:
                print("No /tl requests found in HAR")
        else:
            # Treat as raw body
            decoded = decode_tl_body(arg)
            if decoded:
                print(json.dumps(decoded, indent=2))
            else:
                print("Failed to decode")
    else:
        interactive_mode()
