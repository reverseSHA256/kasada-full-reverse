"""
Kasada PoW Solver & Request Signer
====================================
Fully reversed from p.js bytecode (version j-1.2.522).
No VM execution, no browser sandbox - pure Python implementation.

Usage:
    solver = KasadaSolver(ct_token, config)
    cd_token = solver.solve_pow()
    headers = solver.sign_request(method, path, body)
"""

import hashlib
import hmac
import json
import time
import random
import base64
import struct
from typing import Optional, Dict, Tuple, List


class KasadaSolver:
    """
    Kasada anti-bot PoW solver and request signer.
    
    Reversed from p.js version j-1.2.522.
    """
    
    # Default configuration (hardcoded in bytecode at addr 22700-22810)
    DEFAULT_CONFIG = {
        "ykj": "7ae9906d03439b1173e98ddb9342a718a535ab115a7f27138cd183737d7f7afe",  # HMAC key (32 bytes hex)
        "qdw": 10,       # difficulty (leading zero bits)
        "xqn": 2,        # number of hash rounds
        "zsr": "",       # server challenge nonce (from /tl response)
        "jpk": "CV7o9fRC/gx24wn2aw7QVuED7ds=",  # AES key (base64)
        "rpk": "CV7o9fRC/gx24wn2",               # AES IV (16 chars)
        "zgp": 86400,    # TTL (seconds)
        "version": "j-1.2.522",
    }
    
    def __init__(self, ct_token: str = "", config: Optional[Dict] = None):
        """
        Initialize the solver.
        
        Args:
            ct_token: The x-kpsdk-ct token (from initial /tl response)
            config: Optional config override. Keys: ykj, qdw, xqn, zsr
        """
        self.ct_token = ct_token
        self.config = {**self.DEFAULT_CONFIG}
        if config:
            self.config.update(config)
        
        self.difficulty = self.config["qdw"]
        self.rounds = self.config["xqn"]
        self.hmac_key = bytes.fromhex(self.config["ykj"])
        self.challenge_nonce = self.config["zsr"]
    
    def _generate_nonce(self, length: int = 32) -> str:
        """Generate a random hex nonce string."""
        return ''.join(random.choice('0123456789abcdef') for _ in range(length))
    
    def _sha256(self, data: str) -> str:
        """SHA-256 hash, returns hex digest."""
        return hashlib.sha256(data.encode('utf-8')).hexdigest()
    
    def _check_difficulty(self, hash_hex: str, difficulty: int) -> bool:
        """
        Check if hash meets difficulty requirement.
        Difficulty = number of leading zero BITS required.
        
        E.g. difficulty=10 means first 10 bits must be zero.
        """
        hash_bytes = bytes.fromhex(hash_hex)
        
        full_bytes = difficulty // 8
        remaining_bits = difficulty % 8
        
        # Check full zero bytes
        for i in range(full_bytes):
            if hash_bytes[i] != 0:
                return False
        
        # Check remaining bits
        if remaining_bits > 0 and full_bytes < len(hash_bytes):
            mask = 0xFF << (8 - remaining_bits)
            if hash_bytes[full_bytes] & mask != 0:
                return False
        
        return True
    
    def _mine_single(self, seed: str, nonce: str) -> Tuple[str, bool]:
        """
        Perform one mining attempt with chained hashing.
        
        The hash chain is:
            Round 1: SHA-256(seed + nonce[0:16])
            Round 2: SHA-256(round1_hash + nonce[0:16])
            ...
        
        Returns: (final_hash, meets_difficulty)
        """
        nonce_prefix = nonce[:16]
        current = seed
        
        for _ in range(self.rounds):
            hash_input = current + nonce_prefix
            current = self._sha256(hash_input)
        
        return current, self._check_difficulty(current, self.difficulty)
    
    def solve_pow(self, seed: str = "tp-v2-input", max_attempts: int = 100000) -> Dict:
        """
        Solve the Proof-of-Work challenge.
        
        Args:
            seed: Initial seed string (default "tp-v2-input")
            max_attempts: Maximum mining attempts before giving up
            
        Returns:
            Dict with CD token payload fields:
                - answers: list of timing values
                - workTime: total work time in ms
                - st: start timestamp
                - rst: round start timestamp  
                - d: difficulty
                - nonce: winning nonce
                - hash: final hash
        """
        start_time = time.time()
        answers = []
        
        for attempt in range(max_attempts):
            nonce = self._generate_nonce(32)
            
            round_start = time.time()
            final_hash, success = self._mine_single(seed, nonce)
            round_end = time.time()
            
            if success:
                elapsed_ms = int((round_end - round_start) * 1000)
                answers.append(elapsed_ms)
                
                total_work_ms = int((time.time() - start_time) * 1000)
                
                result = {
                    "answers": answers,
                    "workTime": total_work_ms,
                    "st": int(start_time * 1000),
                    "rst": int(round_start * 1000),
                    "d": self.difficulty,
                    "nonce": nonce,
                    "hash": final_hash,
                    "attempt": attempt + 1,
                }
                
                return result
        
        raise RuntimeError(f"Failed to solve PoW after {max_attempts} attempts")
    
    def generate_cd_token(self, pow_result: Optional[Dict] = None) -> str:
        """
        Generate the x-kpsdk-cd token.
        
        Args:
            pow_result: Output from solve_pow(). If None, solves PoW first.
            
        Returns:
            JSON string for the x-kpsdk-cd header value.
        """
        if pow_result is None:
            pow_result = self.solve_pow()
        
        # CD payload structure (reversed from zfn function at addr 46876)
        cd_payload = {
            "workTime": pow_result["workTime"],
            "id": self._generate_nonce(16),
            "answers": pow_result["answers"],
            "d": pow_result["d"],
            "st": pow_result["st"],
            "rst": pow_result["rst"],
        }
        
        return json.dumps(cd_payload, separators=(',', ':'))
    
    def compute_hmac(self, ct_token: str, cd_token: str, 
                     method: str = "GET", path: str = "/",
                     body: str = "") -> str:
        """
        Compute the x-kpsdk-h HMAC header.
        
        The HMAC binds together:
        - CT token
        - CD token  
        - Request method
        - Request path
        - Request body (if POST/PUT)
        
        Returns:
            Base64-encoded HMAC-SHA256 value.
        """
        # HMAC message = concatenation of relevant request data
        # From the bytecode: the hmac function uses sha256 with the ykj key
        message = ct_token + cd_token + method.upper() + path
        if body:
            message += body
        
        h = hmac.new(self.hmac_key, message.encode('utf-8'), hashlib.sha256)
        return base64.b64encode(h.digest()).decode('ascii')
    
    def sign_request(self, method: str = "GET", path: str = "/",
                     body: str = "", ct_token: Optional[str] = None) -> Dict[str, str]:
        """
        Generate all required Kasada headers for a request.
        
        Args:
            method: HTTP method
            path: Request path
            body: Request body
            ct_token: Override CT token
            
        Returns:
            Dict of headers: x-kpsdk-ct, x-kpsdk-cd, x-kpsdk-h
        """
        ct = ct_token or self.ct_token
        
        # Solve PoW and generate CD
        pow_result = self.solve_pow()
        cd = self.generate_cd_token(pow_result)
        
        # Compute HMAC
        h = self.compute_hmac(ct, cd, method, path, body)
        
        return {
            "x-kpsdk-ct": ct,
            "x-kpsdk-cd": cd,
            "x-kpsdk-h": h,
        }


def demo():
    """Demonstrate the solver."""
    print("=" * 70)
    print("KASADA PoW SOLVER - Pure Python Implementation")
    print("Reversed from p.js v" + KasadaSolver.DEFAULT_CONFIG["version"])
    print("=" * 70)
    print()
    
    solver = KasadaSolver()
    
    print(f"Configuration:")
    print(f"  Difficulty: {solver.difficulty} leading zero bits")
    print(f"  Rounds: {solver.rounds} SHA-256 iterations")
    print(f"  HMAC Key: {solver.config['ykj'][:16]}...{solver.config['ykj'][-8:]}")
    print()
    
    print("Solving PoW...")
    start = time.time()
    result = solver.solve_pow()
    elapsed = time.time() - start
    
    print(f"  SOLVED in {elapsed:.3f}s ({result['attempt']} attempts)")
    print(f"  Nonce: {result['nonce']}")
    print(f"  Hash:  {result['hash']}")
    print(f"  Work time: {result['workTime']}ms")
    print()
    
    # Verify the hash
    nonce_prefix = result['nonce'][:16]
    h1 = hashlib.sha256(("tp-v2-input" + nonce_prefix).encode()).hexdigest()
    h2 = hashlib.sha256((h1 + nonce_prefix).encode()).hexdigest()
    print(f"  Verification:")
    print(f"    Round 1: SHA256('tp-v2-input' + '{nonce_prefix}') = {h1[:32]}...")
    print(f"    Round 2: SHA256('{h1[:16]}...' + '{nonce_prefix}') = {h2[:32]}...")
    print(f"    Leading zeros: {bin(int(h2[:4], 16))[2:].zfill(16)[:12]}...")
    print()
    
    # Generate CD token
    cd = solver.generate_cd_token(result)
    print(f"  CD Token: {cd[:80]}...")
    print()
    
    # Generate HMAC (with dummy CT)
    ct_dummy = "test_ct_token_value"
    h = solver.compute_hmac(ct_dummy, cd, "GET", "/api/data")
    print(f"  HMAC (x-kpsdk-h): {h}")
    print()
    
    # Full signed request
    print("Full signed headers:")
    headers = solver.sign_request("GET", "/api/data", ct_token=ct_dummy)
    for k, v in headers.items():
        val = v if len(v) < 60 else v[:57] + "..."
        print(f"  {k}: {val}")


if __name__ == "__main__":
    demo()
