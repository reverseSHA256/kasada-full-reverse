# KASADA ANTI-BOT SYSTEM: COMPLETE REVERSE-ENGINEERING GUIDE

> **Historical document — outdated; updates required.** This material concerns the archived `j-1.2.522` snapshot. This guide contains historical conclusions and broad compatibility claims from the original investigation. Current behavior has not been verified. Captured authentication header values have been sanitized for publication. See [the current repository overview](../README.md) for status, limitations, and the update roadmap.
## Deep Technical Documentation & Methodology

---

## TABLE OF CONTENTS

1. [What Kasada Is](#1-what-kasada-is)
2. [System Architecture Overview](#2-system-architecture-overview)
3. [The Script Delivery Layer](#3-the-script-delivery-layer)
4. [The TLS/JA3 Fingerprint Layer](#4-the-tlsja3-fingerprint-layer)
5. [The JavaScript VM (p.js)](#5-the-javascript-vm-pjs)
6. [Bytecode Format & Encoding](#6-bytecode-format--encoding)
7. [String Table & Cipher](#7-string-table--cipher)
8. [The 87-Opcode VM ISA](#8-the-87-opcode-vm-isa)
9. [Operand Decoding](#9-operand-decoding)
10. [Frame Management & Scope Chains](#10-frame-management--scope-chains)
11. [The Fingerprint Collection Layer](#11-the-fingerprint-collection-layer)
12. [The CT Token (Client Token)](#12-the-ct-token-client-token)
13. [The CD Token (Client Data / Proof-of-Work)](#13-the-cd-token-client-data--proof-of-work)
14. [The HMAC Header (x-kpsdk-h)](#14-the-hmac-header-x-kpsdk-h)
15. [The Full Request Signing Flow](#15-the-full-request-signing-flow)
16. [SHA-256 Implementation Internals](#16-sha-256-implementation-internals)
17. [VXN — SOLVED](#17-vxn--solved)
18. [What You Need to Reverse Kasada](#18-what-you-need-to-reverse-kasada)
19. [Step-by-Step Methodology](#19-step-by-step-methodology)
20. [Tools & Libraries Required](#20-tools--libraries-required)
21. [Known Approaches & Their Status](#21-known-approaches--their-status)
22. [Version Rotation & Cat-and-Mouse](#22-version-rotation--cat-and-mouse)
23. [File Inventory & Artifacts](#23-file-inventory--artifacts)
24. [Glossary](#24-glossary)

---

## 1. WHAT KASADA IS

Kasada is a **Zero-Trust bot detection system** deployed at the edge (CDN/TLS layer) of protected websites. Unlike traditional CAPTCHAs, it is **invisible to legitimate users** — there is no puzzle to solve, no checkbox to click. The protection operates entirely in the background through:

- **TLS fingerprinting** (JA3/JA4) at the connection layer
- **JavaScript VM execution** that collects browser fingerprints
- **Proof-of-Work (PoW)** challenges that economically burden automation
- **Cryptographic token signing** that binds requests to sessions
- **Polymorphic code rotation** that changes the script daily/hourly

### Protected Sites (confirmed)
- **Twitch** (passport.twitch.tv, www.twitch.tv) — script version j-1.2.522
- **GoDaddy SSO** (sso.secureserver.net) — script version j-1.2.430
- Many others (Kasada's client list is not public, but the tenant UUID system supports many)

### Key Properties
- NOT a CAPTCHA — no user interaction required
- NOT a WAF rule engine — it's a client-side proof system
- NOT static — the script rotates (version UUIDs change)
- NOT solvable by headless browsers alone — it detects them
- NOT solvable by replaying tokens — they're single-use and session-bound

---

## 2. SYSTEM ARCHITECTURE OVERVIEW

```
┌──────────────────────────────────────────────────────────────────────┐
│                         KASADA SYSTEM FLOW                           │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  BROWSER                          KASADA EDGE              ORIGIN     │
│  ───────                          ───────────              ──────     │
│                                                                       │
│  1. GET /page ──────────────────►  ──────────────────►  200 OK       │
│     ← 200 OK (HTML with <script>  │                                    │
│       src=k.twitchcdn.net/...)    │                                    │
│                                   │                                    │
│  2. GET p.js ──────────────────►  │                                    │
│     ← 200 OK (157KB JS VM)  ◄───  │                                    │
│                                   │                                    │
│  3. VM executes:                   │                                    │
│     a. Collects fingerprints       │                                    │
│     b. GET /fp?x-kpsdk-v=...  ──►  │                                    │
│        ← 200 (fingerprint ack) ◄──  │                                    │
│     c. POST /tl ───────────────►   │                                    │
│        ← x-kpsdk-ct: <CT>     ◄──  │  (server validates fingerprint)   │
│     d. GET /mfc ───────────────►   │                                    │
│        ← x-kpsdk-fc, x-kpsdk-h ◄── │  (feature config + HMAC)          │
│     e. Solves PoW (CD)             │                                    │
│     f. Stores CT, CD in window.KPSDK                                  │
│                                                                       │
│  4. User action (login, API call):                                    │
│     VM intercepts fetch/XHR                                           │
│     Injects headers:                                                  │
│       x-kpsdk-ct: <CT>                                                │
│       x-kpsdk-cd: <CD JSON>                                           │
│       x-kpsdk-h: <server-issued HMAC>                                 │
│       x-kpsdk-v: j-1.2.522                                           │
│       x-kpsdk-r: <rotation>                                           │
│     POST /api/protected ─────────►  ──────────────►  Origin           │
│     ← Response                   ◄──  │                                    │
│                                                                       │
│  Kasada edge validates:                                               │
│    - TLS fingerprint matches CT                                      │
│    - CT not expired (~30min)                                         │
│    - CD fresh (<5s), single-use                                      │
│    - HMAC valid (server-issued session token)                         │
│    - Version current                                                 │
│  If valid → forward to origin                                        │
│  If invalid → block (403) or challenge                               │
│                                                                       │
└──────────────────────────────────────────────────────────────────────┘
```

### Token Hierarchy
```
x-kpsdk-v   (version)     ──► "j-1.2.522" — identifies script version
x-kpsdk-r   (rotation)    ──► "N-AAAA" — rotation identifier
x-kpsdk-ct  (client token) ─► ~190 char opaque blob (fingerprint, ~30min life)
x-kpsdk-cd  (client data)  ─► JSON {workTime,id,answers,duration,d,st,rst} (<5s, single-use)
x-kpsdk-h   (HMAC)        ──► Server-computed, received from /mfc response (not client-computed)
x-kpsdk-fc  (feature config) ─► base64 JSON {"featureFlags":{}} (from /mfc)
x-kpsdk-im  (interrogation) ─► interrogation metadata
x-kpsdk-dt  (data)        ─► additional data
```

---

## 3. THE SCRIPT DELIVERY LAYER

### URL Pattern
```
https://<CDN>/<tenant-uuid>/<rotation-uuid>/p.js
```

### Example (Twitch)
```
https://k.twitchcdn.net/149e9513-01fa-4fb0-aad4-566afd725d1b/2d206a39-8ed7-437e-a3be-862e0f06eea3/p.js
```

- **Tenant UUID** (`149e9513-...`): Identifies the Kasada customer (Twitch). This is baked into the script's string table. Same across rotations.
- **Rotation UUID** (`2d206a39-...`): Changes with each script version. Controls the bytecode layout, cipher offsets, and handler order.
- **CDN host**: `k.twitchcdn.net` for Twitch (a CNAME to Kasada's edge)

### What Rotates
When Kasada pushes a new version:
1. New rotation UUID in the URL
2. Bytecode is re-encoded (different alphabet ordering, different string table offset)
3. Cipher key K may change (currently 41, but could be any value 1-63)
4. Handler table order may be shuffled (opcode renumbering)
5. String table contents may change (new detection logic, new properties)
6. Version string increments (j-1.2.NNN)

### What Does NOT Rotate
1. The fundamental VM architecture (tag system, frame management, scope chains)
2. The PoW algorithm structure (tp-v2-input prefix, SHA-256, difficulty formula)
3. The token system (CT/CD/H/V/R headers)
4. The handshake endpoints (/fp, /tl, /mfc)
5. The tenant UUID

### Fetching the Script
```bash
curl -o p.js "https://k.twitchcdn.net/<tenant>/<rotation>/p.js" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36..." \
  -H "Referer: https://www.twitch.tv/" \
  -H "Origin: https://www.twitch.tv"
```

The script is served as `application/javascript; charset=utf-8`, ~157KB.

---

## 4. THE TLS/JA3 FINGERPRINT LAYER

### Why TLS Matters
Before the JavaScript even runs, Kasada's edge inspects the TLS ClientHello packet. Different HTTP clients produce different TLS fingerprints:

| Client | JA3 Hash | Detected as |
|--------|----------|-------------|
| Chrome (real) | `771,4865-4866-4867...` | Legitimate browser |
| Node.js fetch | `771,4865-4866-4867...` (different cipher order) | Bot |
| Python requests | Different again | Bot |
| curl | Different again | Bot |

### How to Defeat It
You must impersonate a real browser's TLS handshake. Options:

1. **`impit`** (Rust library, used by B00H0O) — Impersonates Chrome's TLS fingerprint at the socket level
2. **`curl-impersonate`** — Patched curl that mimics browser TLS
3. **`utls`** (Go library) — Low-level TLS fingerprint spoofing
4. **Real browser** (Playwright/Puppeteer with stealth) — Uses the browser's real TLS stack

### Why This Matters for Reversing
The CT token is **bound to the TLS fingerprint** that generated it. If you mint a CT with one TLS fingerprint and use it from another, the server rejects it. This means:
- You cannot mint CTs with Python `requests` and use them with `curl`
- You must use the **same TLS client** for both minting and using tokens
- `impit` + residential proxy is the current best approach for browserless minting

---

## 5. THE JAVASCRIPT VM (p.js)

### High-Level Structure

The 157KB `p.js` is a single IIFE (Immediately Invoked Function Expression) with three sections:

```
"use strict";(function(){
  // SECTION 1: Bytecode decoder + encoded payload (0-144K chars)
  var A = function(r,v,f) { /* variable-length int decoder */ };
  var H = "zlvDvQvKvtvHv...";  // 144,123-char encoded bytecode

  // SECTION 2: VM implementation (144K-157K chars)
  var c = "length";
  var t = A(H, alphabet, 39);    // decode bytecode → 76,487 ints
  var f = t[c];                   // f = t.length
  // ... string table extraction ...
  // ... 87 opcode handlers ...
  // ... frame management ...
  // ... operand decoder ...
  function U(e) { /* VM dispatch loop */ }
  U(I);                           // start execution

  // SECTION 3: Regenerator runtime (interleaved)
  // Babel's regenerator-runtime for async/generator support
})();
```

### The Decoder Function A()

```javascript
var A = function(r, v, f) {
  // r = encoded string (H)
  // v = alphabet (70 chars)
  // f = base offset (39)
  var l = v.length,      // 70
      a = l - f,         // 31 (continuation radix)
      p = [],            // output array
      x = 0,             // position in r
      n = new Map();     // char → index map
  for (var u = 0; u < l; u++) n.set(v[u], u);

  for (; x < r.length;) {
    for (var h = 0, t = 1;;) {
      var M = n.get(r[x++]) || 0;
      if (M < f) {                    // terminal: M < 39
        h += t * M;
        p.push(h | 0);                // push as int32
        break;
      } else {                        // continuation: M >= 39
        h += t * (M % f + f);
        t *= a;                       // multiply by radix 31
      }
    }
  }
  return p;
};
```

**How it works**: This is a variable-length integer encoding (similar to LEB128 but with a custom alphabet). Each character in `H` maps to an index 0-69 in the alphabet. If the index is < 39, it's a terminal digit. If >= 39, it's a continuation digit (base-31).

### The Alphabet
```
3lYDGQrK~tvHP<cUnS+5f9Nu|kyowRZ$Mq0p=AbLEz2eVdmgaCh46x7FTXBWsIJjOi81>^
```
70 characters, base offset f=39, continuation radix = 70-39 = 31.

### Python Port
```python
def decode_bytecode(r, v, f):
    l = len(v); a = l - f
    n = {ch: i for i, ch in enumerate(v)}
    p = []; x = 0
    while x < len(r):
        h = 0; t = 1
        while True:
            if x >= len(r): break
            M = n.get(r[x], 0); x += 1
            if M < f:
                h += t * M; p.append(h | 0); break
            else:
                h += t * (M % f + f); t *= a
    return p
```

---

## 6. BYTECODE FORMAT & ENCODING

### Decoded Bytecode
- **76,487 integers** (from the 144,123-char H string)
- Values range from 0 to 4,292,870,144 (fits in uint32)
- The bytecode contains THREE regions:
  1. **Program code** (indices 0-1926): VM instructions
  2. **String table** (indices 1927-8203): encoded string pool
  3. **More program code** (indices 8204-76486): VM instructions + data

### String Table Extraction (Runtime)
```javascript
var c = "length";
var t = A(H, alphabet, 39);     // 76,487 ints
var f = t[c];                    // f = t.length = 76487
var L = "";                      // L is empty at this point!
var p = f + (L + true)[c];      // p = 76487 + "true".length = 76487 + 4 = 76491
// L is generated AFTER p (28 random lowercase chars)
// L.indexOf(".") = -1 (no dot in random letters)
var m = t[f + L.indexOf(".")] ^ p;  // m = t[76487 + (-1)] ^ 76491
                                      // m = t[76486] ^ 76491
                                      // m = 77132 ^ 76491 = 1927
var K = t.splice(m, t[m + I.o[0]] + 2);  // splice(1927, t[1928] + 2)
                                           // splice(1927, 84 + 2) = splice(1927, 86)
P.Q = g(K, I.o[1].o, y);          // decode the 86-int string table
```

**Key insight**: The string table location is self-referential — it's computed from the last element of the bytecode XORed with the length. This means each version has a different string table location.

### After Splice
- **Program bytecode**: 76,487 - 86 = 76,401... wait, actually 70,210 after proper extraction
- The splice removes 86 ints starting at index 1927
- Remaining: `t[0:1927] + t[2013:]` = 70,210 ints

---

## 7. STRING TABLE & CIPHER

### String Table Contents
- **6,275 characters** of decoded strings
- Contains ALL string literals used by the VM: property names, error messages, header names, endpoint paths, regex patterns, library constants

### The Cipher
Each character in an inline string is encoded as:
```javascript
String.fromCharCode(S & 4294967232 | S * 41 & 63)
```

**Decoded**:
```python
def decode_char(S, K=41):
    return chr((S & 0xFFFFFFC0) | ((S * K) & 63))
```

This is an **affine cipher on the low 6 bits**:
- The high bits (bits 6-31) are preserved: `S & 0xFFFFFFC0`
- The low 6 bits are transformed: `(S * 41) & 63`
- K=41 is coprime to 64 (gcd(41,64)=1), so it's a bijection on 6-bit values

### Finding K for a New Version
If K changes in a future version, you can find it by:
1. Decode the bytecode
2. Find string operands (tag=30, followed by length + chars)
3. Try all K values 1-63
4. For each K, decode strings and check for known terms ("navigator", "fetch", "x-kpsdk")
5. The K that produces the most known terms is correct

### String Table Access (in VM)
Strings in the program bytecode reference the string table by offset+length:
```
tag=30, length, offset → P.Q.slice(offset, offset+length)
```

This means the same string can be referenced multiple times without duplication.

### Key Strings in the Table

| String | Offset | Significance |
|--------|--------|--------------|
| `tp-v2-input` | 214 | PoW seed prefix |
| `x-kpsdk-cd` | 2869 | CD header name |
| `x-kpsdk-ct` | 4236 | CT header name |
| `x-kpsdk-h` | 1176 | HMAC header name |
| `x-kpsdk-v` | 5403 | Version header |
| `x-kpsdk-r` | 2229 | Rotation header |
| `sha256` | 1231 | Hash function name |
| `sha224` | 3646 | SHA-224 variant |
| `hmac` | 3763 | HMAC function |
| `createHash` | 5608 | Hash factory |
| `setUint32` | 2148 | DataView write |
| `DataView` | — | Binary manipulation |
| `Uint8Array` | 12791 | Byte array type |
| `digest` | 1346 | Hash output |
| `finalize` | 1587 | Hash finalization |
| `workTime` | 1725 | CD field |
| `answers` | 999 | CD field (PoW solutions) |
| `duration` | 876 | CD field |
| `cryptoChallengeEnabled` | 3591 | PoW toggle |
| `validUntil` | 537 | Token expiry |
| `dynamicConfig` | 1187 | Server config |
| `seqNum` | 563 | Sequence number |
| `marker` | 3585 | Timing marker |
| `kpsdkCd` | 5097 | CD variable |
| `kpsdkCt` | 207 | CT variable |
| `JS_SHA256_NO_NODE_JS` | 437 | Node detection |
| `JS_SHA256_NO_WINDOW` | — | Window detection |
| `interrogation` | 2504 | Challenge phase |
| `encodedClientToken` | ~2880 | CT internal name |
| `KP_RC` | ~2875 | Internal config key |

### Obfuscated Property Names
The VM uses short (3-letter) property names that are NOT standard JavaScript. These are Kasada's internal variable names, stored in the string table:

| Name | Meaning |
|------|---------|
| `exn` | PoW seed (starts as "tp-v2-input") |
| `vxn` | **VM-internal secret** (the unsolved value) |
| `qdw` | Difficulty threshold (= 10) |
| `xqn` | Round count (= 2) |
| `ykj` | Hash accumulator / loop counter |
| `rlg` | Answer array reference |
| `nzv` | Interrogation completion flag |
| `ebq` | Hash state |
| `fnq` | Hash state |
| `mh` | Hash state |
| `dw` | Difficulty value |
| `uh` | Unknown (near kpsdkV) |

---

## 8. THE 87-OPCODE VM ISA

### Handler Table Construction
The 87 opcodes are defined as a JavaScript array wrapped in a `Proxy`:

```javascript
u = new Proxy([
  function(n,e,a){a(n,e(n)[e(n)])},           // op 0: property access
  function(n,e){var a=e(n);n.o[1].l=a},       // op 1: set jump target
  function(n,e,a,v,i,r){var o=r[5];a(n,o(n)/e(n))}, // op 2: divide
  // ... 84 more handlers ...
], { /* proxy handler with identity permutation Array.from({length:87}, (n,r)=>r) */ });
```

**NOTE:** Naive regex splitting on `,(?=function()` produces 89 handlers — this is WRONG.
Handler 55 (method_call) contains an inner `function(){return arguments}` literal that
gets incorrectly split. Proper balanced-brace parsing yields exactly 87 handlers.
The Proxy's get handler uses `Array.from({length:87})` as the permutation table,
confirming 87 valid opcodes (0-86).

### Handler Arguments
Each handler receives 6 arguments:
```javascript
function(n, e, a, v, i, r)
```

| Arg | Name | Purpose |
|-----|------|---------|
| `n` | frame | The current VM frame (has `.o` = register array, `.n` = exception) |
| `e` | read_operand | Function: `e(n)` reads next operand from bytecode |
| `a` | store_result | Function: `a(n, value)` stores result in frame register |
| `v` | read_variable | Function: `v(n)` reads a variable from scope chain |
| `i` | runtime | Array: `[O, [M,W], t, u]` = [window, [Promise,resolve], bytecode, handlers] |
| `r` | functions | Array: `[X, D, h, U, L, j]` = [throw, catch, frame, dispatch, rand, pop] |

### `r[]` Function Table
| Index | Name | Purpose |
|-------|------|---------|
| 0 | `X` | Throw exception |
| 1 | `D` | Catch/propagate exception |
| 2 | `h` | Create new frame |
| 3 | `U` | VM dispatch (recursive) |
| 4 | `L` | Random string (28 chars) |
| 5 | `j` | Pop/get top of stack |

### Complete Opcode Table

| Op | Arity | Semantics | Handler Code |
|----|-------|-----------|-------------|
| 0 | 2 | Property get: `obj[key]` | `a(n, e(n)[e(n)])` |
| 1 | 1 | Set loop target: `frame.l = val` | `n.o[1].l = e(n)` |
| 2 | 1 | Divide: `pop / operand` | `a(n, o(n) / e(n))` |
| 3 | 1 | XOR: `operand ^ pop` | `a(n, e(n) ^ o(n))` |
| 4 | 1 | Set catch handler: `frame.i = val` | `n.o[1].i = e(n)` |
| 5 | 2 | Scope store: `scope[idx] = val` | `r.s[i] = o` |
| 6 | 3 | Call 2-arg: `fn(arg1, arg2)` | `a(n, v(i, r))` |
| 7 | 1 | Not-equal: `pop != operand` | `a(n, o(n) != e(n))` |
| 8 | 1 | In: `operand in pop` | `a(n, e(n) in o(n))` |
| 9 | 0 | Bitwise OR: `pop | pop` | `a(n, o(n) | o(n))` |
| 10 | 2 | Declare scope var | `scope[idx] = val` |
| 11 | 1 | New array: `new Array(n)` | `a(n, new Array(e(n)))` |
| 12 | 0 | Less-than: `pop < pop` | `a(n, o(n) < o(n))` |
| 13 | 1 | Greater-than: `pop > operand` | `a(n, o(n) > e(n))` |
| 14 | 2 | Scope delete + try/catch setup | Complex |
| 15 | 1 | Less-than: `pop < operand` | `a(n, o(n) < e(n))` |
| 16 | 1 | Typeof: `typeof operand` | `a(n, typeof e(n))` |
| 17 | 0 | Divide: `pop / pop` | `a(n, o(n) / o(n))` |
| 18 | 2 | Try/catch/finally dispatch | Complex |
| 19 | 3 | Scope store: `scope[idx] = val` | `o.s[i] = r` |
| 20 | 0 | New object: `{}` | `a(n, {})` |
| 21 | 1 | Subtract: `pop - operand` | `a(n, o(n) - e(n))` |
| 22 | 0 | Multiply: `pop * pop` | `a(n, o(n) * o(n))` |
| 23 | 1 | Strict not-equal: `operand !== pop` | `a(n, e(n) !== o(n))` |
| 24 | 1 | Strict not-equal: `pop !== operand` | `a(n, o(n) !== e(n))` |
| 25 | 1 | Modulo: `pop % operand` | `a(n, o(n) % e(n))` |
| 26 | 0 | XOR: `pop ^ pop` | `a(n, o(n) ^ o(n))` |
| 27 | 1 | Add: `operand + pop` | `a(n, e(n) + o(n))` |
| 28 | 3 | Scope chain lookup | Walk scope chain |
| 29 | 4 | Call 3-arg: `fn(a, b, c)` | `a(n, v(i, r, o))` |
| 30 | 0 | Strict equal: `pop === pop` | `a(n, o(n) === o(n))` |
| 31 | 1 | Not-equal: `operand != pop` | `a(n, e(n) != o(n))` |
| 32 | 1 | Bitwise AND: `pop & operand` | `a(n, o(n) & e(n))` |
| 33 | 1 | Multiply: `pop * operand` | `a(n, o(n) * e(n))` |
| 34 | 2 | Save try state | `r.s[i] = {r:T, v:P, u:e}` |
| 35 | 1 | Bitwise NOT: `~operand` | `a(n, ~e(n))` |
| 36 | 0 | Get Promise: `i[1][0]` | `a(n, i[1][0])` |
| 37 | 3 | Property set: `obj[key] = val` | `e(n)[e(n)] = e(n)` |
| 38 | 2 | Bitwise OR: `operand | operand` | `a(n, e(n) | e(n))` |
| 39 | 1 | Get runtime: `i[0][operand]` | `a(n, i[0][e(n)])` |
| 40 | 1 | Bitwise OR: `operand | pop` | `a(n, e(n) | o(n))` |
| 41 | 0 | Add: `pop + pop` | `a(n, o(n) + o(n))` |
| 42 | 2 | Store exception state | `r.s[i] = n.n; n.n = void 0` |
| 43 | 2 | Add: `operand + operand` | `a(n, e(n) + e(n))` |
| 44 | 1 | Greater-equal: `pop >= operand` | `a(n, o(n) >= e(n))` |
| 45 | 2 | Delete property | `a(n, delete v[i])` |
| 46 | 0 | In: `pop in pop` | `a(n, o(n) in o(n))` |
| 47 | 1 | Unsigned right shift: `pop >>> operand` | `a(n, o(n) >>> e(n))` |
| 48 | 1 | Logical NOT: `!operand` | `a(n, !e(n))` |
| 49 | 0 | New array: `[]` | `a(n, [])` |
| 50 | 0 | Modulo: `pop % pop` | `a(n, o(n) % o(n))` |
| 51 | 2 | Function bind/construct | `new (Function.bind.apply(...))` |
| 52 | 1 | Identity: `operand` | `a(n, e(n))` |
| 53 | 0 | Left shift: `pop << pop` | `a(n, o(n) << o(n))` |
| 54 | 1 | Unary plus: `+operand` | `a(n, +e(n))` |
| 55 | 3 | Method call with scope | Complex |
| 56 | 0 | Yield/return value | Returns from handler |
| 57 | 2 | Scope chain read | Walk scope chain for var |
| 58 | 0 | Greater-than: `pop > pop` | `a(n, o(n) > o(n))` |
| 59 | 1 | Add: `pop + operand` | `a(n, o(n) + e(n))` |
| 60 | 4 | Complex call with try/catch | Complex |
| 61 | 0 | Proxy .get result | Returns from proxy handler |
| 62 | 1 | Divide: `operand / pop` | `a(n, e(n) / o(n))` |
| 63 | 0 | Subtract: `pop - pop` | `a(n, o(n) - o(n))` |
| 64 | 2 | New RegExp: `new RegExp(pat, flags)` | `a(n, new RegExp(e(n), e(n)))` |
| 65 | 2 | Subtract: `operand - operand` | `a(n, e(n) - e(n))` |
| 66 | 2 | Loose equal: `operand == operand` | `a(n, v == i)` |
| 67 | 1 | Throw: `X(frame, val)` | `o(n, l)` |
| 68 | 2 | Call 1-arg: `fn(arg)` | `a(n, v(i))` |
| 69 | 0 | Throw undefined | `o(n, void 0)` |
| 70 | 0 | Instanceof: `pop instanceof pop` | `a(n, o(n) instanceof o(n))` |
| 71 | 1 | Call 0-arg: `fn()` | `a(n, v())` |
| 72 | 0 | Get exception: `n.n && n.n.Z` | `a(n, n.n && n.n.Z)` |
| 73 | 0 | Get Promise resolve: `i[1][1]` | `a(n, i[1][1])` |
| 74 | 0 | Return null | `return null` (halts VM) |
| 75 | 1 | Strict equal: `operand === pop` | `a(n, e(n) === o(n))` |
| 76 | 1 | Set PC: `frame.o[0] = operand` | `n.o[0] = e(n)` (JUMP) |
| 77 | 1 | Left shift: `pop << operand` | `a(n, o(n) << e(n))` |
| 78 | 0 | Bitwise AND: `pop & pop` | `a(n, o(n) & o(n))` |
| 79 | 0 | Greater-equal: `pop >= pop` | `a(n, o(n) >= o(n))` |
| 80 | 1 | Less-equal: `pop <= operand` | `a(n, o(n) <= e(n))` |
| 81 | 1 | Loose equal: `operand == pop` | `a(n, e(n) == o(n))` |
| 82 | 0 | Clear exception | `n.n = void 0` |
| 83 | 0 | Get window: `frame.o[1].h` | `a(n, n.o[1].h)` |
| 84 | 0 | Strict not-equal: `pop !== pop` | `a(n, o(n) !== o(n))` |
| 85 | 3 | Conditional jump: `if(val) PC = val` | `e(n) ? n.o[0] = e(n) : e(n)` |
| 86 | 1 | Strict equal: `pop === operand` | `a(n, o(n) === e(n))` |
| 87 | 1 | Catch: `D(frame, val)` | `o(n, l)` |
| 88 | 3 | Conditional: `if(val) val else PC = val` | `e(n) ? e(n) : n.o[0] = e(n)` |

### Key Opcodes for Reversing
- **OP_76** = JUMP (sets the program counter directly)
- **OP_85** = CONDITIONAL JUMP (if true, set PC)
- **OP_88** = CONDITIONAL (ternary-like)
- **OP_0** = PROPERTY ACCESS (most common, used for all `obj.prop`)
- **OP_37** = PROPERTY SET (used for all `obj.prop = val`)
- **OP_28** = SCOPE LOOKUP (variable resolution)
- **OP_5/10/19** = SCOPE STORE (variable assignment)
- **OP_6/29/68/71** = FUNCTION CALLS
- **OP_51** = FUNCTION CONSTRUCTION
- **OP_55** = METHOD CALL (with `this` binding)
- **OP_67/87** = THROW
- **OP_18** = TRY/CATCH/FINALLY

---

## 9. OPERAND DECODING

### The Operand Decoder `g()`
```javascript
var g = function(r, v, f, l) {
  var a = r[v[0]++];           // read next int from bytecode at PC
  if (a & 1) return a >> 1;    // ODD → small integer (val >> 1)

  if (a !== f[5]) {            // not void (26)
    if (a === f[0]) {          // double (4)
      // Read 2 ints as IEEE 754 double
      var p = r[v[0]++], x = r[v[0]++];
      var n = p & 0x80000000 ? -1 : 1;     // sign
      var u = (p & 0x7FF00000) >> 20;       // exponent
      var h = (p & 0xFFFFF) * Math.pow(2,32) + (x < 0 ? x + Math.pow(2,32) : x);
      // ... IEEE 754 decoding ...
      return n * h * Math.pow(2, u - 1075);
    }
    if (a === f[1]) return null;           // null (40)
    if (a === f[3]) return false;          // false (16)
    if (a === f[2]) {                      // string (30)
      if (l != null && l.g) {
        // String table reference: P.g(length, offset)
        return l.g(r[v[0]++], r[v[0]++]);
      }
      // Inline string: length + chars (with cipher)
      var t = "", M = r[v[0]++];
      for (var I = 0; I < M; I++) {
        var S = r[v[0]++];
        t += String.fromCharCode(S & 4294967232 | S * 41 & 63);
      }
      return t;
    }
    return a === f[4] ? true : v[a >> 5];  // true (20) or register R[a>>5]
  }
};
```

### Tag Array
```javascript
var y = [4, 40, 30, 16, 20, 26];
//         │   │   │   │   │   └─ void
//         │   │   │   │   └───── true
//         │   │   │   └───────── false
//         │   │   └───────────── string
//         │   └───────────────── null
//         └───────────────────── double
```

### Operand Types Summary

| Encoding | Type | How to read |
|----------|------|-------------|
| `a & 1 == 1` | Small int | Value = `a >> 1` (range: 0 to ~2^30) |
| `a == 4` | Double | Read 2 more ints as IEEE 754 hi/lo words |
| `a == 40` | Null | No more data |
| `a == 30` (with `l.g`) | String ref | Read 2 ints: length, offset → `P.Q.slice(offset, offset+length)` |
| `a == 30` (without `l.g`) | Inline string | Read 1 int (length), then `length` ints (chars, cipher K=41) |
| `a == 16` | False | No more data |
| `a == 20` | True | No more data |
| `a == 26` | Void | No more data |
| Other even | Register | `R[a >> 5]` (register index) |

### Register File
The frame's register file is `frame.o`:
- `frame.o[0]` = Program Counter (PC)
- `frame.o[1]` = Frame metadata (scope info, jump targets)
- `frame.o[2]` = Exception handler info
- `frame.o[3]` = Arguments array
- `frame.o[4+]` = General-purpose registers

Register index is extracted as `a >> 5` (top 27 bits of the even value).

---

## 10. FRAME MANAGEMENT & SCOPE CHAINS

### Frame Structure
```javascript
function h() {
  var e = [
    1,                                    // o[0]: PC (start at instruction 1)
    {h: O, a: null, s: [], o: [0], m: void 0}, // o[1]: scope metadata
    void 0                                // o[2]: exception info
  ];
  return {o: e, n: void 0};              // {o: registers, n: exception}
}
```

### Scope Metadata (`frame.o[1]`)
```javascript
{
  h: O,        // host (window object)
  a: null,     // parent scope (for chain lookup)
  s: [],       // scope variables (array)
  o: [0],      // inner PC for nested execution
  m: void 0,   // scope chain link (for closures)
  l: undefined, // loop/jump target
  i: undefined, // catch handler index
  T: undefined, // try-block saved state
  P: undefined, // finally-block PC
  e: undefined, // finally counter
}
```

### Scope Chain (OP_28)
```javascript
// OP_28: scope chain lookup
function(n, e, a, v) {
  for (var i = e(n), r = e(n), o = v(n); o; o = o.m) {
    if (i in o.s) {
      o.s[i] = r;  // found: update value
      return;
    }
  }
}
```

The scope chain walks `o.m` links (closure parents) looking for a variable. This is how the VM implements JavaScript's lexical scoping.

### Exception Handling (OP_18)
```javascript
// OP_18: try/catch/finally
function(n, e, a, v, i, r) {
  var o = r[0],    // throw function (X)
      l = r[1],    // catch function (D)
      _ = e(n),    // try block index
      u = v(n),    // scope reference
      h = u?.s[_]; // saved state

  // If exception: restore state, call catch
  // If finally: jump to finally block
  // Complex control flow management
}
```

---

## 11. THE FINGERPRINT COLLECTION LAYER

### What the VM Collects
The VM probes the browser environment extensively. Based on the string table, it accesses:

#### Browser APIs
```
navigator.userAgent          → Chrome version string
navigator.platform          → "Win32"
navigator.hardwareConcurrency → CPU cores
navigator.deviceMemory      → RAM in GB
navigator.languages         → Language preferences
navigator.plugins           → Plugin list
navigator.doNotTrack        → DNT setting
navigator.cookieEnabled     → Cookie support
navigator.maxTouchPoints    → Touch capability
```

#### WebGL Fingerprinting
```
WebGLRenderingContext.getParameter(VERSION)           → "WebGL 1.0"
WebGLRenderingContext.getParameter(VENDOR)            → "Google Inc. (NVIDIA)"
WebGLRenderingContext.getParameter(RENDERER)          → "ANGLE (NVIDIA GeForce RTX 3060)"
WebGLRenderingContext.getSupportedExtensions()        → Extension list
WebGLRenderingContext.getParameter(SHADING_LANGUAGE_VERSION) → GLSL version
```

#### Canvas Fingerprinting
```
CanvasRenderingContext2D.fillText()                   → Draw text
CanvasRenderingContext2D.measureText()                → Text metrics
HTMLCanvasElement.toDataURL()                         → Pixel hash
CanvasRenderingContext2D.getImageData()               → Raw pixels
```

#### Environment Detection
```
window.chrome                  → Chrome-specific object
window.outerWidth/outerHeight  → Window dimensions
screen.width/height            → Screen resolution
screen.colorDepth              → Color depth
devicePixelRatio               → Pixel ratio
Intl.DateTimeFormat().resolvedOptions().timeZone → Timezone
performance.now()              → High-resolution timer
performance.timing             → Navigation timing
```

#### Anti-Headless Checks
```
fetch.toString()               → Must contain "[native code]"
XMLHttpRequest.toString()      → Must contain "[native code]"
window.webdriver               → Must be undefined/false
document.createElement('canvas').toDataURL() → Must produce valid data
navigator.webdriver            → Must be undefined
```

#### Node.js Detection (from string table)
```
JS_SHA256_NO_NODE_JS    → Checks for Node.js process object
JS_SHA256_NO_WINDOW     → Checks for window object
JS_SHA256_NO_ARRAY_BUFFER → Checks for ArrayBuffer
JS_SHA256_NO_BUFFER_FROM → Checks for Buffer.from
JS_SHA256_NO_COMMON_JS   → Checks for require/module
```

### How to Fake It (B00H0O's Approach)
1. Use `happy-dom` for basic DOM
2. Override `navigator` properties with Chrome values
3. Stub WebGL `getParameter` with NVIDIA GPU strings
4. Proxy canvas methods to no-op + fixed `toDataURL`
5. Override `fetch.toString()` to return `"function fetch() { [native code] }"`
6. Hide Node.js globals (`process`, `require`, `module`, `Buffer`)
7. Use `impit` for real TLS-impersonated network requests

---

## 12. THE CT TOKEN (CLIENT TOKEN)

### What CT Is
- **~190 character opaque encrypted blob**
- Generated by the **server** at the `/tl` endpoint
- Carries the browser fingerprint (encrypted)
- Bound to: IP address + User-Agent + TLS fingerprint
- Lifetime: ~30 minutes
- Reusable across multiple requests within its lifetime

### How CT Is Generated
```
1. VM collects browser fingerprint (WebGL, canvas, navigator, etc.)
2. VM POSTs fingerprint blob to /tl endpoint
3. Server validates fingerprint:
   - Checks for headless/browser automation tells
   - Checks TLS fingerprint consistency
   - Checks IP reputation
4. If valid: server encrypts fingerprint + metadata → returns as x-kpsdk-ct header
5. VM stores CT in window.KPSDK.ct
```

### The /tl Endpoint
```
POST /tl HTTP/1.1
Host: k.twitchcdn.net
Content-Type: application/json
x-kpsdk-v: j-1.2.522

<fingerprint blob>

HTTP/1.1 200 OK
x-kpsdk-ct: <190-char base64 token>
x-kpsdk-st: <server timestamp>
x-kpsdk-r: <rotation id>
```

### CT Binding
The CT is cryptographically bound to:
1. **TLS fingerprint** (JA3 hash of the connection that minted it)
2. **IP address** (the proxy/residential IP used)
3. **User-Agent** (must match what was sent during minting)

**You cannot mint a CT on one connection and use it from another.** This is why B00H0O uses `impit` (TLS impersonation) + residential proxy for both minting and using.

### Browserless CT Generation (SOLVED by B00H0O)
```
1. Set up Node.js + happy-dom + impit
2. Load decompiled p.js (Emrovsky's decomp.js)
3. Fake all browser APIs (navigator, WebGL, canvas, fetch)
4. Forward /tl request through impit + residential proxy
5. Server validates fingerprint → returns real x-kpsdk-ct
6. CT is now valid for ~30 minutes from the same IP+UA+TLS
```

### Why This Works
The server can't fully distinguish a faked browser from a real one because:
- The TLS fingerprint matches Chrome (via impit)
- The UA string matches Chrome
- The fingerprint blob contains consistent GPU/canvas/navigator data
- The IP is residential (via proxy)
- `fetch.toString()` looks native

The remaining detection vectors (canvas pixel-level analysis, WebGL rendering differences) are mitigated by returning fixed but plausible values.

---

## 13. THE CD TOKEN (CLIENT DATA / PROOF-OF-WORK)

### What CD Is
- **Small JSON object**: `{"workTime":..., "id":..., "answers":[...], "duration":..., "d":..., "st":..., "rst":...}`
- Generated **client-side** by the VM (or offline — no server secret needed!)
- `answers` = array of mining TIMING values per round (ms), NOT nonces
- `d` = total attempt count, NOT difficulty
- `workTime` = completion timestamp (ms since epoch), NOT duration
- Lifetime: **<5 seconds** (single-use, must be fresh)
- NOT cryptographically bound to any server secret — the PoW uses a random nonce

### The PoW Algorithm (FULLY REVERSED & VERIFIED)

#### Parameters (set at bytecode addr 46274-46286)
```
qdw = 10    → difficulty (number of leading zero BITS required in hash)
xqn = 2     → number of hash rounds (chained iterations)
```

#### Seed & State Initialization (addr 46303-46322)
```javascript
state = {
    exn: "tp-v2-input",       // hardcoded seed prefix
    vxn: {qdw:10, xqn:2, zsr:""}  // PoW parameters object (NOT a secret!)
}
// Stored in scope[398]
```

#### Mining Loop (addr 46334-46484)
```python
# CORRECT pseudocode (verified against real tokens)
answers = []        # timing values per successful round
attempt_count = 0
start_time = now()

while True:
    nonce = random_hex(32)    # 32-char random hex string
    nonce_prefix = nonce[0:16]  # first 16 hex chars

    # Round 1: hash = SHA-256("tp-v2-input" + nonce_prefix)
    hash_input = "tp-v2-input" + nonce_prefix
    hash_result = sha256(hash_input)  # returns hex string

    # Round 2: hash = SHA-256(round1_hash + nonce_prefix)
    hash_input = hash_result + nonce_prefix
    hash_result = sha256(hash_input)

    attempt_count += 1

    # Difficulty check: first 10 bits of hash must be zero
    if leading_zero_bits(hash_result) >= qdw:  # qdw = 10
        round_time = now() - start_time
        answers.append(round_time)  # timing in ms
        break
```

#### Difficulty Check (Leading Zero Bits)
```
qdw = 10 means the SHA-256 output must start with 10 zero bits.

In hex: first 2.5 hex chars must form a value < 0x0040
  - "003..." = binary 0000 0000 0011... = 10 leading zeros ✓
  - "001..." = binary 0000 0000 0001... = 14 leading zeros ✓
  - "004..." = binary 0000 0000 0100... = 6 leading zeros ✗

Probability per hash: 1 / 2^10 = 1/1024
Expected hashes to find solution: ~1024
At ~500K hashes/sec in JS: ~2ms expected per round

Verified: Real CD shows d=1233 attempts, duration=101.7ms (2 rounds)
```

#### CD Token Construction (from zfn function at addr 46876)
```json
{
  "workTime": 1783001197516,    // timestamp when mining COMPLETED (ms since epoch)
  "id": "8fe05a7065dedaa8c7e5a3b05b0a41cb",  // 32-char random hex ID
  "answers": [11, 1],           // mining time per round (ms) - NOT nonces!
  "duration": 101.7,            // total mining duration (ms, floating point)
  "d": 1233,                    // total number of ATTEMPTS (not difficulty!)
  "st": 1783001182942,          // start timestamp (ms since epoch)
  "rst": 1783001184175          // round start timestamp (ms since epoch)
}
```

**KEY CORRECTIONS vs earlier analysis:**
- `workTime` = completion timestamp (NOT duration)
- `answers` = timing per round in ms (NOT nonce values)
- `d` = total attempt count (NOT difficulty threshold)
- `duration` = total time as float (was missing from initial analysis)

### Why CD CAN Be Forged (vxn is SOLVED)

The PoW seed is simply:
```
hash_input = "tp-v2-input" + random_nonce[0:16]
```

**`vxn` is NOT a secret string in the hash input.** It is the PoW parameters object
`{qdw:10, xqn:2, zsr:""}` that controls difficulty and rounds. The actual hash
computation only uses the fixed seed "tp-v2-input" and a random nonce.

This means **CD can be forged completely offline** — you just need to:
1. Generate random nonces
2. Hash them with SHA-256 (2 rounds)
3. Check for 10 leading zero bits
4. Format the CD JSON with plausible timing values

The `zsr` field (from dynamicConfig/tl response) may update the PoW params
but does NOT change the fundamental hash input formula.

### What B00H0O Got Wrong

B00H0O's brute-force tested `sha256("tp-v2-input" + X)` with various wire-visible
values for X. The reason nothing matched is that **X is a random nonce generated
fresh each time** — it's not derived from any captured value. The answers in the CD
are timing measurements, not the nonces themselves. The server validates the CD by
checking that the timing/attempt values are plausible for the stated difficulty,
NOT by re-computing the hash (the server doesn't know the nonce).

---

## 14. THE HMAC HEADER (x-kpsdk-h) — SOLVED

### Critical Finding: x-kpsdk-h is SERVER-COMPUTED, NOT CLIENT-COMPUTED

**The `x-kpsdk-h` header value is received from the Kasada server (via the `/mfc`
endpoint response headers) and simply echoed back on subsequent protected requests.**

The client does NOT compute the HMAC. The server computes it and sends it to the client.

### Evidence from Bytecode Analysis

1. **`sha256.hmac` is set up (addr 22399) but NEVER called** — `prop_get(obj, "hmac")`
   appears zero times in the entire 76K-instruction bytecode.

2. **The value flows from response → storage → request:**
   ```
   /mfc response → headers.get("x-kpsdk-h") → scope[293].gpk → request header
   ```

   Bytecode trace:
   ```
   addr 43009: headers.get("x-kpsdk-h")      // read from /mfc response
   addr 43112: obj.gpk = response_value       // store as "gpk"
   addr 43917: scope[295].jhc([gpk, jqn])     // save signing state pair
   addr 48429: scope[295].uqn().gpk           // retrieve for outbound request
   addr 48495: headers["x-kpsdk-h"] = gpk     // attach to request
   ```

3. **The initial value sent TO /mfc is just "01"** (a protocol version indicator):
   ```
   addr 43159: defineProperty(obj, "x-kpsdk-h", "01")  // sent in /mfc request
   ```
   The "01" prefix in the real value `REDACTED_H_TOKEN` is the
   protocol version — the server includes it in its computed HMAC response.

### The `gpk` Key (Not the HMAC key — it's the HMAC VALUE)

```
gpk (hardcoded default) = "2d71074c6905b27f163a551545a012cabb954b1832bbacb3bf511a79e82879e3"
gpk (live value)         = response from /mfc endpoint's x-kpsdk-h header
```

The hardcoded `gpk` is a FALLBACK/initial value. In practice, it's immediately
replaced by the server's response after the /mfc handshake completes.

### What the Server Computes

The server-side HMAC likely binds:
- The CT token (session identity)
- The TLS fingerprint (connection identity)
- A server-side session secret
- Possibly a timestamp/nonce

The client cannot compute this value because:
- It doesn't know the server's signing secret
- The value changes per /mfc call (session-specific)
- The `sha256.hmac` function in the client is setup but unused

### The `ykj` Key — What It's Actually For

```
ykj = "7ae9906d03439b1173e98ddb9342a718a535ab115a7f27138cd183737d7f7afe"
```

Despite being labeled "HMAC key" in our earlier analysis, `ykj` is used ONLY in:
1. The PoW diagnostic hash (addr 9813-10021): `sha256(exn + ", " + arg + ", " + arg + ykj + zsr)`
2. Passed through the mining closure as metadata (addr 46478)
3. NEVER used in an actual `hmac()` call

It may serve as a challenge-response seed for server-side validation of the CD
token, but the client never computes HMAC with it.

### Implication for Solvers

**You cannot forge `x-kpsdk-h` without talking to the Kasada server.**

The flow MUST be:
1. POST fingerprint to `/tl` → get CT token
2. GET `/mfc` with `{x-kpsdk-h: "01", x-kpsdk-v: version}` → get real x-kpsdk-h value
3. Use that value on all subsequent requests

This means a solver MUST maintain an active session with the Kasada edge.
The CD can be forged offline, but the H header requires the /mfc handshake.

### The Paired Storage: gpk + jqn

The signing state stores a pair `{gpk, jqn}`:
- `gpk` = x-kpsdk-h value (from /mfc response header `x-kpsdk-h`)
- `jqn` = feature config (from /mfc response header `x-kpsdk-fc`, base64-encoded JSON)

Both are refreshed together via the "remote config" polling mechanism (scope[370])
with a 4000ms retry interval (addr 43185: `gxn: 4000`).

---

## 15. THE FULL REQUEST SIGNING FLOW

```
┌─────────────────────────────────────────────────────────────┐
│                  REQUEST SIGNING SEQUENCE                    │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. PAGE LOAD                                                │
│     Browser loads page → downloads p.js → VM boots           │
│                                                              │
│  2. FINGERPRINT COLLECTION                                   │
│     VM probes: navigator, WebGL, canvas, screen, etc.        │
│     Builds fingerprint blob                                  │
│                                                              │
│  3. HANDSHAKE                                                │
│     a. POST /fp (fingerprint page)                           │
│        → Server acknowledges                                 │
│     b. POST /tl (token lookup)                               │
│        → Server returns x-kpsdk-ct (CT token)                │
│        → Server may return encrypted challenge in body       │
│     c. GET /mfc (feature config)                             │
│        → Server returns x-kpsdk-fc (feature flags)           │
│        → Server returns x-kpsdk-h (HMAC value for signing)   │
│        → Client stores gpk + jqn pair in signing state       │
│                                                              │
│  4. STORE TOKENS                                             │
│     window.KPSDK = {                                         │
│       ct: <CT token>,                                        │
│       cd: null,  // will be computed per-request             │
│       v: "j-1.2.522",                                        │
│       r: <rotation>,                                         │
│       fc: <feature config>,                                  │
│       gpk: <x-kpsdk-h from /mfc response>,                  │
│       vxn: {qdw:10, xqn:2, zsr:""}  // PoW params           │
│     }                                                        │
│                                                              │
│  5. REQUEST INTERCEPTION                                     │
│     User triggers fetch/XHR → VM intercepts                  │
│     (p.js monkey-patches fetch and XMLHttpRequest)           │
│                                                              │
│  6. CD GENERATION (per-request)                              │
│     VM runs PoW:                                             │
│       nonce = random_hex(32)                                 │
│       hash = sha256("tp-v2-input" + nonce[0:16])   // rnd 1 │
│       hash = sha256(hash + nonce[0:16])            // rnd 2 │
│       check: leading_zero_bits(hash) >= 10 (qdw)            │
│       retry with new nonce until success                     │
│     CD = {workTime, id, answers, duration, d, st, rst}       │
│                                                              │
│  7. HMAC RETRIEVAL (not computation!)                        │
│     gpk = stored x-kpsdk-h from /mfc response               │
│     (Server-computed; client just echoes it back)            │
│                                                              │
│  8. HEADER INJECTION                                         │
│     fetch/XHR adds:                                          │
│       x-kpsdk-ct: <CT>                                       │
│       x-kpsdk-cd: <CD JSON>                                  │
│       x-kpsdk-h: <gpk from /mfc response>                    │
│       x-kpsdk-v: j-1.2.522                                   │
│       x-kpsdk-r: <rotation>                                  │
│                                                              │
│  9. REQUEST SENT                                             │
│     Kasada edge validates ALL headers:                       │
│       ✓ TLS fingerprint matches CT                          │
│       ✓ CT not expired (<30min)                             │
│       ✓ CD fresh (<5s) and not reused                       │
│       ✓ HMAC matches session (server verifies own token)    │
│       ✓ Version current                                     │
│     If all pass → forward to origin                          │
│     If any fail → 403 block                                  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 16. SHA-256 IMPLEMENTATION INTERNALS

### Library Identification
Kasada uses the **js-sha256** npm package (or a derivative), embedded directly in the VM bytecode.

### Markers Found in String Table
```
JS_SHA256_NO_NODE_JS          → Node.js environment detection
JS_SHA256_NO_WINDOW           → Browser environment detection
JS_SHA256_NO_ARRAY_BUFFER     → ArrayBuffer support check
JS_SHA256_NO_BUFFER_FROM      → Buffer.from support check
JS_SHA256_NO_COMMON_JS        → CommonJS module system check
sha256                        → Main function name
sha224                        → SHA-224 variant
createHash                    → Hash factory method
digest                        → Hash output method
finalize                      → Hash finalization
update                        → Hash update method
hex                           → Hex output format
array                         → Array output format
arrayBuffer                   → ArrayBuffer output format
```

### Constants in Bytecode

#### K[] Round Constants (64 values)
Found at bytecode indices ~13626-13966, encoded as IEEE 754 doubles (tag=4, 3 ints each):

```python
# K[0] = 0x428a2f98 = 1116352408
# As IEEE 754 double: hi=0x41d0a28b, lo=0xe6000000
# In bytecode: [4, 1104192139, -436207616]
```

28 of 64 K[] constants were found via direct double encoding. The remaining 36 are likely:
- Computed at runtime from a compressed representation
- Stored in a different encoding (e.g., as integer operations)
- Generated by the VM's initialization code

#### H[] Initial Hash Values (8 values)
Found at bytecode indices ~12060-12078 (2 of 8 found as doubles):
```
H[0] = 0x6a09e667
H[1] = 0xbb67ae85
H[2] = 0x3c6ef372
H[3] = 0xa54ff53a
H[4] = 0x510e527f
H[5] = 0x9b05688c
H[6] = 0x1f83d9ab
H[7] = 0x5be0cd19
```

#### Difficulty Constant
```
2^52 = 4503599627370496 = 0x10000000000000
Found at bytecode index 9592 as IEEE 754 double: [4, 1127219200, 0]
```

### Implementation Details
- Uses `DataView` and `setUint32` for byte-level manipulation (not `crypto.subtle.digest`)
- This is a **pure JavaScript SHA-256** implementation, not using the Web Crypto API
- The choice of pure JS (rather than `crypto.subtle`) is deliberate:
  - `crypto.subtle.digest` is async (returns a Promise)
  - The PoW loop is synchronous (tight loop, no async overhead)
  - Pure JS is ~10x slower than native, but this is intentional — it's the PoW cost

---

## 17. VXN — SOLVED

### Answer

**`vxn` is NOT a secret.** It is the **PoW parameters object**:

```javascript
vxn = {
    qdw: 10,    // difficulty (leading zero bits required)
    xqn: 2,     // number of hash rounds
    zsr: ""     // server challenge nonce (from dynamicConfig, initially empty)
}
```

### How We Solved It

The previous analysis (B00H0O and others) was wrong because:

1. **OP_56 was misidentified as "yield"** — it's actually `scope_chain_get` (a READ operation)
2. **OP_28 was misidentified as "scope read"** — it's actually `scope_chain_set` (a WRITE operation)
3. **The handler count was wrong (89 vs 87)** — regex splitting broke handler 55

With the correct 87-handler table and proper opcode semantics, the disassembly shows:

```
addr 46272: R5 = {}                          // new object
addr 46274: R5.qdw = 10                      // difficulty
addr 46280: R5.xqn = 2                       // rounds
addr 46286: scope[393] = R5                  // store params
addr 46303: R4 = {}                          // new state object
addr 46305: R4.exn = "tp-v2-input"           // seed
addr 46313: R5 = scope[393]                  // READ BACK the params!
addr 46316: R4.vxn = R5                      // vxn = {qdw:10, xqn:2}
addr 46322: scope[398] = R4                  // store state
```

**vxn is simply read back from the same scope slot where the params were just stored.**
It is NOT derived from any encrypted response or secret computation.

### Why B00H0O's Brute Force Failed

B00H0O tested `sha256("tp-v2-input" + X)` trying to match captured CD answers.
This failed because:

1. The hash input is `"tp-v2-input" + random_nonce[0:16]` — the nonce is random!
2. The CD `answers` field contains TIMING values (milliseconds), NOT nonces
3. The server does NOT re-compute the hash — it validates timing plausibility
4. There is nothing to "match" because the nonce is ephemeral and not stored

### The vxn Update in Mining Loop

In the mining closure (addr 46457-46469):
```
addr 46457: R5 = scope[398]         // read state
addr 46460: R6 = R5.vxn             // get current vxn params
addr 46469: new_state.vxn = R8      // carry forward (or use override from arg2)
```

The vxn object is simply carried forward between iterations. If a new value
is passed as the second argument to the mining closure (non-null), it overrides
the previous vxn. This is how `dynamicConfig` can update difficulty mid-session.

### Dynamic Updates via /tl Response

The `dynamicConfig` from the /tl response (addr 44216) can update the vxn params:
```
scope[283]() → returns state object
state.yzv.ewm → {qdw, xqn, zsr}   // these are the live params
```

When `zsr` gets a non-empty value from the server, it becomes part of the vxn
object but does NOT change the hash input formula. The hash always uses:
```
"tp-v2-input" + nonce[0:16]
```

### Implication: CD is Fully Forgeable Offline

There is NO cryptographic binding between the PoW and any server-issued secret.
The solver (`05_solver/kasada_solver.py`) generates valid CDs in ~76ms without
any network calls, VM execution, or browser simulation.

The **HMAC header (x-kpsdk-h)** was determined to be SERVER-COMPUTED (see Section 14).
The client receives it from the /mfc response and echoes it back. A solver MUST
perform the /mfc handshake with the Kasada edge to obtain this value.

---

## 18. WHAT YOU NEED TO REVERSE KASADA

### Knowledge Requirements

#### 1. JavaScript Deep Understanding
- V8 internals (how `Proxy`, `WeakMap`, `DataView` work at the engine level)
- Babel/regenerator-runtime transpilation patterns
- Monkey-patching techniques (how `fetch` and `XMLHttpRequest` are wrapped)
- JavaScript scope chains and closures (the VM uses scope chains extensively)
- `Function.toString()` and `[native code]` detection

#### 2. Cryptography
- SHA-256 algorithm (round constants, message schedule, compression function)
- HMAC-SHA1 (key derivation, message construction)
- IEEE 754 double-precision float encoding (bytecode stores constants as doubles)
- Affine ciphers (the string cipher `chr((S & 0xFFFFFFC0) | ((S * 41) & 63))`)
- Proof-of-Work systems (difficulty thresholds, hash chaining, nonce searching)

#### 3. TLS/Networking
- JA3/JA4 TLS fingerprinting (how ClientHello is hashed)
- TLS cipher suite ordering (why Chrome's TLS differs from Node's)
- HTTP/2 vs HTTP/1.1 differences (Kasada checks protocol)
- Proxy types (residential vs datacenter vs mobile)
- TLS impersonation libraries (impit, curl-impersonate, utls)

#### 4. Browser Fingerprinting
- WebGL renderer strings (GPU vendor/model identification)
- Canvas fingerprinting (how `toDataURL` produces unique hashes)
- Navigator properties (hardwareConcurrency, deviceMemory, languages)
- Screen properties (width, height, colorDepth, pixelRatio)
- Anti-headless detection vectors (webdriver, native code checks, timing)

#### 5. Reverse Engineering Skills
- Custom bytecode VM analysis (opcode identification, arity derivation)
- Linear-sweep disassembly (for unknown ISAs)
- Devirtualization (converting VM bytecode back to high-level code)
- Dynamic binary instrumentation (hooking, tracing)
- Deobfuscation (control flow flattening, string encryption)

#### 6. Tool Proficiency
- Python (for scripting analysis tools)
- Node.js (for running/sandboxing the VM)
- Rust (for TLS impersonation, devirtualization tools)
- Browser DevTools (for runtime analysis)
- Wireshark/tcpdump (for TLS analysis)
- Custom disassembler development

### Infrastructure Requirements

#### For Analysis (what we did)
- Python 3.x with `re`, `json`, `struct` modules
- A text editor / IDE for reading 157KB minified JS
- ~100MB disk space for artifacts
- No special hardware

#### For CT Generation (B00H0O's approach)
- Node.js 18+ with `happy-dom` and `impit` packages
- Residential proxy access (IP rotation, ~$5-20/month)
- The decompiled p.js (Emrovsky's `decomp.js` or your own devirtualization)
- ~500MB RAM for the VM sandbox

#### For Full Solver (hypothetical)
- Everything above, plus:
- A V8 isolate or modified Node VM for instrumentation
- Custom Rust code for TLS impersonation
- A proxy pool with IP rotation (for scale)
- A CT caching system (CT is valid ~30min, reuse across requests)
- A CD minting system (CD must be fresh, <5s, single-use)

---

## 19. STEP-BY-STEP METHODOLOGY

### Phase 1: Script Acquisition
```
1. Identify the protected site's p.js URL
   - Open DevTools → Network tab
   - Look for script from <CDN>/<UUID>/<UUID>/p.js

2. Download the script
   curl -o p.js "https://k.twitchcdn.net/<tenant>/<rotation>/p.js" \
     -H "User-Agent: Mozilla/5.0..." -H "Referer: https://www.twitch.tv/"

3. Verify version
   - Search for "j-1.2." in the script or in x-kpsdk-v header
```

### Phase 2: Structure Analysis
```
4. Identify the IIFE structure
   - Find var A=function (the decoder)
   - Find var H="..." (the encoded bytecode, ~144K chars)
   - Find A(H,"<alphabet>",<f>) (the decode call)
   - Find function U( (the VM dispatch loop)

5. Extract the alphabet and base offset
   - Parse A(H,"3lYDGQrK~tvHP<cUnS+5f9Nu|kyowRZ$Mq0p=AbLEz2eVdmgaCh46x7FTXBWsIJjOi81>^",39)
   - alphabet = "3lYDGQrK~tvHP<cUnS+5f9Nu|kyowRZ$Mq0p=AbLEz2eVdmgaCh46x7FTXBWsIJjOi81>^"
   - f = 39

6. Port the A() decoder to Python
   - See Section 5 for the Python port
   - Decode H → 76,487 integers
```

### Phase 3: String Table Extraction
```
7. Find the string table location
   - c = "length"
   - f = t.length (76487)
   - p = f + 4 (L is empty at computation time, "true".length = 4)
   - m = t[f-1] ^ p (t[76486] ^ 76491 = 77132 ^ 76491 = 1927)

8. Extract the string table
   - splice_len = t[m+1] + 2 (t[1928] + 2 = 84 + 2 = 86)
   - K = t[m : m+splice_len] (86 ints)
   - Decode K as a single string operand (tag=30, inline, cipher K=41)

9. Find the cipher key
   - Try K=41 first (it's been stable across versions)
   - If not, brute-force K=1..63, checking for "navigator", "fetch", "sha256"

10. Save the string table (P.Q) to a file
    - Search for known terms to verify correctness
```

### Phase 4: Handler Table Extraction
```
11. Find the Proxy array
    - Search for 'u=new Proxy([' in the source
    - Extract the array between matching [ ]

12. Split into individual handlers
    - Split on ',(?=function()' (comma followed by function)
    - Count: should be 87 handlers (use balanced brace parsing, NOT regex split!)

13. Analyze each handler's arity
    - Count e(n) calls (operand reads)
    - Count v(n) calls (variable reads)
    - Count B(e) calls (register index reads)
    - arity = e_count + v_count + b_count

14. Document each handler's semantics
    - Read the handler code
    - Identify the operation (add, subtract, property access, etc.)
    - Map to JavaScript equivalent
```

### Phase 5: Disassembly
```
15. Implement the operand decoder
    - Port g() to Python
    - Handle all 6 tag types + small ints + register refs
    - For string operands: use P.Q.slice(offset, offset+length)

16. Linear-sweep disassembly
    - Start at PC=0
    - Read opcode = ints[PC++]
    - Read `arity` operands
    - Format and emit instruction
    - Continue until end of bytecode

17. Handle desync
    - Some values may be data, not opcodes (jump targets, etc.)
    - Use control flow analysis to identify valid instruction boundaries
    - OP_76 (JUMP) and OP_85 (CONDITIONAL JUMP) targets are data, not opcodes
```

### Phase 6: PoW Region Identification
```
18. Search disassembly for key strings
    - "tp-v2-input" → PoW seed prefix
    - "workTime", "answers", "duration" → CD token construction
    - "sha256", "createHash" → SHA-256 implementation
    - "cryptoChallengeEnabled" → PoW toggle

19. Trace the PoW algorithm
    - Find where "tp-v2-input" is used (seed initialization)
    - Find where "sha256" is called (hash computation)
    - Find where "answers" is populated (nonce pushing)
    - Find where "workTime"/"duration" are set (timing)

20. Identify the vxn secret
    - Find where vxn is set (scope chain lookup via OP_28)
    - Trace back through the scope chain to find the origin
    - Look for /tl response body processing
    - Look for /mfc response processing
```

### Phase 7: SHA-256 Verification
```
21. Search for K[] constants
    - Convert each SHA-256 K[i] to IEEE 754 double
    - Search bytecode for [4, hi_word, lo_word] patterns

22. Search for H[] init values
    - Same approach as K[] but for initial hash values

23. Search for difficulty constant
    - 2^52 = 4503599627370496
    - As double: [4, 1127219200, 0]

24. Map the SHA-256 implementation region
    - K[] and H[] locations define the SHA-256 code boundaries
    - Look for DataView/setUint32 usage nearby
```

### Phase 8: Dynamic Analysis (Optional but Powerful)
```
25. Set up a sandboxed VM environment
    - Node.js + happy-dom + impit
    - Fake navigator, WebGL, canvas, fetch

26. Instrument the VM
    - Hook the dispatch loop (function U)
    - Log every opcode execution
    - Capture scope variable values at each instruction

27. Run the VM against the real server
    - Forward requests through impit + residential proxy
    - Let the VM complete the handshake
    - Capture the /tl response body

28. Trace vxn
    - Find the instruction where vxn is set
    - Log the value and trace its origin
    - Identify the /tl response body decryption
```

### Phase 9: Solver Implementation (If Attempting)
```
29. CT caching system
    - Mint CT via sandboxed VM + impit + proxy
    - Cache for ~25 minutes (5min safety margin)
    - Reuse across multiple CD generations

30. CD generation
    - Option A: Run the full VM per request (reliable but slow)
    - Option B: Extract vxn from VM, compute PoW natively (fast but requires vxn)

31. HMAC computation
    - Identify the HMAC key source
    - Implement HMAC-SHA1 signing

32. Request assembly
    - Combine CT + CD + HMAC + version headers
    - Send through impit (same TLS fingerprint as CT minting)
```

---

## 20. TOOLS & LIBRARIES REQUIRED

### Analysis Tools

| Tool | Purpose | Required? |
|------|---------|-----------|
| Python 3.x | Scripting analysis | Yes |
| Node.js 18+ | Running/sandboxing VM | For dynamic analysis |
| Wireshark | TLS packet capture | For TLS analysis |
| Browser DevTools | Runtime analysis | Yes |
| VS Code / IDE | Reading minified JS | Yes |
| `jq` | JSON processing | Helpful |

### Python Libraries

| Library | Purpose |
|---------|---------|
| `re` | Regex parsing of minified JS |
| `json` | Bytecode serialization |
| `struct` | IEEE 754 double encoding |
| `hashlib` | SHA-256 verification |

### Node.js Libraries

| Library | Purpose |
|---------|---------|
| `happy-dom` | DOM implementation for sandbox |
| `impit` | TLS-impersonating HTTP client (Rust) |
| `regenerator-runtime` | Async/generator polyfill |
| `vm2` / `isolated-vm` | VM sandboxing |

### Rust Libraries (for advanced work)

| Library | Purpose |
|---------|---------|
| `impit` | TLS impersonation (Chrome fingerprint) |
| `serde_json` | JSON parsing |
| `sha2` | SHA-256 implementation |
| `hmac` | HMAC-SHA1 |

### Proxy Services

| Service | Type | Cost |
|---------|------|------|
| Bright Data | Residential | ~$500/month |
| Smartproxy | Residential | ~$200/month |
| IPRoyal | Residential | ~$100/month |
| Any ISP proxy | Residential | ~$5-20/month |

---

## 21. KNOWN APPROACHES & THEIR STATUS

### Approach 1: CDP Browser (Nodriver/Zendriver)
**Status**: Working (but not "browserless")

Use a real Chromium browser controlled via CDP (Chrome DevTools Protocol). The browser runs the real p.js with a real TLS stack.

**Pros**: Most reliable, handles all detection vectors
**Cons**: Resource-intensive (full browser per session), detectable via CDP artifacts

### Approach 2: Session Harvesting
**Status**: Working (but not scalable)

Run real browsers to mint CT+CD tokens, store them, and replay them.

**Pros**: Tokens are 100% valid
**Cons**: CD is single-use (<5s), so you can only harvest CT (30min). Still need CD per request.

### Approach 3: Solver APIs (2Captcha, CapSolver)
**Status**: Working (commercial)

Pay a third-party to solve Kasada challenges. They run real browsers or CDP behind the scenes.

**Pros**: No infrastructure needed
**Cons**: $2-5 per 1000 solves, latency (2-10s), rate limits, dependency on third party

### Approach 4: Browserless VM Sandbox (B00H0O)
**Status**: CT working, CD SHOULD WORK (vxn is solved — no secret needed)

Run decompiled p.js in Node.js with faked DOM + impit for TLS.

**Pros**: No browser needed, lightweight, CD is now fully forgeable offline
**Cons**: Sandbox may be detected, HMAC message format still needs tracing

### Approach 5: Full Devirtualization (Emrovsky)
**Status**: Partial (decomp.js produced). vxn is now solved — CD generation
does not require devirtualization at all.

Devirtualize the entire VM to readable JS, then extract specific algorithms.

**Pros**: No VM runtime needed, fastest execution
**Cons**: Extremely labor-intensive, breaks on version rotation
**Update**: With vxn solved, the main remaining value of devirtualization is
tracing the HMAC message format for x-kpsdk-h header generation.

### Approach 6: Dynamic Instrumentation
**Status**: Not yet attempted

Run p.js in an instrumented V8 isolate, hook scope operations, capture vxn.

**Pros**: Would reveal vxn's origin definitively
**Cons**: Anti-instrumentation checks, complex setup

---

## 22. VERSION ROTATION & CAT-AND-MOUSE

### How Kasada Rotates

| What Changes | Frequency | Impact on Reversing |
|--------------|-----------|---------------------|
| Rotation UUID | Per version | URL changes, must re-fetch |
| Bytecode encoding | Per version | Alphabet may reorder, must re-extract |
| String table offset | Per version | XOR computation changes, must re-derive |
| Cipher key K | Sometimes | String decryption changes, must re-find K |
| Handler order | Sometimes | Opcode numbers change, must re-map |
| Detection logic | Often | New checks added, sandbox must adapt |
| PoW difficulty | Sometimes | Threshold changes (5→10 seen) |
| Version string | Always | j-1.2.NNN increments |

### What This Means for Reversing

**You cannot write a one-time solver.** Any solution must:
1. Re-fetch p.js for the current rotation
2. Re-extract the bytecode (alphabet may change)
3. Re-derive the string table location (XOR with length)
4. Re-find the cipher key (usually 41, but could change)
5. Re-map opcodes to handlers (order may shuffle)
6. Re-identify the PoW region (string offsets change)
7. Re-verify SHA-256 constants (encoding may change)

**The good news**: The fundamental architecture is stable. Across 92 versions (j-1.2.430 to j-1.2.522):
- Same VM architecture (tag system, frame management, scope chains)
- Same PoW algorithm (tp-v2-input, SHA-256, difficulty formula)
- Same token system (CT/CD/H/V/R)
- Same handshake endpoints (/fp, /tl, /mfc)
- Same cipher (K=41)

**The bad news**: Each rotation requires ~2-4 hours of re-analysis to update the tooling. Full devirtualization (Emrovsky's approach) would need to be partially redone.

### Version Comparison

| Aspect | j-1.2.430 (B00H0O) | j-1.2.522 (This analysis) |
|--------|--------------------|---------------------------|
| Bytecode size | ~33K ints | 76,487 ints |
| String cipher K | 41 | 41 |
| Handler count | ~84 | 87 (was incorrectly reported as 89) |
| PoW seed prefix | tp-v2-input | tp-v2-input |
| Difficulty threshold | 5 | 10 |
| Rounds | ~2 | 2 |
| SHA-256 library | Custom | js-sha256 |
| vxn secret | Unsolved | **SOLVED** (= PoW params object, not a secret) |
| x-kpsdk-h (HMAC) | Unsolved | **SOLVED** (= server-issued, not client-computed) |
| CT generation | Working | Should work with updated decomp |

---

## 23. FILE INVENTORY & ARTIFACTS

### Organized Structure (Current)

```
E:\kasada fully reverse\organized\
├── README.md                     # Master guide with full sequence
├── 01_source/                    # Raw source materials
│   ├── p.js                      # Raw script (157,795 bytes)
│   ├── vm_section.js             # VM implementation source (13,141 chars)
│   ├── program_bytecode.json     # 70,210-int program (string table removed)
│   ├── bytecode.json             # Full 76,487-int decoded bytecode
│   ├── string_table.txt          # 6,275-char decoded string table
│   ├── handlers.json             # Extracted handler arities (87 handlers)
│   └── www.twitch.tv.har         # HAR capture (1.2MB, 37 entries)
├── 02_disassembler/              # Disassembler tool evolution
│   ├── 01_disasm_cfg.py          # v1: Initial linear sweep (buggy)
│   ├── 02_disasm_correct.py      # v2: Fixed operand ordering
│   ├── 03_disasm_v3_final.py     # v3: CORRECT (brace-matching, 87 handlers)
│   └── 04_fix_handlers.py        # Handler extraction fixer
├── 03_analysis/                  # Tracing & analysis scripts
│   ├── 01_extract_op28.py        # OP_28 scope_chain_set analysis
│   ├── 02_analyze_op56.py        # OP_56 scope_chain_get analysis
│   ├── 03_trace_vxn.py           # vxn tracing v1
│   ├── 04_trace_vxn_v2.py        # vxn tracing v2 (SOLVED)
│   ├── 05_trace_zsr.py           # zsr/dynamicConfig tracing
│   ├── 06_extract_keys.py        # Crypto key extraction
│   ├── 07_trace_hmac_gen.py      # HMAC generation tracing
│   ├── 08_full_reverse.py        # Full reverse engineering script
│   └── 09_instrument_vm.js       # VM instrumentation hook
├── 04_disasm_output/             # Generated disassembly text files
│   ├── 01_disasm_initial.txt     # v1 output
│   ├── 02_disasm_improved.txt    # v2 output
│   ├── 03_disasm_v2.txt          # Intermediate output
│   ├── 04_disasm_v3_final.txt    # Final correct disassembly
│   ├── 05_pow_region_annotated.txt  # PoW region annotated
│   └── 06_pow_analysis.txt       # PoW algorithm summary
├── 05_solver/                    # Working PoW solver
│   └── kasada_solver.py          # Standalone solver (~76ms avg)
├── 06_testing/                   # HAR parsing & token validation
│   ├── parse_har.py              # HAR kpsdk header parser
│   ├── extract_har_details.py    # Detailed HAR extraction
│   ├── analyze_real_tokens.py    # Real vs generated token comparison
│   └── crack_hmac.py             # HMAC format analysis
└── 07_docs/                      # Full documentation
    ├── KASADA_COMPLETE_REVERSING_GUIDE.md  # This document
    ├── KASADA_VXN_SOLVED.md       # vxn solution summary
    └── REVERSE_ENGINEERING_ANALYSIS.md  # Earlier analysis notes
```

---

## 24. GLOSSARY

| Term | Definition |
|------|------------|
| **CD** | Client Data — the PoW token (x-kpsdk-cd), JSON with workTime/answers/duration/etc. |
| **CT** | Client Token — the fingerprint token (x-kpsdk-ct), ~190 char opaque blob |
| **CDP** | Chrome DevTools Protocol — for browser automation |
| **Devirtualization** | Converting VM bytecode back to readable high-level code |
| **FC** | Feature Config — x-kpsdk-fc, base64 JSON with feature flags |
| **H** | HMAC — x-kpsdk-h, HMAC-SHA256 based (custom encoding), binds CT+CD+request |
| **JA3** | TLS ClientHello fingerprint hash |
| **K[]** | SHA-256 round constants (64 values) |
| **Linear sweep** | Disassembly technique that reads instructions sequentially without control flow analysis |
| **Opcode** | Operation code — an index into the handler table (0-86) |
| **PoW** | Proof-of-Work — computational puzzle (SHA-256 hash with difficulty threshold) |
| **R** | Rotation — x-kpsdk-r, rotation identifier |
| **Register** | VM storage slot in frame.o (R0=PC, R1=scope, R2+=general) |
| **Scope chain** | VM's implementation of JavaScript lexical scoping (walks o.m links) |
| **Tag** | Operand type indicator (4=double, 30=string, 40=null, etc.) |
| **Tenant UUID** | Kasada customer identifier in the script URL |
| **V** | Version — x-kpsdk-v, format j-1.2.NNN |
| **vxn** | PoW parameters object `{qdw, xqn, zsr}` — NOT a secret (SOLVED) |
| **VM** | Virtual Machine — the custom bytecode interpreter in p.js |

---

## APPENDIX A: Python Disassembler Template

```python
import json, re, struct

def load_pjs(path):
    """Load and parse p.js, return bytecode + string table + handlers"""
    with open(path, "r", encoding="utf-8") as f:
        src = f.read()

    # Extract H (encoded bytecode)
    m = re.search(r'var H="((?:[^"\\]|\\.)*)"', src)
    H = m.group(1)

    # Extract alphabet and base offset
    a_call = re.search(r'A\(H,"([^"]+)",(\d+)\)', src)
    alphabet = a_call.group(1)
    f_val = int(a_call.group(2))

    # Decode bytecode
    def decode_bytecode(r, v, f):
        l = len(v); a = l - f
        n = {ch: i for i, ch in enumerate(v)}
        p = []; x = 0
        while x < len(r):
            h = 0; t = 1
            while True:
                if x >= len(r): break
                M = n.get(r[x], 0); x += 1
                if M < f:
                    h += t * M; p.append(h | 0); break
                else:
                    h += t * (M % f + f); t *= a
        return p

    t = decode_bytecode(H, alphabet, f_val)

    # Extract string table
    f_len = len(t)
    p_val = f_len + 4  # L is empty, "true".length = 4
    m_val = t[f_len - 1] ^ p_val
    splice_len = t[m_val + 1] + 2
    K_data = t[m_val:m_val + splice_len]

    # Decode string table (inline string, cipher K=41)
    TAGS = [4, 40, 30, 16, 20, 26]
    def decode_char(S, K=41):
        return chr((S & 0xFFFFFFC0) | ((S * K) & 63))

    # First int is tag (30=string), second is length, rest are chars
    assert K_data[0] == 30
    str_len = K_data[1]
    P_Q = "".join(decode_char(K_data[2 + i]) for i in range(str_len))

    # Remove string table from bytecode
    program = t[:m_val] + t[m_val + splice_len:]

    # Extract handler arities from source
    proxy_pos = src.find('u=new Proxy([')
    bracket_start = src.index('[', proxy_pos)
    depth = 0
    end = bracket_start
    for i in range(bracket_start, len(src)):
        if src[i] == '[': depth += 1
        elif src[i] == ']': depth -= 1
        if depth == 0: end = i + 1; break
    handler_src = src[bracket_start:end][1:-1]
    handlers = re.split(r',(?=function\()', handler_src)

    arities = []
    for h in handlers:
        e_count = len(re.findall(r'\be\s*\(\s*n\s*\)', h))
        v_count = len(re.findall(r'\bv\s*\(\s*n\s*\)', h))
        b_count = len(re.findall(r'\bB\s*\(\s*e\s*\)', h))
        arities.append(e_count + v_count + b_count)

    return program, P_Q, TAGS, arities

def disassemble(program, P_Q, TAGS, arities, max_instr=None):
    """Disassemble bytecode into human-readable instructions"""
    def read_double(ints, ip):
        p = ints[ip]; x = ints[ip+1]
        n = -1 if (p & 0x80000000) else 1
        u = (p & 0x7FF00000) >> 20
        h = (p & 0xFFFFF) * (2**32) + (x if x >= 0 else x + 2**32)
        if u == 2047: return float('nan') if h else n*float('inf')
        if u != 0: h += 2**52; return n*h*(2**(u-1075))
        return n*h*(2**(1-1075))

    ip = 0
    instructions = []
    while ip < len(program):
        if max_instr and len(instructions) >= max_instr: break
        start = ip
        op = program[ip]; ip += 1
        if op >= len(arities):
            instructions.append(f"{start:6d}  DATA {op}")
            continue
        arity = arities[op]
        ops = []
        for _ in range(arity):
            if ip >= len(program): break
            a = program[ip]; ip += 1
            if a & 1: ops.append(str(a >> 1))
            elif a == TAGS[0]: d = read_double(program, ip); ip += 2; ops.append(f"{d:.4g}")
            elif a == TAGS[1]: ops.append("null")
            elif a == TAGS[2]:
                length = program[ip]; offset = program[ip+1]; ip += 2
                ops.append(f'"{P_Q[offset:offset+length][:60]}"')
            elif a == TAGS[3]: ops.append("false")
            elif a == TAGS[4]: ops.append("true")
            elif a == TAGS[5]: ops.append("void")
            else: ops.append(f"R{a>>5}")
        instructions.append(f"{start:6d}  OP_{op:2d}({' '.join(ops)})")
    return instructions

# Usage
program, P_Q, TAGS, arities = load_pjs("p.js")
instructions = disassemble(program, P_Q, TAGS, arities)
for instr in instructions[:100]:
    print(instr)
```

---

## APPENDIX B: Key Disassembly Regions

### PoW State Initialization (addr 46272-46322) — CORRECTED
```
46272  new_obj               -> R5         # R5 = {}
46274  prop_set   R5, "qdw", 10            # R5.qdw = 10  (difficulty)
46280  prop_set   R5, "xqn", 2             # R5.xqn = 2   (rounds)
46286  scope_chain_set 393, R5             # scope[393] = {qdw:10, xqn:2}
46289  empty_array       -> R4             # R4 = []
46291  scope_chain_set 394, R4             # scope[394] = [] (answers)
46303  new_obj               -> R4         # R4 = {} (state object)
46305  prop_set   R4, "exn", "tp-v2-input" # R4.exn = "tp-v2-input"
46313  scope_chain_get 393 -> R5           # R5 = scope[393] (reads params back!)
46316  prop_set   R4, "vxn", R5            # R4.vxn = {qdw:10, xqn:2}
46322  scope_chain_set 398, R4             # scope[398] = state
```

### Mining Closure Hash Computation (addr 46347-46409) — CORRECTED
```
46347  scope_chain_get 398 -> R4           # R4 = state
46350  prop_get  R4, "exn" -> R5           # R5 = "tp-v2-input"
46362  prop_get  R4, "concat" -> R6        # R6 = String.concat
46371  scope_chain_get 1966 -> R10         # R10 = NONCE (arg1 to closure)
46374  prop_get  R10, "slice" -> R9        # R9 = nonce.slice
46383  prop_set  R11, 0, 0                 # args = [0, 16]
46387  prop_set  R11, 1, 16
46391  method_call R10, R9, R11            # R2 = nonce.slice(0, 16)
46402  method_call R4, R6, R7              # R2 = "tp-v2-input".concat(nonce[0:16])
46409  scope_chain_set 1969, R5            # scope[1969] = hash_input
```

### Mining API Object Methods (addr 46693-47000)
```
.lnu  (addr 46500) = push timing answer, track start/end times
.gzv  (addr 46708) = return current difficulty value
.vgp  (addr 46730) = reset answers array and counters
.qbh  (addr 46762) = call mining closure via Promise
.xwm  (addr 46830) = call mining closure synchronously
.zfn  (addr 46876) = build CD payload object
.yjp  (addr 46944) = format ["x-kpsdk-cd", JSON.stringify(payload)]
```

---

## APPENDIX C: Opcode Corrections (CRITICAL)

### What Was Wrong in Earlier Analysis

| Issue | Old (WRONG) | Correct |
|-------|-------------|---------|
| Handler count | 89 (regex split) | **87** (brace-matched) |
| OP_28 | scope read | **scope_chain_SET** (write) |
| OP_56 | yield/generator | **scope_chain_GET** (read) |
| OP_55 | split into 2 handlers | **single method_call handler** |

### Root Cause of Errors

**Handler extraction bug:** The original regex `split(',(?=function()')` incorrectly
broke handler 55 because it contains:
```javascript
function(n,e,a,v,i,r){
  var o=e(n),l=e(n),_=e(n),u=r[4];
  if(l[u]&&l[u].K===l){
    var h;
    n.o=[l[u].Y,{...},void 0,function(){return arguments}.apply(void 0,_)];
    //                         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ THIS broke the split!
```

The inner `function(){return arguments}` matched the split regex, creating a
phantom "handler 56" that was actually part of handler 55.

### Correct Key Opcodes

```
OP_28  scope_chain_set:  for(o=v(n);o;o=o.m) if(i in o.s) {o.s[i]=r; return}
       → Walks scope chain, WRITES value to slot. 2 e(n) operands, no dest.

OP_56  scope_chain_get:  for(r=v(n);r;r=r.m) if(i in r.s) {a(n,r.s[i]); return}
       → Walks scope chain, READS value from slot. 1 e(n) operand + dest byte.

OP_55  method_call:      e(n),l=e(n),_=e(n) → l[method].apply(l, _)
       → 3 e(n) operands (receiver, method, args array), no dest byte.
       → Manages its own frame creation for the call.
```

---

*End of document. Updated 2026-07-02 with SOLVED vxn analysis and corrected opcodes.
Based on p.js version j-1.2.522 from Twitch, cross-referenced with B00H0O's kasada-vm (j-1.2.430).
Working solver: `05_solver/kasada_solver.py`*
