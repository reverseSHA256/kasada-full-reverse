# Kasada Reverse-Engineering Analysis

> **Historical document — outdated; updates required.** This material concerns the archived `j-1.2.522` snapshot. This is the initial analysis. Its handler count and interpretation of vxn were revised in later research; read it as an early hypothesis record. See [the current repository overview](../README.md) for status, limitations, and the update roadmap.

## Source: `p.js` version `j-1.2.522` from Twitch CDN
## Date: 2026-07-02

---

## 1. Script Structure

The 157,795-byte `p.js` is a single IIFE with three sections:

1. **Bytecode decoder + encoded payload** (chars 0-144,374)
   - `A(r,v,f)`: Variable-length integer decoder (base-26 continuation encoding)
   - `H`: 144,123-char encoded string (the bytecode)
   - Alphabet: `3lYDGQrK~tvHP<cUnS+5f9Nu|kyowRZ$Mq0p=AbLEz2eVdmgaCh46x7FTXBWsIJjOi81>^` (70 chars)
   - Base offset: `f=39`

2. **VM implementation** (chars 144,374-157,618)
   - `c="length"`, `t=A(H,alphabet,39)` → 76,487 integers of bytecode
   - String table extraction via XOR + splice
   - 89 opcode handlers in a `Proxy` array
   - Operand decoder `g()` with 6 tag types
   - Frame management, exception handling, scope chains

3. **Regenerator runtime** (chars 144,374-157,618, interleaved)
   - Babel's `regenerator-runtime` for transpiled async/generators

---

## 2. Bytecode Format

### Encoding
- 76,487 integers decoded from `H` via the `A()` function
- Variable-length encoding: chars with index < 39 terminate, >= 39 continue with base-26

### String Table
- Extracted at runtime: `m = t[t.length-1] ^ (t.length + 4)` = 1927
- Splice length: `t[m+1] + 2` = 6,277
- Region: `t[1927..8203]` (86 ints → 6,275-char string)
- **Cipher**: `chr((S & 0xFFFFFFC0) | ((S * 41) & 63))` — affine cipher, K=41

### Program Bytecode
- 70,210 integers (after string table removal)
- String operands use `P.g(length, offset)` → `P.Q.slice(offset, offset+length)`
- Inline strings (tag=30) use the cipher directly

### Operand Tags (`y = [4, 40, 30, 16, 20, 26]`)
| Tag | Type | Encoding |
|-----|------|----------|
| 4 | double | 2 ints (IEEE 754 hi/lo) |
| 40 | null | — |
| 30 | string | length + offset (into P.Q) |
| 16 | false | — |
| 20 | true | — |
| 26 | void | — |
| odd | small int | `val >> 1` |
| other even | register | `R(val >> 5)` |

---

## 3. VM Architecture

### Dispatch Loop
```javascript
function U(e) {
  var n = [O, [M,W], t, u];      // runtime: [window, [Promise,resolve], bytecode, handlers]
  var r = [X, D, h, U, L, j];    // functions: [throw, catch, frame, dispatch, rand, pop]
  while (true) {
    var i = u[t[e.o[0]++]];       // read opcode, dispatch to handler
    var N = i(e, G, F, s, n, r); // execute handler
    if (N === null) break;        // halt
  }
}
```

### Handler Table: 89 Opcodes
Key opcodes identified:

| Op | Arity | Semantics |
|----|-------|-----------|
| 0 | 2 | Property access: `a(n, e(n)[e(n)])` |
| 1 | 1 | Set `.l` (loop/jump target) |
| 2 | 1 | Division: `o(n) / e(n)` |
| 3 | 1 | XOR: `e(n) ^ o(n)` |
| 5 | 2 | Scope store: `r.s[i] = o` |
| 6 | 3 | Call: `v(i, r)` |
| 7 | 1 | Not-equal: `o(n) != e(n)` |
| 9 | 0 | Bitwise OR: `o(n) | o(n)` |
| 10 | 2 | Scope variable declaration |
| 11 | 1 | New array |
| 19 | 3 | Scope store with value |
| 20 | 0 | New object `{}` |
| 24 | 1 | Strict not-equal: `o(n) !== e(n)` |
| 28 | 3 | Scope chain lookup |
| 30 | 0 | Strict equal: `o(n) === o(n)` |
| 37 | 3 | Property set: `e(n)[e(n)] = e(n)` |
| 40 | 1 | Bitwise OR: `e(n) | o(n)` |
| 43 | 2 | Addition: `e(n) + e(n)` |
| 49 | 0 | New array `[]` |
| 51 | 2 | Function bind/construct |
| 52 | 1 | Identity: `a(n, e(n))` |
| 55 | 3 | Method call with scope |
| 56 | 0 | Yield/return |
| 59 | 1 | Addition: `o(n) + e(n)` |
| 65 | 2 | Subtraction: `e(n) - e(n)` |
| 66 | 2 | Loose equal: `v == i` |
| 67 | 1 | Throw: `o(n, l)` |
| 74 | 0 | Return null |
| 76 | 1 | Set PC: `n.o[0] = e(n)` |
| 82 | 0 | Clear exception |
| 84 | 0 | Strict not-equal: `o(n) !== o(n)` |
| 86 | 1 | Strict equal: `o(n) === e(n)` |

---

## 4. String Table (6,275 chars)

### Key Strings Found
| String | Offset | Context |
|--------|--------|---------|
| `tp-v2-input` | 214 | PoW seed prefix (adjacent to `kpsdkCt`) |
| `x-kpsdk-cd` | 2869 | CD header name (near `encodedClientToken`, `KP_RC`) |
| `x-kpsdk-ct` | 4236 | CT header name |
| `x-kpsdk-h` | 1176 | HMAC header name |
| `x-kpsdk-v` | 5403 | Version header |
| `x-kpsdk-r` | 2229 | Region/rotation header |
| `sha256` | 1231 | Hash function (js-sha256 library) |
| `sha224` | 3646 | SHA-224 variant |
| `hmac` | 3763 | HMAC computation |
| `createHash` | 5608 | Hash factory |
| `setUint32` | 2148 | DataView byte writing |
| `DataView` | — | Binary data manipulation |
| `Uint8Array` | 12791 | Byte array |
| `digest` | 1346 | Hash output |
| `finalize` | 1587 | Hash finalization |
| `workTime` | 1725 | CD token field |
| `answers` | 999 | CD token field (PoW solutions) |
| `duration` | 876 | CD token field |
| `cryptoChallengeEnabled` | 3591 | PoW toggle |
| `interrogationTimeoutDuration` | — | Challenge timeout |
| `validUntil` | 537 | Token expiry |
| `dynamicConfig` | 1187 | Server config |
| `seqNum` | 563 | Sequence number |
| `marker` | 3585 | Timing marker |
| `kpsdkCd` | 5097 | CD token variable |
| `kpsdkCt` | 207 | CT token variable |
| `JS_SHA256_NO_NODE_JS` | 437 | Node detection guard |
| `JS_SHA256_NO_WINDOW` | — | Window detection guard |

### Obfuscated Property Names (from PoW region)
| Name | Offset | Likely meaning |
|------|--------|----------------|
| `exn` | 128 | PoW seed (starts as "tp-v2-input") |
| `vxn` | 1979 | **VM-internal secret** (the unsolved value) |
| `qdw` | 125 | Difficulty threshold (= 10) |
| `xqn` | 910 | Round count (= 2) |
| `ykj` | 1237 | Loop counter / hash accumulator |
| `rlg` | 5836 | Answer array reference |
| `nzv` | 5244 | Interrogation completion flag |

---

## 5. SHA-256 Implementation

- **Library**: js-sha256 (embedded in bytecode)
- **K[] round constants**: 28/64 found as IEEE 754 doubles at indices 13626-13966
  (Remaining 36 likely computed or stored differently)
- **H[] init values**: 2/8 found at indices 12060-12078
- **Difficulty constant**: 2^52 (0x10000000000000) at index 9592
- **Implementation markers**: `setUint32`, `DataView`, `Uint8Array`, `digest`, `finalize`, `createHash`
- **Detection guards**: `JS_SHA256_NO_NODE_JS`, `JS_SHA256_NO_WINDOW`, `JS_SHA256_NO_ARRAY_BUFFER`, `JS_SHA256_NO_BUFFER_FROM`, `JS_SHA256_NO_COMMON_JS`

---

## 6. PoW / CD Token Algorithm

### Parameters (addr ~46274-46280)
- `qdw = 10` — difficulty threshold
- `xqn = 2` — number of rounds (answer count)

### Seed Initialization (addr ~46305-46316)
```
exn = "tp-v2-input"     // hardcoded seed prefix
vxn = R5                // VM-INTERNAL SECRET (from scope chain)
```

### Mining Loop (addr ~46326-46598, per round)
```
1. hash_input = exn.concat(vxn)
2. hash = sha256(hash_input)
3. exn = hash.slice(0, 16)           // chaining: seed = first 16 hex chars
4. difficulty = 2^52 / (parseInt(hash.slice(0,13), 16) + 1)
5. if difficulty >= qdw (10):
     answers.push(nonce)
     vxn = R8                        // update secret for next round
6. loop until answers.length == xqn (2)
```

### CD Token Construction (addr ~10454-10508)
```json
{
  "workTime": <performance.now() delta>,
  "id": <challenge ID from server>,
  "answers": [<nonce1>, <nonce2>],
  "duration": <mining time ms>,
  "d": <difficulty parameter>,
  "st": 0,
  "rst": 0
}
```

### Difficulty Check
- Constant: `2^52 = 4503599627370496` at bytecode index 9592
- Formula: `difficulty(h) = 2^52 / (parseInt(h.slice(0,13), 16) + 1)`
- Threshold: `difficulty >= 10`
- Equivalent: `parseInt(h.slice(0,13), 16) <= 450359962737049` (≈ 0x1999999999999)

---

## 7. The Unsolved Problem: `vxn` (VM-Internal Secret)

### What We Know
- `vxn` is set at addr 46316 from register R5
- R5 comes from the VM's scope chain (via `OP_28` operations)
- It is **NOT** any network-visible value:
  - Not from request/response headers
  - Not from the CT token
  - Not from the CD token fields (st, id, workTime, etc.)
  - Not from the HAR-captured data
- It **IS** updated each round (addr 46460-46469: `vxn = R8`)
- B00H0O's brute-force across 4 samples confirmed no combination of wire-visible values reproduces the answers

### Likely Sources
1. **Server-issued challenge nonce** — delivered via an encrypted/obfuscated channel in the `/tl` or `/mfc` response body (not in headers)
2. **Fingerprint-derived value** — computed from the browser fingerprint collection (WebGL, canvas, etc.) during the CT handshake
3. **CT handshake key** — a key derived during the `/tl` endpoint response processing, stored in VM scope
4. **dynamicConfig value** — a secret embedded in the server's dynamic configuration response

### Why It Can't Be Forged Offline
The `vxn` value exists only transiently inside the running VM's scope chain. It is:
- Computed during the CT handshake (which requires a real TLS-impersonated session)
- Stored in a closure/scope variable (never serialized to the network)
- Mixed into the PoW seed via string concatenation
- Updated each round based on the previous hash output

To forge a CD token, you must either:
1. **Run the full VM** to produce `vxn` (requires the full browser environment or a faithful sandbox like B00H0O's approach)
2. **Fully devirtualize the parent VM** to extract the key-derivation logic that produces `vxn` (this is the "lifting" problem Emrovsky started with `leak.rs`)

---

## 8. Full Token System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    KASADA TOKEN SYSTEM                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. CT (Client Token) — x-kpsdk-ct                          │
│     ├─ Generated by server at /tl endpoint                  │
│     ├─ ~190 char opaque encrypted blob                      │
│     ├─ Carries browser fingerprint                          │
│     ├─ Bound to IP + UA + TLS fingerprint                   │
│     ├─ Lifetime: ~30 minutes                                │
│     └─ B00H0O SOLVED: can mint browserlessly via sandbox    │
│                                                              │
│  2. CD (Client Data) — x-kpsdk-cd                           │
│     ├─ Generated client-side by VM PoW                      │
│     ├─ Small JSON: {workTime, id, answers, duration, d, st, rst} │
│     ├─ answers = SHA-256 PoW nonces                         │
│     ├─ Seed = "tp-v2-input" + vxn (VM-internal secret)     │
│     ├─ Difficulty: 2^52/(parseInt(h[0:13],16)+1) >= 10     │
│     ├─ 2 rounds, hash-chained                               │
│     ├─ Lifetime: <5 seconds (single-use)                    │
│     └─ UNSOLVED: vxn cannot be forged without running VM    │
│                                                              │
│  3. H (HMAC) — x-kpsdk-h                                    │
│     ├─ HMAC-SHA1, 20 bytes base64                           │
│     ├─ Binds CT + CD + request                              │
│     └─ Computed in VM (hmac string at offset 3763)          │
│                                                              │
│  4. V (Version) — x-kpsdk-v                                 │
│     ├─ Format: j-1.2.<NNN>                                  │
│     ├─ Current Twitch: j-1.2.522                            │
│     └─ Rotates with script URL UUID                         │
│                                                              │
│  5. FC (Feature Config) — x-kpsdk-fc                        │
│     ├─ Base64 JSON: {"featureFlags":{}}                     │
│     └─ From /mfc endpoint                                   │
│                                                              │
│  6. R (Region/Rotation) — x-kpsdk-r                         │
│     └─ Format: N-AAAA (rotation identifier)                 │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 9. What's Solved vs. Open

| Component | Status | Method |
|-----------|--------|--------|
| Script fetch & structure | **Solved** | Direct download from CDN |
| Bytecode decoding | **Solved** | Ported `A()` decoder to Python |
| String table extraction | **Solved** | XOR + splice, cipher K=41 |
| String cracking | **Solved** | 6,275 chars, all key terms found |
| Opcode handler extraction | **Solved** | 89 handlers from Proxy array |
| Operand format | **Solved** | 6 tags, register refs, inline strings |
| Disassembly | **Partial** | Linear sweep with sync issues (DATA entries) |
| SHA-256 location | **Solved** | K[] constants at indices 13626+, js-sha256 library |
| PoW algorithm structure | **Solved** | Seed, hash, chain, difficulty, CD construction |
| PoW parameters | **Solved** | difficulty=10, rounds=2, threshold=2^52/10 |
| CT token generation | **Solved** (B00H0O) | Sandbox + TLS impersonation + proxy |
| **CD `vxn` secret** | **UNSOLVED** | VM-internal scope value, not on wire |
| HMAC computation | **Partial** | HMAC-SHA1 identified, key derivation unknown |
| Full request signing | **UNSOLVED** | Blocked on CD + HMAC key |

---

## 10. Files Produced

| File | Description |
|------|-------------|
| `p.js` | Raw script (157,795 bytes) |
| `bytecode.json` | Full 76,487-int decoded bytecode |
| `program_bytecode.json` | 70,210-int program (string table removed) |
| `string_table.txt` | 6,275-char decoded string table |
| `disasm.txt` | Full linear-sweep disassembly (37,727 instructions) |
| `vm_section.js` | VM implementation source (13,141 chars) |
| `pow_analysis.txt` | PoW algorithm summary |

---

## 11. Comparison with B00H0O's Research

| Aspect | B00H0O (j-1.2.430) | This analysis (j-1.2.522) |
|--------|--------------------|---------------------------|
| Bytecode size | ~33K ints | 76,487 ints (larger script) |
| String cipher K | 41 | 41 (unchanged) |
| Handler count | ~84 | 89 (5 new opcodes) |
| PoW seed prefix | tp-v2-input | tp-v2-input (unchanged) |
| Difficulty | threshold 5 | threshold 10 (harder) |
| Rounds | ~2 | 2 (unchanged) |
| SHA-256 | Custom impl | js-sha256 library |
| `vxn` secret | Unsolved | Unsolved (confirmed) |
| CT generation | Working | Should work with updated decomp |

The core architecture is unchanged across 92 versions. Kasada increased the difficulty threshold (5→10) and added 5 new opcodes, but the fundamental PoW structure and the `vxn` secret problem remain identical.
