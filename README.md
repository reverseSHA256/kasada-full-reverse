# Kasada Full Reverse

**Historical reverse-engineering research, bytecode analysis, and experimental Python implementations for Kasada `p.js` version `j-1.2.522`.**

> **Project status: outdated — updates required.** This repository preserves research against an older script snapshot. Its bytecode addresses, opcode mappings, extracted constants, fingerprint assumptions, and HTTP examples are specific to that snapshot. The project requires renewed analysis and implementation updates before use with current integrations. Current live compatibility has not been verified.

## Overview

`kasada-full-reverse` documents an investigation into the virtual machine, encoded bytecode, fingerprint payloads, proof-of-work routines, and request headers found in a historical Kasada integration.

The repository brings together the original JavaScript snapshot, extracted bytecode and strings, multiple generations of disassemblers, focused tracing scripts, generated disassembly, and experimental Python solver interfaces. It preserves the research process as well as its results, including early interpretations that were later corrected.

The core reverse-engineering work uses static inspection: reading the interpreter, reconstructing operand decoding, following register and scope operations, and tracing data through the bytecode. Separate network and capture utilities explore the surrounding HTTP protocol.

The repository name describes the scope of the investigation. It does not indicate that every component is complete or compatible with current Kasada versions.

### Repository description

For the GitHub About field:

> Historical Kasada p.js reverse-engineering research: VM disassembly, static analysis, PoW experiments, and Python prototypes. Outdated; requires updates for current versions.

### Intended audience

- Researchers studying JavaScript virtualization and bytecode interpretation.
- Developers reviewing a historical proof-of-work implementation.
- Contributors interested in improving reproducibility and maintaining versioned analysis.
- Readers who want to follow the progression from raw source to annotated findings.

## Current Status

| Component | What is included | Current limitation |
| --- | --- | --- |
| Source snapshot | `p.js`, interpreter excerpt, bytecode, handlers, and string table | Represents one historical snapshot |
| Disassembler | Earlier implementations and the later v3 handler table | Several entry points retain original Windows paths |
| Static analysis | Opcode, scope, configuration, and cryptographic tracing scripts | Addresses and assumptions must be checked against the matching snapshot |
| Offline PoW | A Python implementation and demonstration | A locally valid hash does not establish server acceptance |
| HTTP prototypes | Async client, CLI, and FastAPI server | Current protocol and dependency compatibility are unverified |
| Capture tools | Fingerprint decoders and mitmproxy addons | Payload layout and encoding assumptions are version-specific |
| Testing utilities | HAR inspection and token-comparison experiments | Original HAR files are absent; sensitive fixtures are sanitized |
| Documentation | Research notes, architectural descriptions, and implementation guide | Historical files contain superseded conclusions |

**Maintenance state:** this is an outdated research archive with experimental implementations. It needs updates to source artifacts, paths, dependency versions, protocol assumptions, and validation coverage.

## Repository Structure

```text
kasada-full-reverse/
├── README.md
├── .gitignore
├── 01_source/
│   ├── p.js
│   ├── vm_section.js
│   ├── bytecode.json
│   ├── program_bytecode.json
│   ├── handlers.json
│   └── string_table.txt
├── 02_disassembler/
│   ├── 01_disasm_cfg.py
│   ├── 02_disasm_correct.py
│   ├── 03_disasm_v3_final.py
│   └── 04_fix_handlers.py
├── 03_analysis/
│   ├── 01_extract_op28.py
│   ├── 02_analyze_op56.py
│   ├── 03_trace_vxn.py
│   ├── 04_trace_vxn_v2.py
│   ├── 05_trace_zsr.py
│   ├── 06_extract_keys.py
│   ├── 07_trace_hmac_gen.py
│   ├── 08_full_reverse.py
│   └── 09_instrument_vm.js
├── 04_disasm_output/
│   ├── 01_disasm_initial.txt
│   ├── 02_disasm_improved.txt
│   ├── 03_disasm_v2.txt
│   ├── 04_disasm_v3_final.txt
│   ├── 05_pow_region_annotated.txt
│   └── 06_pow_analysis.txt
├── 05_solver/
│   ├── README.md
│   ├── kasada_solver.py
│   ├── kasada_full_solver.py
│   ├── solver.py
│   ├── server.py
│   ├── capture_fingerprint.py
│   ├── kasada_intercept.py
│   ├── example_twitch.py
│   └── request.json
├── 06_testing/
│   ├── parse_har.py
│   ├── extract_har_details.py
│   ├── analyze_real_tokens.py
│   ├── crack_hmac.py
│   └── check_mfc.py
└── 07_docs/
    ├── KASADA_COMPLETE_REVERSING_GUIDE.md
    ├── KASADA_VXN_SOLVED.md
    └── REVERSE_ENGINEERING_ANALYSIS.md
```

The local working directory may still be named `organized`. The GitHub repository name is `kasada-full-reverse`.

## How the Research Works

### 1. Preserve the source materials

The starting point is the historical `p.js` snapshot in [01_source](01_source/). The directory contains an interpreter excerpt, extracted numeric arrays, a handler table, and a decoded string table.

`program_bytecode.json` is the input used by the Python disassemblers. Keep it paired with the matching string table and interpreter snapshot; combining artifacts from different versions can produce misleading output.

### 2. Reconstruct the virtual machine

The analysis follows a register-based interpreter whose dispatch table maps numeric opcodes to JavaScript handlers.

The later research describes 87 handlers. Earlier notes describe a different count because the first extraction method split nested function literals incorrectly. The handler-fixing script demonstrates why balanced-brace parsing matters when reconstructing a table from obfuscated JavaScript.

The investigation also separates ordinary operands from destination-register bytes. Consuming these fields in the wrong order shifts the instruction pointer and corrupts subsequent decoding.

### 3. Decode operands and instructions

The disassemblers interpret immediate integers, register references, strings, floating-point values, and special values according to the captured interpreter.

Examples from this snapshot include:

| Representation | Historical interpretation |
| --- | --- |
| Odd integer | Immediate integer encoded as `value * 2 + 1` |
| Register encoding | Register index recovered through a right shift by five |
| Tag `30` | String reference using a length and string-table offset |
| Tag `4` | Floating-point representation |
| Tags `40`, `16`, `20`, `26` | Null, false, true, and undefined-like values |

These mappings belong to the recorded interpreter. They must be derived again if the instruction set or decoder changes.

### 4. Trace configuration and data flow

The scripts in [03_analysis](03_analysis/) inspect scope operations, configuration assignments, cryptographic references, and the proof-of-work region.

One documented correction concerns `vxn`: later notes identify it as a configuration object containing `qdw`, `xqn`, and `zsr`. Earlier notes treat it as an unresolved secret. Both stages are retained so readers can see how the interpretation changed.

### 5. Reconstruct the offline computation

The historical Python PoW implementation generates a hexadecimal nonce and repeatedly hashes a seed plus the first 16 nonce characters. With the recorded default configuration:

```text
seed = "tp-v2-input"
difficulty = 10 leading zero bits
rounds = 2

nonce_prefix = nonce[:16]
first_hash = SHA256_UTF8(seed + nonce_prefix).hexdigest()
final_hash = SHA256_UTF8(first_hash + nonce_prefix).hexdigest()

accept locally when final_hash has at least difficulty leading zero bits
```

The second round uses the hexadecimal text of the first digest. This distinction matters when reproducing the implementation.

Mining time varies with hardware, random sampling, and difficulty. Historical timing claims should be treated as observations from the original investigation.

### 6. Explore the surrounding HTTP flow

The network prototypes implement a historical sequence:

```text
Fingerprint fields
    │ JSON serialization, XOR transformation, Base64 encoding
    ▼
POST /tl ──► capture x-kpsdk-ct
    ▼
GET /mfc ──► capture x-kpsdk-h
    ▼
Local PoW ──► construct x-kpsdk-cd
    ▼
Return or attach the historical x-kpsdk-* header set
```

The server prototype first attempts to extract a version and XOR key from `p.js`. This limited detection does not refresh opcode mappings, fingerprint schemas, challenge semantics, or token validation.

Later HTTP implementations obtain `x-kpsdk-h` from the server. The legacy PoW module contains a local HMAC experiment that reflects an earlier interpretation. The archive does not establish that either interpretation applies to current deployments.

## Components and Responsibilities

### Source, disassembly, and analysis

| File or group | Purpose |
| --- | --- |
| `01_source/p.js` | Original script snapshot used for the investigation |
| `01_source/vm_section.js` | Extracted interpreter section |
| `program_bytecode.json`, `bytecode.json` | Numeric artifacts retained from extraction |
| `handlers.json`, `string_table.txt` | Handler and string references |
| `01_disasm_cfg.py` | Early control-flow-aware disassembly experiments |
| `02_disasm_correct.py` | Revised operand-consumption logic |
| `03_disasm_v3_final.py` | Later disassembler with the corrected handler table |
| `04_fix_handlers.py` | Balanced-brace handler extraction |
| `01_extract_op28.py`, `02_analyze_op56.py` | Focused opcode investigations |
| `03_trace_vxn.py`, `04_trace_vxn_v2.py` | Successive configuration tracing attempts |
| `05_trace_zsr.py` | Configuration update references |
| `06_extract_keys.py`, `07_trace_hmac_gen.py` | Cryptographic constant and header investigations |
| `08_full_reverse.py` | Broader PoW data-flow analysis |
| `09_instrument_vm.js` | JavaScript instrumentation experiment |
| `04_disasm_output/` | Saved outputs that can be reviewed without rerunning scripts |

### Solver and testing tools

| File | Purpose |
| --- | --- |
| `kasada_solver.py` | Standard-library PoW demonstration and legacy signing experiment |
| `kasada_full_solver.py` | Async client, fingerprint builder, encoding helpers, PoW, and session logic |
| `solver.py` | Command-line interface returning a JSON result |
| `server.py` | FastAPI interface with health and solving endpoints |
| `capture_fingerprint.py` | Manual payload decoding and optional mitmproxy capture |
| `kasada_intercept.py` | Interactive, HAR-based, and proxy-based payload inspection |
| `example_twitch.py` | Historical integration example containing sample credentials |
| `request.json` | Historical request configuration example |
| `parse_har.py`, `extract_har_details.py` | Inspection of external HAR captures |
| `analyze_real_tokens.py` | Exploratory comparison of historical token fields |
| `crack_hmac.py` | Earlier header-format experiments |
| `check_mfc.py` | Inspection of captured feature-configuration responses |

See [the solver guide](05_solver/README.md) for interfaces, examples, and troubleshooting.

## Getting Started

### Requirements

The offline PoW demonstration uses only Python's standard library. Network tools additionally import `wreq`; the HTTP server imports `fastapi`, `pydantic`, and `uvicorn`. Proxy capture mode imports `mitmproxy`.

There is no dependency lockfile or declared, tested package-version matrix. Use an isolated environment and verify that your installed `wreq` exposes the `Client`, `Emulation`, and `Jar` interfaces referenced by the source.

### Create an environment

Run these commands from the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

On Windows, activate with `.venv\Scripts\activate`.

### Run the offline demonstration

```bash
python3 05_solver/kasada_solver.py
```

The demonstration mines a proof, prints a hash calculation, and constructs example headers using a dummy CT value. It makes no network requests.

Its local HMAC calculation and legacy CD formatting are historical experiments. Successful execution demonstrates the offline code path, while server acceptance remains unverified.

### Install optional network dependencies

```bash
python3 -m pip install wreq
```

For the server:

```bash
python3 -m pip install wreq fastapi uvicorn
```

For proxy capture:

```bash
python3 -m pip install mitmproxy
```

These commands install dependencies; they do not resolve the project's outdated protocol assumptions. Package versions must be reviewed and pinned as part of a maintenance update.

### Review the existing disassembly

Start with [the saved v3 output](04_disasm_output/04_disasm_v3_final.txt) and [the annotated PoW region](04_disasm_output/05_pow_region_annotated.txt).

The disassembler entry points still reference the original Windows working directory. Before regenerating output, update input paths to `01_source/` and choose explicit output paths under `04_disasm_output/`.

Several analysis scripts also load an old file named `disasm_v3.py` through `exec()`. That filename is not included in this repository; these scripts need their imports and paths updated before execution.

### Start the local server

After installing compatible dependencies:

```bash
python3 05_solver/server.py --host 127.0.0.1 --port 8080
```

Check local availability:

```bash
curl http://127.0.0.1:8080/health
```

The expected health response is `{"status":"ok"}`. It confirms that the application responds, without validating an external protocol.

## Important Implementation Limitations

1. **Historical source dependency.** Bytecode offsets, extracted keys, endpoint examples, and property names come from one older snapshot.
2. **Conflicting research stages.** Early and later files disagree about handler counts, `vxn`, HMAC behavior, and token fields. Read corrections alongside the original claims.
3. **Nonportable paths.** Several scripts use absolute Windows paths and references to filenames from the original workspace.
4. **Missing captures.** HAR utilities require files that are not distributed with the project.
5. **Sanitized fixtures.** Captured login credentials and authentication headers have been replaced with placeholders. Historical comparisons need separate private fixtures to be reproducible.
6. **Unpinned dependencies.** Network examples depend on APIs and emulation profiles that have not been validated against a pinned installation.
7. **Different solver generations.** The legacy and later implementations differ in CD construction and signing behavior.
8. **Limited configuration detection.** The server's version/key extraction does not implement full adaptation to a new script.
9. **No comprehensive automated suite.** `06_testing/` contains exploratory scripts rather than a maintained regression suite.
10. **Unverified live operation.** The archive provides no current guarantee of token acceptance or compatibility with a particular site.

The `kasada_full_solver.py` demonstration also contacts an external TLS inspection endpoint. Use `kasada_solver.py` for the standalone offline demonstration.

## Update Roadmap

| Priority | Work | Expected outcome |
| --- | --- | --- |
| 1 | Acquire and identify a new source snapshot; record hashes and provenance | A clearly versioned research baseline |
| 2 | Rebuild string extraction, handler parsing, and operand mappings | Disassembly tied to the new interpreter |
| 3 | Replace absolute paths and `exec()` loading with reusable modules | Reproducible execution across operating systems |
| 4 | Review fingerprint encoding, challenge configuration, and header lifecycle | Documented behavior for the new snapshot |
| 5 | Reconcile CD fields and remove superseded signing assumptions | Consistent implementations and examples |
| 6 | Validate and pin Python and package versions | Repeatable installation |
| 7 | Create sanitized fixtures and meaningful offline regression checks | Evidence for decoder and PoW correctness |
| 8 | Validate the HTTP flow in a controlled integration | Version-specific compatibility results |
| 9 | Revise documentation and publish a compatibility matrix | A clear distinction between observed and unverified behavior |

An update should record the exact script version and environment used. Changing a version string alone is insufficient.

## Documentation Guide

| Document | Reading purpose |
| --- | --- |
| [Solver guide](05_solver/README.md) | Available interfaces, setup, and operational limitations |
| [Complete reversing guide](07_docs/KASADA_COMPLETE_REVERSING_GUIDE.md) | Detailed historical VM and protocol investigation |
| [VXN research note](07_docs/KASADA_VXN_SOLVED.md) | Later configuration and PoW interpretations |
| [Initial analysis](07_docs/REVERSE_ENGINEERING_ANALYSIS.md) | Early observations and hypotheses |

Historical headings such as “working,” “solved,” and “complete” describe claims made during the original investigation. They do not establish present compatibility.

## Verification

During repository preparation, the standalone `kasada_solver.py` demonstration completed successfully under Python 3.14.8. Its generated proof was also checked independently against the historical SHA-256 calculation and difficulty condition.

This verification covers the offline PoW computation only. Network dependencies, HTTP flows, capture integrations, and live acceptance were not validated.

## Contributing

Maintenance contributions should identify the script snapshot they target, explain the observed behavior, and include reproducible evidence for substantive algorithm changes.

Keep captured traffic, account credentials, proxy credentials, and session tokens outside the repository. Use synthetic or sanitized fixtures in published examples. The ignore rules exclude HAR captures, common fingerprint captures, environment files, caches, and virtual environments.

Existing historical findings should be corrected with clear version context so that readers can distinguish the original observation from the maintained interpretation.

## License and Attribution

No license file is currently included. A repository license has not been selected, and the included third-party script snapshot may carry separate terms.

This is an independent research repository. No affiliation with or endorsement by Kasada, Twitch, or any other referenced service is claimed.
