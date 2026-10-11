# Solver and Protocol Experiments

> **Outdated — updates required.** These implementations were written around Kasada `p.js` version `j-1.2.522`. Current endpoint behavior, fingerprint requirements, dependency compatibility, and server acceptance have not been verified. Read the [repository overview](../README.md) before running network examples.

## Purpose

This directory contains several generations of Python experiments around historical fingerprint encoding, offline proof-of-work, session handling, and request-header construction.

The modules differ in scope and assumptions. The original PoW module includes a client-side HMAC experiment; later HTTP implementations request the header value from `/mfc`. These differences reflect the research history and need reconciliation during an update.

## Available Interfaces

| Entry point | Responsibility | Dependencies |
| --- | --- | --- |
| `kasada_solver.py` | Offline mining, legacy CD formatting, and signing demonstration | Python standard library |
| `kasada_full_solver.py` | Async HTTP client, encoding helpers, PoW, and session handling | `wreq` |
| `solver.py` | CLI producing a JSON result | `wreq` |
| `server.py` | FastAPI service returning headers | `wreq`, `fastapi`, `pydantic`, `uvicorn` |
| `capture_fingerprint.py` | Manual decoder and optional proxy capture | Standard library; `mitmproxy` for proxy mode |
| `kasada_intercept.py` | Interactive and HAR decoding; optional proxy addon | Standard library; `mitmproxy` for proxy mode |
| `example_twitch.py` | Historical integration example | Solver dependencies |
| `request.json` | Original site-specific request configuration | Data file |

No package versions are pinned. The HTTP source imports `Client`, `Emulation`, and `Jar` from `wreq`, and references specific Chrome emulation members. Verify these APIs against the installed version.

## Historical Protocol Flow

1. Build a JSON object representing browser fingerprint fields.
2. Apply the snapshot's XOR transformation and Base64 encoding.
3. Submit the encoded payload to the configured `/tl` endpoint.
4. Read `x-kpsdk-ct` from the response.
5. Request `/mfc` with the CT value and the historical `x-kpsdk-h: 01` marker.
6. Read `x-kpsdk-h` from the response.
7. Compute the historical PoW locally and serialize a CD payload.
8. Return or attach the resulting headers.

| Header | Role in the later prototypes |
| --- | --- |
| `x-kpsdk-ct` | Token obtained through the historical `/tl` exchange |
| `x-kpsdk-cd` | JSON text produced from the local PoW result |
| `x-kpsdk-h` | Value read from the historical `/mfc` response |
| `x-kpsdk-v` | Historical version identifier |

The prototypes attempt to keep the client profile, user agent, cookie state, and proxy configuration consistent within their requests. The archive does not establish current validation rules or token lifetimes.

## Installation

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install wreq
```

Add server dependencies when needed:

```bash
python3 -m pip install fastapi uvicorn
```

Proxy mode additionally requires `mitmproxy`. Manual payload decoding does not require the proxy addon to run.

The following network commands describe the existing interfaces. They require compatible dependencies and updated, site-specific configuration before their results can be assessed.

## Offline Demonstration

```bash
python3 05_solver/kasada_solver.py
```

This entry point prints a locally mined proof, digest calculations, an example CD value, and signed headers using a dummy CT. It makes no network requests.

For an offline mining example from this directory:

```python
from kasada_solver import KasadaSolver

solver = KasadaSolver()
proof = solver.solve_pow()

print(proof["nonce"])
print(proof["hash"])
```

The recorded defaults are a `tp-v2-input` seed, two SHA-256 rounds, and ten leading zero bits. Later CD serialization differs from this legacy module, so a successful demonstration does not validate the header format used by a live server.

## Command-Line Interface

Run from the repository root, replacing the example origin and path with reviewed configuration:

```bash
python3 05_solver/solver.py \
  --site https://example.com \
  --path /integration-id/script-id \
  --chrome 131
```

The `--path` argument is the integration prefix. This CLI appends `/tl` and `/mfc` itself; do not provide a path ending in `/p.js`.

| Argument | Required | Meaning |
| --- | --- | --- |
| `--site` | Yes | Target origin used to construct endpoint URLs |
| `--path` | Yes | Historical integration path prefix |
| `--chrome` | No | Requested emulation version; defaults to `131` |
| `--proxy` | No | Proxy URL passed to the client |

The result is serialized to standard output:

```json
{
  "success": true,
  "type": "kasada",
  "headers": {
    "x-kpsdk-ct": "<server-issued CT>",
    "x-kpsdk-cd": "<JSON-encoded local proof>",
    "x-kpsdk-v": "j-1.2.522",
    "x-kpsdk-h": "<server-issued H>"
  }
}
```

Failure results include `success: false`, `headers: null`, and an error string. This shape describes the implementation's output contract.

An unsupported Chrome selection falls back to the configured Chrome 131 emulation while the user-agent string is built from the supplied argument. Review supported profiles before selecting a version.

## Local HTTP Server

Start the server from the repository root:

```bash
python3 05_solver/server.py --host 127.0.0.1 --port 8080
```

| Endpoint | Purpose |
| --- | --- |
| `GET /health` | Returns `{"status":"ok"}` |
| `POST /solve` | Accepts structured JSON configuration |
| `GET /solve` | Accepts equivalent configuration through query parameters |

The POST body uses this structure:

```json
{
  "type": "kasada",
  "url": "https://example.com",
  "ua_version": 131,
  "kasada_config": {
    "p_js_path": "/integration-id/script-id/p.js",
    "fp_host": "example.com",
    "tl_host": "example.com"
  }
}
```

Create a local JSON file named `request.local.json` with reviewed configuration, then submit it:

```bash
curl -X POST http://127.0.0.1:8080/solve \
  -H 'Content-Type: application/json' \
  --data-binary @request.local.json
```

### Request Fields

| Field | Meaning |
| --- | --- |
| `type` | Defaults to `kasada`; the implementation also accepts `kasada-bypass` |
| `url` | Target URL; its scheme is used when constructing endpoints |
| `user_agent` | Optional user-agent override |
| `ua_version` | Requested Chrome major version; defaults to `131` |
| `kasada_config.p_js_path` | Script path, with or without the final `/p.js` |
| `kasada_config.fp_host` | Host used to fetch the script and construct origin/referer values |
| `kasada_config.tl_host` | Host used for the `/tl` and `/mfc` endpoints |
| `kasada_config.cd_constant` | Optional replacement for the PoW seed |
| `proxy` | Optional client proxy URL |

The server attempts to extract a version identifier and XOR key from the script. If extraction fails, it falls back to built-in defaults. The server's fallback XOR key differs from the constant used by the CLI and async module; this discrepancy needs review.

A successful server result also contains a `response_time` string. A responding health endpoint does not verify the external flow.

## Async Python Interface

The later module exposes:

- `FingerprintBuilder.build()` for the historical fingerprint object.
- `encode_payload()` and `decode_payload()` for the historical payload transformation.
- `PowSolver.solve()` for local proof computation.
- `KasadaSolver.init_session()` for the historical handshake.
- `KasadaSolver.get_headers()` for header construction.
- `KasadaSolver.protected_request()` for the experimental request wrapper.

These APIs must be reviewed against the updated protocol before integration. Running `kasada_full_solver.py` directly also makes a request to an external TLS inspection endpoint as part of its demonstration.

## Payload Inspection

For manual inspection of a previously captured payload:

```bash
python3 05_solver/capture_fingerprint.py
```

The tool prompts for a Base64 request body and attempts to decode it using the historical key and transformation.

For interactive decoding with the alternative tool:

```bash
python3 05_solver/kasada_intercept.py
```

The interceptor can also read a HAR file:

```bash
python3 05_solver/kasada_intercept.py /path/to/private-capture.har
```

Keep HAR files and decoded fingerprint captures outside published source control. A decode failure may mean the key, transformation, or payload layout differs from the archived snapshot.

## Troubleshooting

| Symptom | Checks to perform |
| --- | --- |
| Missing `wreq` or emulation member | Confirm the active virtual environment and dependency API |
| Script fetch or handshake fails | Review endpoint paths, hosts, version, and response details |
| Missing CT or H header | Inspect the actual response and compare it with the archived assumptions |
| Decoder fails | Check the snapshot's XOR key, Base64 body, and expected data structure |
| Server starts but solving fails | Separate application startup from external protocol validation |
| HAR tool cannot find a file | Supply your private capture and replace original absolute paths |
| Local PoW works but headers are rejected | Review CD serialization, challenge configuration, and current protocol behavior |
| A selected browser profile behaves inconsistently | Check the emulation fallback and user-agent construction |

Captured login credentials and authentication headers in the public testing scripts are placeholders. Their original comparisons cannot be reproduced from the sanitized values.

## Required Updates

The next maintained revision should reconcile solver generations, replace outdated source assumptions, verify endpoint behavior, fix path handling, pin dependencies, and add meaningful offline regression checks.

Historical comments claiming broad compatibility or describing a “working” solver are retained in source as part of the archive. Current compatibility remains unverified.
