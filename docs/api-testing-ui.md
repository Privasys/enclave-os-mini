# API Testing — WIT-Based Interactive API Explorer

<img width="910" height="747" alt="api-testing-page" src="https://github.com/user-attachments/assets/f20d3818-c2a7-43ef-b004-4db50439f6c4" />

## Overview

The API Testing tab provides an interactive interface for calling WASM application functions through the **Connect protocol**. It introspects the deployed application's WIT (WebAssembly Interface Types) schema to auto-generate a typed request builder with parameter inputs, function signatures, and response display — functioning as a specialized API explorer for enclave-hosted WASM applications.

## Architecture

```
Browser                Management Service              Enclave
  │                         │                             │
  │  GET /apps/{id}/schema  │                             │
  ├────────────────────────►│  wasm_schema (RA-TLS)       │
  │                         ├────────────────────────────►│
  │                         │◄────────────────────────────┤
  │◄────────────────────────┤  { functions, interfaces }  │
  │                         │                             │
  │  POST /apps/{id}/rpc/fn │                             │
  ├────────────────────────►│  connect_call (RA-TLS)      │
  │                         ├────────────────────────────►│
  │                         │◄────────────────────────────┤
  │◄────────────────────────┤  { status, returns }        │
  │                         │                             │
```

### Protocol Flow

1. **Schema Discovery**: On tab load, the frontend calls `GET /api/v1/apps/{id}/schema`. The management service sends a `wasm_schema` command to the enclave over RA-TLS, which returns the WIT-derived schema of all exported functions.

2. **RPC Calls**: When the user clicks Send, the frontend calls `POST /api/v1/apps/{id}/rpc/{function}` with a JSON body of named parameters. The management service forwards this as a `connect_call` over RA-TLS to the enclave, which executes the WASM function and returns the result.

## WIT Schema Model

The schema is derived from the WASM component's [WIT](https://component-model.bytecodealliance.org/design/wit.html) (WebAssembly Interface Types) definition. The enclave parses the compiled `.cwasm` module's type information and exposes it as a structured schema.

### Schema Types

```typescript
interface AppSchema {
    name: string;           // App name (e.g., "wasm-app-example")
    hostname: string;       // App hostname (e.g., "wasm-app-example.apps.privasys.org")
    functions: FunctionSchema[];    // Top-level exported functions
    interfaces: InterfaceSchema[];  // Exported interfaces with grouped functions
}

interface FunctionSchema {
    name: string;
    params: ParamSchema[];
    results: ParamSchema[];
}

interface ParamSchema {
    name: string;
    type: WitType;
}
```

### WIT Type System

The `WitType` structure maps the WebAssembly Component Model's type system to JSON, supporting all WIT primitive and compound types:

| WIT Kind | Example | JSON Representation |
|----------|---------|---------------------|
| `string` | `string` | `{ "kind": "string" }` |
| `bool` | `bool` | `{ "kind": "bool" }` |
| `u8`..`u64`, `s8`..`s64` | `u32` | `{ "kind": "u32" }` |
| `f32`, `f64` | `f64` | `{ "kind": "f64" }` |
| `char` | `char` | `{ "kind": "char" }` |
| `list<T>` | `list<string>` | `{ "kind": "list", "element": { "kind": "string" } }` |
| `option<T>` | `option<u32>` | `{ "kind": "option", "inner": { "kind": "u32" } }` |
| `result<O, E>` | `result<string, string>` | `{ "kind": "result", "ok": {...}, "err": {...} }` |
| `record` | named fields | `{ "kind": "record", "fields": [{ "name": "x", "type": {...} }] }` |
| `tuple<A, B>` | `tuple<u32, string>` | `{ "kind": "tuple", "elements": [{...}, {...}] }` |
| `enum` | `enum { a, b }` | `{ "kind": "enum", "names": ["a", "b"] }` |
| `variant` | tagged union | `{ "kind": "variant", "cases": [{ "name": "x", "type": {...} }] }` |
| `flags` | bit flags | `{ "kind": "flags", "names": ["read", "write"] }` |

## UI Components

### 1. Endpoint Bar

The top of the request builder shows a styled endpoint bar with:

- **POST** method badge (emerald accent)
- **Function selector** dropdown showing the full RPC path: `/rpc/{app-name}/{function-name}`
- **Send** button (blue accent)

The dropdown lists all functions from both:
- Top-level exports (`schema.functions`)
- Interface exports (`schema.interfaces[].functions`), prefixed with `{interface-name}.{function-name}`

### 2. Function Signature

Below the endpoint bar, the selected function's WIT signature is displayed with syntax highlighting:

```
fn kv-store(key: string, value: string) → string
```

Color coding:
- `fn` keyword in blue
- Function name in bold
- Parameter names in muted text
- Parameter types in purple
- Return types in emerald

### 3. Parameter Inputs

The PARAMETERS section generates **type-aware input controls** for each function parameter:

| WIT Type | Input Control |
|----------|--------------|
| `string`, `char` | Text input with placeholder |
| `bool` | Toggle switch (true/false) |
| `u8`..`u64`, `s8`..`s64`, `f32`, `f64` | Number input |
| `enum` | Dropdown select with enum variants |
| `list`, `record`, `variant`, `option`, other compound types | JSON textarea (auto-parses) |

Default values are generated based on type:
- Strings → `""`
- Numbers → `0`
- Booleans → `false`
- Lists → `[]`
- Options → `null`
- Records → object with default-valued fields

### 4. Response Panel

After sending a request, the response panel shows:

- **Status badge**: `200 OK` (green dot) or `Error` (red dot)
- **Elapsed time**: Request duration in milliseconds
- **JSON body**: Pretty-printed response with syntax highlighting
- **Copy** button

Successful responses from the enclave follow this format:

```json
{
  "status": "ok",
  "returns": [
    {
      "type": "string",
      "value": "stored: test-1"
    }
  ]
}
```

Error responses show the error message in a red-tinted panel.

### 5. Call History

A scrollable history panel tracks the last 20 calls with:

- **Status dot**: Green (success) or red (error)
- **Function name**: Monospace font
- **Elapsed time**: Duration in milliseconds
- **Timestamp**: `HH:MM:SS` format

Clicking a history entry **replays** it — restoring the function selection, parameter values, and response. The history is session-local (not persisted).

### 6. Keyboard Shortcut

Press **Ctrl+Enter** (or **Cmd+Enter** on Mac) to send the current request from anywhere in the form.

## API Reference

### `GET /api/v1/apps/{id}/schema`

Returns the WIT-derived schema for the deployed WASM application.

**Response:**
```json
{
  "status": "schema",
  "schema": {
    "name": "wasm-app-example",
    "hostname": "wasm-app-example.apps.privasys.org",
    "functions": [
      {
        "name": "hello",
        "params": [],
        "results": [{ "name": "", "type": { "kind": "string" } }]
      },
      {
        "name": "kv-store",
        "params": [
          { "name": "key", "type": { "kind": "string" } },
          { "name": "value", "type": { "kind": "string" } }
        ],
        "results": [{ "name": "", "type": { "kind": "string" } }]
      }
    ],
    "interfaces": []
  }
}
```

### `POST /api/v1/apps/{id}/rpc/{function}`

Calls a WASM function with named parameters.

**Request:**
```json
{
  "key": "test-1",
  "value": "value-1"
}
```

**Response (success):**
```json
{
  "status": "ok",
  "returns": [
    {
      "type": "string",
      "value": "stored: test-1"
    }
  ]
}
```

**Response (error):**
```json
{
  "status": "error",
  "message": "function not found: unknown-fn"
}
```

## Connect Protocol

The API Testing interface is a frontend for the **Connect protocol** — a typed RPC layer that transforms WIT function exports into HTTP-like endpoints.

### Enclave-Side Wire Format

Under the hood, the management service sends frames over RA-TLS using the length-delimited binary protocol:

**Schema request:**
```json
{
  "type": "wasm_schema",
  "auth": "<service_jwt>",
  "name": "wasm-app-example"
}
```

**RPC request:**
```json
{
  "type": "connect_call",
  "auth": "<user_jwt>",
  "name": "wasm-app-example",
  "function": "kv-store",
  "params": {
    "key": "test-1",
    "value": "value-1"
  }
}
```

The enclave deserializes the params into WASM Component Model values using the WIT type metadata, calls the function, and serializes the results back.

### Security Model

| Aspect | Detail |
|--------|--------|
| Transport | All RPC calls travel over RA-TLS (TLS with SGX quote) |
| Schema auth | Service JWT with `manager` role (auto-generated by management service) |
| RPC auth | User's JWT — `connect_call` does not require a platform role |
| Isolation | Each WASM function runs in its own sandboxed instance inside the SGX enclave |
| Input validation | WIT types enforce parameter shapes at the WASM boundary |
