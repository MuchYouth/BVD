# Ghidra Output Schema

## Purpose

Ghidra extraction now produces decompiled C-like function code as the primary input for LLMDFA, while preserving P-code and callsite records as binary-level evidence.

This stage does not perform source/sink classification, dataflow tracing, vulnerability classification, or LLMDFA analysis. It only extracts function-level artifacts from the binary.

## Runner

The runner is:

```text
scripts/run_ghidra_extract.py
```

It invokes Ghidra `analyzeHeadless` with:

```text
ghidra_scripts/DumpDecompileAndPcode.java
```

For each successful build metadata record, outputs are written under:

```text
data/pcode/{cwe}/{variant}/{opt_level}/{sample_id}.decompiled.jsonl
data/pcode/{cwe}/{variant}/{opt_level}/{sample_id}.pcode.jsonl
data/pcode/{cwe}/{variant}/{opt_level}/{sample_id}.callsites.jsonl
data/pcode/{cwe}/{variant}/{opt_level}/{sample_id}.ghidra_errors.jsonl
data/pcode/{cwe}/{variant}/{opt_level}/{sample_id}.ghidra.log
```

The directory name remains `data/pcode` for compatibility with existing configuration, but the primary output is now `{sample_id}.decompiled.jsonl`.

## Primary LLMDFA Input

LLMDFA should consume `decompiled_code` from `{sample_id}.decompiled.jsonl` first.

P-code and callsite JSONL files should be used to attach binary-level evidence to LLMDFA results after LLMDFA has analyzed the decompiled C-like code.

## Function Identity

Each function receives a stable per-binary extraction id:

```text
func_0001
func_0002
...
```

The `function_id` field is shared across:

- `{sample_id}.decompiled.jsonl`
- `{sample_id}.pcode.jsonl`
- `{sample_id}.callsites.jsonl`
- `{sample_id}.ghidra_errors.jsonl`

Use `function_id` plus `function_entry` to join decompiled code, P-code operations, callsites, and errors for the same binary function.

## Decompiled JSONL

File:

```text
{sample_id}.decompiled.jsonl
```

One row is emitted per function visited in `currentProgram`.

Fields:

| Field | Type | Description |
| --- | --- | --- |
| `sample_id` | string | Sample id passed from the pipeline. |
| `binary_name` | string | Ghidra `currentProgram` executable name. |
| `function_id` | string | Stable per-extraction function id such as `func_0001`. |
| `original_function_name` | string | Function name recovered by Ghidra. Metadata/evidence only. |
| `function_entry` | string | Function entry address. |
| `decompiled_code` | string | C-like code from `DecompileResults.getDecompiledFunction().getC()`. |
| `decompile_success` | boolean | Whether Ghidra reported a completed decompile. |
| `warnings` | array[string] | Non-fatal extraction warnings. |

Notes:

- A failed decompile still emits a row with `decompile_success=false` and empty `decompiled_code`.
- This file is the intended input surface for LLMDFA adapters.

Example:

```json
{"sample_id":"sample_001","binary_name":"sample_001.out","function_id":"func_0001","original_function_name":"main","function_entry":"00101139","decompiled_code":"int main(...) { ... }","decompile_success":true,"warnings":[]}
```

## P-code JSONL

File:

```text
{sample_id}.pcode.jsonl
```

Rows are emitted for P-code operations from `HighFunction.getPcodeOps()` when decompilation succeeds and a `HighFunction` is available.

Fields:

| Field | Type | Description |
| --- | --- | --- |
| `sample_id` | string | Sample id passed from the pipeline. |
| `function_id` | string | Join key for the decompiled function row. |
| `function_entry` | string | Function entry address. |
| `op_seq` | integer | Function-local P-code operation sequence number. |
| `op_address` | string | Address associated with the P-code sequence number. |
| `mnemonic` | string | P-code mnemonic, for example `CALL`, `COPY`, `LOAD`, or `STORE`. |
| `output_varnode` | object or null | Output varnode for the operation. |
| `input_varnodes` | array[object] | Input varnodes for the operation. |

Varnode object fields:

| Field | Type |
| --- | --- |
| `space` | string |
| `address` | string |
| `offset` | integer |
| `size` | integer |
| `is_constant` | boolean |
| `is_unique` | boolean |
| `is_register` | boolean |
| `is_address` | boolean |
| `is_addr_tied` | boolean |

## Callsites JSONL

File:

```text
{sample_id}.callsites.jsonl
```

Rows are emitted for `CALL`, `CALLIND`, and `CALLOTHER` P-code operations.

Fields:

| Field | Type | Description |
| --- | --- | --- |
| `sample_id` | string | Sample id passed from the pipeline. |
| `function_id` | string | Join key for the decompiled function row. |
| `function_entry` | string | Function entry address. |
| `call_address` | string | Address associated with the call P-code op. |
| `call_target_name` | string | Primary symbol name at the target address when available. Empty if unresolved. |
| `raw_input_varnodes` | array[object] | Raw P-code input varnodes for the call op. |
| `recovered_arguments` | array[object] | Best-effort argument list derived from raw call inputs after the target input. |
| `warnings` | array[string] | Non-fatal callsite extraction warnings. |

`recovered_arguments` objects currently use:

| Field | Type | Description |
| --- | --- | --- |
| `index` | integer | Zero-based argument index. |
| `varnode` | object | Varnode associated with the argument. |

## Error JSONL

File:

```text
{sample_id}.ghidra_errors.jsonl
```

Rows are emitted for decompiler failures or runner-level failures.

Fields:

| Field | Type | Description |
| --- | --- | --- |
| `sample_id` | string | Sample id passed from the pipeline. |
| `binary_name` | string | Binary name or file name. |
| `function_id` | string | Function id when known. |
| `original_function_name` | string | Ghidra function name when known. |
| `function_entry` | string | Function entry address when known. |
| `error_type` | string | Machine-readable error category. |
| `message` | string | Error details. |
| `logged_at` | string | Present for runner-level errors appended by `scripts/run_ghidra_extract.py`. |

## Non-Goals

This extraction stage must not:

- decide sources or sinks,
- build source-to-sink traces,
- classify vulnerabilities,
- call an LLM,
- claim that P-code evidence is an LLMDFA implementation.

The intended interpretation is: Ghidra decompiled code is connected to LLMDFA input, and P-code/callsite/address records are stored as binary-level evidence.
