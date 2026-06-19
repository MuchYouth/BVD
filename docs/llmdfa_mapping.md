# LLMDFA Mapping

## Principle

LLMDFA is treated as an upstream source-level dataflow analyzer. This project should not reimplement LLMDFA on P-code and should not force P-code into LLMDFA internals.

The intended integration is:

```text
Ghidra decompiled C-like function code
-> anonymized source files
-> upstream LLMDFA entry point or minimal upstream-compatible adapter
-> LLMDFA source/sink/dataflow/path-validation output
-> attach P-code/callsite/address evidence by function_id
```

P-code is binary-level evidence only.

## Upstream Entry Point

Current upstream entry point:

```text
external/LLMDFA/src/run_llmdfa.py
```

README command shape:

```bash
cd external/LLMDFA/src
python run_llmdfa.py --bug-type osci --model-name gpt-4o-mini \
  -syn-parser -fscot -syn-solver \
  --solving-refine-number 3 \
  --analysis-mode single
```

The current upstream script maps `--bug-type` to one of three Java Juliet benchmark directories:

| `--bug-type` | Upstream project |
| --- | --- |
| `dbz` | `benchmark/juliet-test-suite-DBZ` |
| `xss` | `benchmark/juliet-test-suite-XSS` |
| `osci` | `benchmark/juliet-test-suite-CI` |

## Current Upstream Assumptions

The current LLMDFA checkout assumes:

- Java source files under `external/LLMDFA/benchmark/{project}`.
- Java Tree-sitter grammar loaded from `external/LLMDFA/lib/build/my-languages.so`.
- Java AST node types such as `method_invocation`, `method_declaration`, `class_declaration`, and `field_declaration`.
- Juliet Java naming conventions and labels for its built-in evaluation.
- LLM config through `OPENAI_API_KEY`.
- Output logs under `external/LLMDFA/log/{model}/{mode}/{case}`.

Therefore, unmodified upstream LLMDFA cannot yet consume arbitrary anonymized C/C++ files generated from Ghidra decompilation.

## Wrapper Components

| Path | Role | Upstream modification |
| --- | --- | --- |
| `scripts/setup_external_repos.py` | Clone `external/LLMDFA` if missing, otherwise inspect checkout state. | None |
| `src/llmdfa_adapter/input_converter.py` | Convert Ghidra `{sample_id}.decompiled.jsonl` rows to anonymized source files. | None |
| `src/llmdfa_adapter/runner.py` | Build and optionally invoke the upstream `run_llmdfa.py` command. Blocks by default for converted C/C++ inputs until upstream arbitrary-input support exists. | None |
| `src/llmdfa_adapter/output_parser.py` | Parse upstream JSON logs into a stable wrapper schema separating source/sink, dataflow, and path-validation results. | None |

## Input Mapping Table

| LLMDFA original input | Our decompiled input | Required conversion | Original code modification needed? | Minimal modification if needed |
| --- | --- | --- | --- | --- |
| Java Juliet benchmark directory under `external/LLMDFA/benchmark/{project}` | Ghidra `{sample_id}.decompiled.jsonl` with function-level `decompiled_code` | Write each function to `data/llmdfa_inputs/{anonymized_sample_id}/func_0001.c` or `.cpp`; replace original function name with `function_id`; redact `CWE*`, `bad`, `good`, `Juliet` tokens from code/path. | Yes, for real analysis of C/C++ decompiled inputs. | Add an upstream entry point that accepts `--input-file` or `--input-dir` and `--language c/cpp` instead of hardcoded Java benchmark projects. |
| Java Tree-sitter parser configured in `TSAgent/TS_parser.py` | C-like or C++-like decompiler output | The wrapper emits C/C++ source files, but parser node names differ from Java. | Yes. | Generalize `TSParser`/`TSAnalyzer` by language and load tree-sitter-c/tree-sitter-cpp grammars; map function definitions, calls, params, returns, if/switch nodes for C/C++. |
| Upstream synthesized/manual source/sink extractors for Java bug types | Decompiled C/C++ functions from Juliet binaries | Keep code source-level; do not convert to P-code. Source/sink specs may need C/C++ API names. | Probably yes for robust C/C++ support. | Add C/C++ spec files or bug-type mapping for C/C++ command injection and format-string APIs while preserving upstream extractor architecture. |
| Built-in Juliet Java label logic in `BatchRun.examineBugReport` | Labels tracked outside LLMDFA in our manifest/evidence metadata | Do not expose labels to LLMDFA input. Evaluate outside LLMDFA wrapper. | Yes if using upstream evaluation routine directly. | Add a no-label/custom-eval mode that emits raw LLMDFA findings without Java Juliet TP/FP labeling. |
| Output under `external/LLMDFA/log/{model}/{mode}/{case}` | Standard records in `data/llmdfa_outputs/parsed_results.jsonl` | Parse `report_summary.json` and other JSON logs; preserve raw payloads. | No for coarse parsing; maybe for richer trace extraction. | If needed, add upstream JSON export for source/sink facts, summaries, and validation decisions. |

## Decompiled Input Conversion

`src/llmdfa_adapter/input_converter.py` reads:

```text
data/ghidra_decompiled/**/*.decompiled.jsonl
```

and writes:

```text
data/llmdfa_inputs/{anonymized_sample_id}/func_0001.c
data/llmdfa_inputs/manifest.jsonl
```

The converter intentionally anonymizes:

- output sample directory names,
- output function filenames,
- original function names inside code when recoverable,
- `CWE*`, `bad`, `good`, and `Juliet` strings.

The manifest retains original ids and function entries as metadata for later evidence joining. LLMDFA should receive the anonymized source files, not the metadata.

## Runner Behavior

`src/llmdfa_adapter/runner.py` builds the upstream command but does not modify `external/LLMDFA`.

By default, when pointed at converted decompiled C/C++ inputs, it records:

```text
status = blocked_needs_upstream_patch
```

This is intentional. Running unmodified `external/LLMDFA/src/run_llmdfa.py` would analyze upstream Java demo benchmarks, not our converted C/C++ inputs.

For smoke-testing the upstream checkout only, pass:

```bash
python3 -m src.llmdfa_adapter.runner --allow-upstream-benchmark-run
```

That mode validates that the upstream entry point can run, but it should not be interpreted as analyzing Ghidra decompiled code.

## Output Schema

`src/llmdfa_adapter/output_parser.py` emits JSONL records with:

| Field | Meaning |
| --- | --- |
| `record_id` | Stable parser-side id. |
| `source_file` | Best-effort source/case name inferred from upstream output. |
| `source_sink_result` | Source/sink extraction result if present. |
| `dataflow_result` | Dataflow/bug candidate/report result if present. |
| `path_validation_result` | Path validation result if present. |
| `raw_output` | Original upstream JSON payload. |
| `warnings` | Missing-field or compatibility warnings. |

## Patch Notes To Carry Forward

No upstream files have been modified.

Minimum upstream-compatible changes needed for real decompiled C/C++ analysis:

1. Add arbitrary `--input-file` / `--input-dir` support to `run_llmdfa.py` or a sibling upstream entry point.
2. Generalize Tree-sitter parsing from Java-only to `--language c/cpp`.
3. Add C/C++ node mappings for functions, calls, arguments, returns, branches, and field/global access.
4. Add a raw-results export mode that does not depend on Java Juliet TP/FP label heuristics.
5. Keep P-code outside LLMDFA. Join P-code evidence after LLMDFA emits source-level findings.
