# LLMDFA-Primary Refactor Report

## Removed From Primary Path

Primary pipeline no longer calls P-code-native source/sink/trace generation.

Removed primary calls:

- `scripts/build_dataset.py` no longer imports or calls `src.analysis.source_sink.extract_source_sink_pairs`.
- `scripts/build_dataset.py` no longer imports or calls `src.analysis.trace_builder.build_trace_candidates`.
- `scripts/build_dataset.py` no longer loads CWE rules to decide source/sink/trace paths.
- `scripts/run_pipeline.py` no longer has P-code-native trace generation behavior.
- Primary dataset writing no longer depends on `SourceCandidate`, `SinkCandidate`, or `TraceCandidate`.

The primary analysis decision path is now LLMDFA output only.

## Experimental Code Retained

The following P-code-native analysis files were not deleted, but are marked deprecated and excluded from the primary path.

- `src/analysis/source_sink.py`
- `src/analysis/trace_builder.py`
- `src/analysis/rule_registry.py`
- `configs/cwe_rules/*.yaml`

The related tests were moved under:

- `tests/experimental/test_source_sink_cwe78.py`
- `tests/experimental/test_source_sink_cwe134.py`
- `tests/experimental/test_trace_builder.py`
- `tests/experimental/test_rule_registry.py`

`pytest.ini` excludes `tests/experimental` from the primary test suite.

## Ghidra Evidence Kept

The refactor preserves Ghidra extraction and evidence loading.

Kept:

- Ghidra decompiled C-like function extraction
- Ghidra P-code op extraction
- Ghidra callsite/address extraction
- Minimal P-code/callsite JSONL parser
- Evidence linking from LLMDFA result to function entry/function id

New evidence-only modules:

- `src/ghidra_evidence/schema.py`
- `src/ghidra_evidence/loader.py`
- `src/ghidra_evidence/linker.py`

These modules must not perform source/sink/dataflow/trace judgment.

## New Primary Pipeline

```text
discover_juliet
build_juliet
run_ghidra_extract
convert_ghidra_to_llmdfa_input
run_llmdfa
parse_llmdfa_output
attach_ghidra_evidence
build_dataset
report
```

Architecture:

```text
SARD Juliet C/C++ source
-> build binary
-> Ghidra decompile
-> decompiled C-like function code
-> LLMDFA input converter
-> LLMDFA original repo or minimal wrapper
-> LLMDFA source/sink/dataflow/path result
-> P-code/callsite/address evidence linking
-> dataset
```

## Primary vs Experimental Path

| Area | Primary path | Experimental/deprecated path |
| --- | --- | --- |
| Source artifact | SARD Juliet C/C++ source | P-code JSON as analysis input |
| Binary stage | Build binary from Juliet metadata | N/A |
| Ghidra output | Decompiled C plus P-code/callsite evidence | Normalized P-code as model input |
| Analysis engine | LLMDFA original repo or minimal wrapper | Custom P-code source/sink rules |
| Source/sink decision | LLMDFA output | `src/analysis/source_sink.py` |
| Dataflow/trace decision | LLMDFA output | `src/analysis/trace_builder.py` def-use/backward slicing |
| Rule registry | Not used for primary dataflow | `src/analysis/rule_registry.py`, `configs/cwe_rules/*.yaml` |
| Evidence linking | `src/ghidra_evidence/loader.py`, `src/ghidra_evidence/linker.py` | N/A |
| Dataset writing | `src/dataset/writer.py` from LLMDFA result + evidence | Old trace-candidate dataset writer removed |
| Tests | `tests/test_llmdfa_primary_pipeline.py`, parser/leakage tests | `tests/experimental/*` |

## TODO

- Connect upstream LLMDFA to converted decompiled C/C++ inputs, or add a minimal wrapper that consumes `data/llmdfa_inputs/manifest.jsonl`.
- Tighten LLMDFA output parsing once the exact upstream result schema is fixed for this project.
- Add an integration smoke test with a real Ghidra run when Ghidra is available in the environment.
- Consider physically moving deprecated P-code-native modules into `experimental/pcode_native/` after downstream imports are audited.
- Decide whether `configs/cwe_rules` should remain for reports only or move with the experimental P-code-native code.

## Example Commands

```bash
python3 scripts/discover_juliet.py --config configs/default.yaml --cwe CWE78 --limit 5
python3 scripts/build_juliet.py --config configs/default.yaml --cwe CWE78 --limit 5
python3 scripts/run_ghidra_extract.py --config configs/default.yaml --cwe CWE78 --limit 5
python3 -m src.llmdfa_adapter.input_converter --input-root data/pcode --output-root data/llmdfa_inputs
python3 -m src.llmdfa_adapter.runner --llmdfa-root external/LLMDFA --input-manifest data/llmdfa_inputs/manifest.jsonl
python3 -m src.llmdfa_adapter.output_parser --output-root data/llmdfa_outputs --parsed-path data/llmdfa_outputs/parsed_results.jsonl
python3 scripts/build_dataset.py --config configs/default.yaml --cwe CWE78
```
