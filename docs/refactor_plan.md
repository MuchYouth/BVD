# Refactor Plan: Primary vs Experimental Paths

## Purpose

This document classifies the current implementation before refactoring toward the new LLMDFA-first research direction.

No code should be deleted in this phase. The goal is to identify which files remain on the primary path, which files should be demoted to experimental status, and which files are supporting infrastructure or generated artifacts.

## New Research Direction

The primary research path should become:

```text
SARD Juliet C/C++ source
-> build binary
-> Ghidra decompile
-> extract decompiled C-like function code
-> feed code into upstream LLMDFA or a minimal adapter
-> produce LLMDFA trace/dataflow results
-> attach P-code, callsite, and address evidence for the same function
```

The previous P-code-native dataflow analyzer should remain available for comparison and debugging, but it is no longer the primary analysis path.

## Current Primary Path

These files are currently on the executable MVP path. Some will remain primary after refactoring, while others should move to experimental because they implement native P-code dataflow analysis.

Current end-to-end command path:

```text
scripts/run_pipeline.py
-> src.juliet.discovery
-> src.juliet.builder
-> scripts/run_ghidra_extract.py
-> ghidra_scripts/DumpPcodeJson.java
-> scripts/build_dataset.py
-> src.pcode.parser / src.pcode.normalizer
-> src.analysis.source_sink
-> src.analysis.trace_builder
-> src.dataset.writer
```

## Primary Path After Refactor

These files should remain primary or become part of the new primary path because they support Juliet discovery/building, Ghidra execution, binary provenance, dataset writing, or documentation. Some need modification later to route through LLMDFA instead of the native P-code analyzer.

| Path | Current role | Refactor classification | Notes |
| --- | --- | --- | --- |
| `external/LLMDFA/` | Upstream LLMDFA clone | Primary upstream dependency | Treat as imported upstream code. Analyze first, modify minimally, prefer wrappers/adapters. |
| `scripts/discover_juliet.py` | CLI wrapper for Juliet discovery | Primary | Still needed for source corpus discovery. |
| `src/juliet/discovery.py` | Juliet C/C++ manifest discovery | Primary | Still the source of Juliet sample metadata and source-level experiment inputs. |
| `scripts/build_juliet.py` | CLI wrapper for Juliet build | Primary | Still needed for binary generation. |
| `src/juliet/builder.py` | Manifest-based binary build manager | Primary, needs hardening | Still needed, but may need support files/include handling for broader Juliet C/C++ builds. |
| `scripts/run_ghidra_extract.py` | Ghidra headless orchestration | Primary, needs update | Keep orchestration, but update outputs from P-code-only to decompiled code + P-code + callsite/address evidence. |
| `ghidra_scripts/DumpPcodeJson.java` | Ghidra P-code/callsite extractor | Primary evidence extractor, needs expansion or replacement | Should extract decompiled C-like function code as primary LLMDFA input plus P-code/callsite/address evidence. Consider renaming later rather than deleting. |
| `src/dataset/schema.py` | Dataset record schema | Primary/supporting | Should evolve to store LLMDFA result and binary evidence links. |
| `src/dataset/writer.py` | Dataset JSONL writer | Primary/supporting, needs update | Currently expects P-code trace candidates. Should be adapted for LLMDFA results plus evidence. |
| `src/dataset/leakage_check.py` | Model input leakage checks | Primary/supporting | Still useful for source/decompiled code experiments, but rules may need LLMDFA prompt/input awareness. |
| `src/utils/` | Shared IO/logging/hash helpers | Supporting primary | Keep as general infrastructure. |
| `configs/default.yaml` | Pipeline config | Primary, needs update | Add LLMDFA paths, Ghidra decompile output paths, experiment A/B/C settings. |
| `README.md` | User execution order | Primary docs, needs update | Should be rewritten around LLMDFA setup and source-vs-decompiled comparison. |
| `docs/architecture.md` | Current architecture | Primary docs, needs update | Move P-code-native analyzer to optional future/experimental work. |

## New Primary Files To Add Later

The current repository does not yet contain these adapter-level files. They should be added without large upstream LLMDFA rewrites.

| Proposed path | Role |
| --- | --- |
| `docs/llmdfa_mapping.md` | Map upstream LLMDFA entry points, prompts, Tree-sitter usage, API calls, outputs, Juliet support, and required modifications. |
| `adapters/llmdfa/` or `src/llmdfa_adapter/` | Thin wrapper that feeds Juliet source or Ghidra decompiled functions into upstream LLMDFA. |
| `patches/llmdfa/` | Minimal upstream LLMDFA patches if wrappers are insufficient. Each patch should be justified in `docs/llmdfa_mapping.md`. |
| `ghidra_scripts/DumpFunctionEvidence.java` or updated `DumpPcodeJson.java` | Ghidra extractor for decompiled C-like code, P-code ops, callsite/address mapping per function. |
| `scripts/run_llmdfa_source.py` | Experiment A: Juliet original source -> LLMDFA. |
| `scripts/run_llmdfa_decompiled.py` | Experiment B: Ghidra decompiled C-like code -> LLMDFA. |
| `scripts/attach_pcode_evidence.py` | Experiment C: connect LLMDFA function-level results to P-code/callsite/address evidence. |
| `scripts/compare_llmdfa_runs.py` | Compare source-level and decompiled-level LLMDFA results. |

## Experimental Path

These files implement the existing P-code-native source/sink and def-use pipeline. They should not be deleted, but should be marked as experimental / not primary path in follow-up changes.

| Path | Current role | Refactor classification | Reason |
| --- | --- | --- | --- |
| `src/pcode/` | P-code schema, parser, normalizer | Experimental evidence support | Parsing/normalization is still useful for evidence, but P-code-native analysis should not be framed as LLMDFA. |
| `src/analysis/trace_builder.py` | Intraprocedural P-code def-use trace builder | Experimental | This is the custom dataflow analyzer that should no longer be primary. |
| `src/analysis/source_sink.py` | Rule-based source/sink extraction over P-code callsites | Experimental | LLMDFA should own source/sink extraction/synthesis where possible. This remains a comparison/debug baseline. |
| `src/analysis/rule_registry.py` | YAML CWE rule registry for native extraction | Experimental/supporting | Useful for baseline and metadata, but not the primary LLMDFA extraction mechanism. |
| `configs/cwe_rules/` | P-code-native CWE rules | Experimental | These drive the local rule-based analyzer, not upstream LLMDFA. |
| `configs/prompts/pcode_dataflow_review_v1.md` | Prompt for reviewing P-code trace candidates | Experimental | This prompt belongs to the old P-code-native path. |
| `src/analysis/prompts.py` | P-code trace review prompt builder | Experimental | Coupled to the old P-code trace representation. |
| `src/analysis/llm_trace.py` | Mock/OpenAI skeleton for P-code trace review | Experimental | Not upstream LLMDFA API integration. |
| `scripts/build_dataset.py` | Builds dataset from P-code trace candidates | Experimental, later replace or split | Current implementation routes through native P-code trace candidates. |
| `scripts/run_pipeline.py` | End-to-end MVP pipeline | Experimental until rerouted | Current stages assume P-code-native dataset construction. Later it can become the LLMDFA-first orchestrator. |

## Tests To Reclassify

These tests are valuable, but their naming and documentation should reflect that they cover the experimental P-code-native baseline.

| Path | Classification | Notes |
| --- | --- | --- |
| `tests/test_pcode_parser.py` | Experimental/evidence support | Keep for P-code evidence parser stability. |
| `tests/test_pcode_normalizer.py` | Experimental/evidence support | Keep for stable evidence normalization. |
| `tests/test_trace_builder.py` | Experimental | Covers native P-code def-use tracing. |
| `tests/test_source_sink_cwe78.py` | Experimental | Covers local rule-based extraction. |
| `tests/test_source_sink_cwe134.py` | Experimental | Covers local rule-based extraction. |
| `tests/test_rule_registry.py` | Experimental/supporting | Covers local CWE YAML registry. |
| `tests/test_leakage_check.py` | Supporting | Still relevant for future LLMDFA model inputs and outputs. |

## Generated Or Data Artifacts

These paths are generated outputs or local data. They should not define the architecture.

| Path | Classification | Notes |
| --- | --- | --- |
| `data/manifests/` | Generated metadata | Manifest and status outputs. |
| `data/binaries/` | Generated build artifacts/metadata | Binary outputs and build metadata. |
| `data/pcode/` | Generated experimental/evidence output | Will become binary-level evidence, not primary analyzer input. |
| `data/traces/` | Generated experimental output | Current traces are P-code-native baseline traces. |
| `data/datasets/` | Generated datasets | Existing records reflect the old path. |
| `data/ghidra_projects/` | Generated Ghidra workspace | Cache/runtime artifact. |
| `reports/` | Generated reports | Current reports describe MVP P-code-native coverage/statistics. |

## Documentation To Update Next

| Path | Required update |
| --- | --- |
| `docs/llmdfa_mapping.md` | Create after analyzing upstream LLMDFA execution structure. |
| `docs/architecture.md` | Rewrite around LLMDFA-first source/decompiled-code flow. Move native P-code analyzer to experimental/optional future work. |
| `README.md` | Replace current MVP order with LLMDFA setup, Ghidra setup, source LLMDFA run, binary build, decompile, decompiled LLMDFA run, comparison, and evidence attachment. |
| `docs/TODO.md` | Reprioritize around adapters, evidence extraction, and A/B/C experiment structure. |
| `docs/experiment_log.md` | Record the research-direction pivot and current classification. |

## Immediate Refactor Sequence

1. Analyze `external/LLMDFA` and write `docs/llmdfa_mapping.md`.
2. Add explicit experimental markers to `src/pcode/`, `src/analysis/trace_builder.py`, local CWE rule docs, and P-code prompt docs.
3. Expand or replace the Ghidra script so it extracts decompiled C-like code per function alongside P-code ops and callsite/address mapping.
4. Add LLMDFA wrapper/adapter scripts without large upstream edits.
5. Split experiment outputs into:
   - A: Juliet original source -> LLMDFA
   - B: Juliet binary -> Ghidra decompiled C-like code -> LLMDFA
   - C: B + P-code/callsite/address evidence attachment
6. Update architecture and README after the LLMDFA mapping is concrete.

## Current Risk Notes

- The current `scripts/build_dataset.py` result should not be described as an LLMDFA result. It is a local P-code-native trace candidate dataset.
- The current Ghidra extractor does not emit decompiled C-like code, so it cannot yet feed LLMDFA as planned.
- The current LLM adapter is a mock/skeleton P-code reviewer, not the LLMDFA repository's LLM execution path.
- The current CWE YAML rules encode local source/sink extraction logic. Upstream LLMDFA extractor synthesis should be mapped before deciding whether any of these rules remain useful.
- `external/LLMDFA/` is currently untracked in this repository status. Decide later whether it should remain an external clone, submodule, documented dependency, or vendored snapshot.
