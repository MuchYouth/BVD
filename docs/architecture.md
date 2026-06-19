# Binary Vulnerability Trace Dataset Architecture

## Primary Architecture

이 프로젝트의 primary path는 LLMDFA 원본 구조를 중심에 둔다. Ghidra P-code는 분석 엔진이 아니라 LLMDFA 결과를 binary-level address/provenance로 설명하기 위한 evidence이다.

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

짧게 표현하면 다음이다.

```text
Ghidra decompiled C
-> LLMDFA
-> LLMDFA dataflow result
-> P-code/callsite evidence linking
-> dataset
```

## Stage Responsibilities

### Juliet Discovery

`scripts/discover_juliet.py`는 SARD Juliet C/C++ source tree를 스캔하고 `data/manifests/juliet_manifest.jsonl`을 만든다. CWE id, bad/good variant, original filename 같은 label-bearing metadata는 metadata로만 보존한다.

### Juliet Build

`scripts/build_juliet.py`는 selected Juliet source를 binary로 빌드하고 `data/binaries/build_metadata.jsonl`을 기록한다. Dataset model input은 이 metadata를 직접 포함하지 않는다.

### Ghidra Extraction

`scripts/run_ghidra_extract.py`는 Ghidra headless를 실행해 다음 artifact를 만든다.

```text
data/pcode/{cwe}/{variant}/{opt}/{sample_id}.decompiled.jsonl
data/pcode/{cwe}/{variant}/{opt}/{sample_id}.pcode.jsonl
data/pcode/{cwe}/{variant}/{opt}/{sample_id}.callsites.jsonl
```

Primary LLMDFA input은 `{sample_id}.decompiled.jsonl`의 decompiled C-like function code이다. P-code와 callsite JSONL은 source/sink/dataflow를 판단하지 않고, 나중에 LLMDFA result에 evidence로 attach된다.

### LLMDFA Adapter

`src/llmdfa_adapter/input_converter.py`는 Ghidra decompiled output을 anonymized LLMDFA input file과 manifest로 변환한다.

`src/llmdfa_adapter/runner.py`는 upstream LLMDFA checkout 또는 minimal wrapper를 호출한다.

`src/llmdfa_adapter/output_parser.py`는 upstream output을 stable wrapper schema로 정리한다.

### Ghidra Evidence

`src/ghidra_evidence/`는 P-code/callsite JSONL을 evidence로만 다룬다.

- `schema.py`: evidence dataclass
- `loader.py`: P-code/callsite JSONL 최소 parser 연결
- `linker.py`: LLMDFA result에 function entry/function id 기준으로 evidence attach

이 패키지는 source/sink 후보 추출, dataflow 판단, trace 판단을 하면 안 된다.

### Dataset Builder

`scripts/build_dataset.py`는 LLMDFA parsed output을 읽고 Ghidra evidence를 붙인 뒤 final dataset JSONL을 쓴다.

Dataset record는 다음을 분리한다.

- `metadata`: CWE, Juliet variant, source filename, original function name, binary hash, evidence provenance
- `model_input`: anonymized LLMDFA source/sink/dataflow/path result
- `ghidra_evidence`: P-code ops, callsite, address provenance
- `leakage_check`: bad/good/CWE/Juliet/original function name leakage 여부

## Removed From Primary Path

다음 구조는 primary path에서 제거되었다.

```text
P-code JSON
-> custom parser
-> custom source/sink rule
-> custom def-use analyzer
-> custom trace builder
-> custom trace 판단
```

구체적으로 primary pipeline은 더 이상 다음을 호출하지 않는다.

- `src/analysis/source_sink.py`의 P-code-native source/sink extraction
- `src/analysis/trace_builder.py`의 def-use/backward slicing trace construction
- CWE rule registry 기반 P-code-native trace 판단
- `scripts/build_dataset.py`의 P-code def-use trace generation
- `scripts/run_pipeline.py`의 P-code-native trace generation stage

## Future Optional Experiment

P-code-native modules are retained as deprecated experimental code only. They may be moved under `experimental/pcode_native/` later if a separate experiment explicitly needs them.

Current retained experimental files:

- `src/analysis/source_sink.py`
- `src/analysis/trace_builder.py`
- `src/analysis/rule_registry.py`
- `configs/cwe_rules/*.yaml`
- `tests/experimental/*`

They are not part of the primary test suite or primary pipeline.

## Leakage Policy

The following values must stay out of `model_input`.

- `bad`
- `good`
- `CWE`, `CWE78`, `CWE134`, and similar CWE strings
- `Juliet`
- original Juliet filename
- original function name

They may remain in `metadata` for provenance and evaluation.
