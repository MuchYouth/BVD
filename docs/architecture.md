# Binary Vulnerability Trace Dataset Architecture

## 목표

이 프로젝트는 SARD Juliet C/C++ testcase로부터 binary vulnerability trace dataset을 만들기 위한 재현 가능한 연구용 MVP pipeline을 구축한다. 첫 MVP 대상은 SARD Juliet CWE-78 OS Command Injection이다. 다음 확장 대상으로는 CWE-134 Uncontrolled Format String을 계획한다. Architecture는 전체 Juliet C/C++ CWE corpus로 확장 가능해야 한다.

이 pipeline은 LLMDFA를 P-code에 그대로 적용한다고 주장하지 않는다. 대신 LLMDFA의 핵심 구조인 source/sink extraction, dataflow summarization, path validation을 binary-level P-code input에 맞게 이식한다.

## Pipeline Overview (전체 흐름)

End-to-end 흐름은 다음과 같다.

1. Juliet source
2. Juliet manifest discovery
3. Build manager
4. Binary artifacts
5. Ghidra headless analysis
6. P-code JSONL and callsite JSONL extraction
7. P-code normalizer
8. CWE rule registry
9. Source/sink extractor
10. Trace builder
11. Dataset builder
12. LLM trace reviewer

### Juliet Source 준비

Juliet C/C++ testcase는 `data/raw_juliet/` 아래에 둔다. Repository는 특정 CWE directory layout을 hard-code하지 않아야 한다. Discovery 단계는 Juliet root를 스캔해 CWE directory와 testcase source file을 찾아야 한다.

### Juliet Manifest Discovery

`scripts/discover_juliet.py`는 Juliet testcase를 탐색하고 다음 manifest를 작성한다.

```text
data/manifests/juliet_manifest.jsonl
```

각 manifest row에는 sample id, CWE id, source path, testcase variant, language, 기대되는 Juliet label metadata, discovery status 같은 stable metadata가 포함되어야 한다.

Manifest는 이후 batch execution의 source of truth이다. 이후 단계는 `--cwe`, `--limit`, `--jobs`, `--resume`, `--force` 같은 option으로 manifest에서 작업 대상을 선택해야 한다.

### Build Manager

`scripts/build_juliet.py`는 manifest를 읽고 active CWE testcase를 build한다. MVP는 `-O0`, unstripped binary만 build한다. Bad variant와 good variant는 별도 binary artifact로 build해야 하며, label은 metadata에서 추적하되 `model_input`으로 새지 않아야 한다.

예상 output은 다음과 같다.

```text
data/binaries/{cwe}/{variant}/{opt}/{sample_id}.out
data/binaries/build_metadata.jsonl
```

Build metadata에는 compiler version, compiler flags, source hash, binary hash, build command, build status, error message가 포함되어야 한다.

### Binary Artifacts

Binary는 immutable stage output으로 취급한다. 이후 단계는 `--force`가 주어지지 않는 한 기존 binary를 재사용해야 한다. 재현성과 cache validation을 위해 binary path와 hash는 metadata file에 기록해야 한다.

### Ghidra Headless Analysis

`scripts/run_ghidra_extract.py`는 build된 binary에 대해 Ghidra headless를 실행하고 다음 postScript를 호출한다.

```text
ghidra_scripts/DumpPcodeJson.java
```

예상 Ghidra project output은 다음과 같다.

```text
data/ghidra_projects/
```

예상 extraction output은 다음과 같다.

```text
data/pcode/{cwe}/{variant}/{opt}/{sample_id}.pcode.jsonl
data/pcode/{cwe}/{variant}/{opt}/{sample_id}.callsites.jsonl
```

실패는 반드시 기록해야 하며, 한 sample의 실패가 전체 batch를 중단해서는 안 된다.

### P-code JSONL

Function-level P-code extraction은 dataflow tracing에 필요한 구조를 충분히 보존해야 한다.

- Function identifier
- Entry address
- Basic blocks
- Instruction addresses
- P-code operations
- Varnodes
- Def-use candidates
- Call operations
- 사용 가능한 경우 referenced symbols

`bad`/`good`, CWE string, filename, original function name처럼 label leakage를 일으킬 수 있는 이름은 기본적으로 metadata에만 남겨야 하며 `model_input`에 들어가면 안 된다.

### Callsite JSONL

Callsite extraction은 recovered call target과 argument를 포착해야 한다.

- Caller function id
- Callsite address
- Callee symbol 또는 external target
- Argument index
- Argument varnode
- Argument recovery confidence
- 사용 가능한 경우 calling convention metadata

CWE-78과 CWE-134는 sink definition이 특정 argument position에 의존하므로 call argument recovery가 특히 중요하다.

### P-code Normalizer

`src/pcode/normalizer.py`는 raw Ghidra output을 stable internal representation으로 변환한다. Address, varnode, operation name, call target, function-local identifier를 normalize해야 한다.

Normalizer는 optional symbol anonymization도 지원해야 한다. 이를 통해 function name, filename, CWE id, variant name을 통한 label leakage가 `model_input`에 들어가지 않도록 한다.

### CWE Rule Registry

CWE rule은 Python code 밖에 둔다.

```text
configs/cwe_rules/CWE78.yaml
configs/cwe_rules/CWE134.yaml
```

`src/analysis/rule_registry.py`는 rule YAML file을 동적으로 load하고 source, sink, trace rule definition을 제공한다.

Unsupported CWE는 `unsupported`로 기록해야 하며 pipeline을 crash시키면 안 된다. 이렇게 해야 전체 Juliet analysis support가 준비되기 전에도 전체 Juliet discovery를 수행할 수 있다.

### Source/Sink Extractor

`src/analysis/source_sink.py`는 load된 CWE rule을 normalized P-code와 callsite에 적용한다.

CWE-78의 경우:

- Sources: `argv`, `getenv`, `fgets`, `scanf`, `recv`, `read` 등 external input API
- Sinks: `system`, `popen`, `execl`, `execv`, `execle`, `execve`, `CreateProcess` 등 command execution API
- Sink argument: command 또는 path argument

CWE-134의 경우:

- Sources: `argv`, `getenv`, `fgets`, `scanf`, `recv`, `read` 등 external input string
- Sinks: `printf`, `fprintf`, `sprintf`, `snprintf`, `syslog` 등 format-string API
- Sink argument: format string argument

### Trace Builder

`src/analysis/trace_builder.py`는 normalized P-code, extracted source event, sink callsite argument로부터 source-to-sink trace candidate를 만든다.

MVP는 intraprocedural def-use trace candidate에서 시작한다. 단일 function 안에서 source-derived varnode가 sink argument varnode까지 이어지는 candidate path를 생성해야 한다.

예상 trace output은 다음과 같다.

```text
data/traces/{cwe}/{variant}/{opt}/{sample_id}.trace.jsonl
```

Trace record에는 dataflow node, edge type, source event reference, sink event reference, confidence, validation status, metadata reference가 포함되어야 한다. Label은 LLM output이 아니라 Juliet metadata에서 와야 한다.

### Dataset Builder

`scripts/build_dataset.py`는 trace candidate와 metadata를 dataset JSONL file로 변환한다.

```text
data/datasets/*.jsonl
```

Dataset writer는 다음을 분리해야 한다.

- `metadata`: CWE id, Juliet label, variant, source filename, function identity, binary hash
- `model_input`: label-leaking string이 없는 normalized trace representation
- `target`: Juliet metadata에서만 파생된 label field

### LLM Trace Reviewer

`src/analysis/llm_trace.py`는 MVP에서 mock interface로 유지한다. 실제 LLM integration은 이후로 미룬다. LLM을 ground-truth generator로 취급하면 안 된다. 이후에는 trace candidate를 review, rank, summarize하는 용도로만 사용할 수 있다.

Prompt construction은 `src/analysis/prompts.py`에 두며, prompt는 사용 전에 leakage check를 통과해야 한다.

## MVP Scope (범위)

현재 MVP scope는 의도적으로 좁게 유지한다.

- Active CWE: CWE-78 only
- Next extension: CWE-134
- Input corpus: SARD Juliet C/C++ CWE-78 testcase의 small subset
- Binary type: `-O0`, unstripped
- Variants: bad/good binary를 별도로 build
- Analysis granularity: function-level P-code
- Trace analysis: intraprocedural def-use trace candidate
- Source/sink extraction: rule-based
- LLM API: mock interface only
- Labels: Juliet metadata only

MVP의 목적은 source value가 P-code def-use trace candidate를 통해 command execution sink argument까지 연결될 수 있음을 보이는 것이다.

## Long-Term Extension Direction (장기 확장 방향)

Architecture는 다음을 지원해야 한다.

- Full Juliet C/C++ CWE discovery
- CWE-specific rule registry expansion
- `supported`, `partially_supported`, `unsupported` status tracking
- Manifest-based batch execution
- Large run을 위한 resume 및 cache reuse
- Full pipeline을 중단하지 않는 failed testcase status
- Interprocedural trace expansion
- Stack, heap, pointer alias, structure field를 위한 memory model expansion
- Calling convention 개선
- LLM reviewer, ranker, summarizer expansion
- Rule coverage가 충분히 성숙한 이후의 `active_cwes: all`

## Target CWEs and Active CWEs

`target_cwes`는 장기적인 research interest를 나타낸다. Corpus에서 discovery된 모든 Juliet CWE를 포함할 수 있다.

`active_cwes`는 현재 execution 대상으로 선택한 subset이다. MVP에서는 다음과 같다.

```yaml
active_cwes:
  - CWE78
```

다음 planned addition은 다음과 같다.

```yaml
active_cwes:
  - CWE78
  - CWE134
```

나중에 충분한 rule coverage가 확보되면 다음을 사용할 수 있다.

```yaml
active_cwes: all
```

## Data Leakage Prevention Policy

Dataset construction은 label leakage를 반드시 방지해야 한다.

다음 값은 metadata에만 들어가야 한다.

- Juliet bad/good variant
- CWE id and CWE name
- Source filename
- Original function name
- Testcase directory name
- Ground-truth label

다음 값은 `model_input` 또는 LLM prompt에 직접 나타나면 안 된다.

- `bad`
- `good`
- `CWE78`, `CWE-78`, `CWE134`, `CWE-134`, 또는 다른 CWE string
- Juliet testcase filename
- Label을 암시하는 original function name

Pipeline은 optional symbol anonymization을 지원해야 한다. 예를 들어 original name을 `func_0001`, `bb_0001`, `var_0001`, `call_0001` 같은 stable local identifier로 치환할 수 있어야 한다.

`src/dataset/leakage_check.py`는 dataset writing 또는 LLM review 전에 model input과 prompt를 scan해야 한다. Leakage violation은 기록되어야 하며, debug 목적으로 명시적으로 override하지 않는 한 해당 record가 final dataset에 들어가는 것을 막아야 한다.

## Stage Inputs and Outputs

| Stage | Script or module | Input | Output |
| --- | --- | --- | --- |
| Juliet discovery | `scripts/discover_juliet.py` | `data/raw_juliet/` | `data/manifests/juliet_manifest.jsonl` |
| Build | `scripts/build_juliet.py` | `data/manifests/juliet_manifest.jsonl` | `data/binaries/{cwe}/{variant}/{opt}/{sample_id}.out`, `data/binaries/build_metadata.jsonl` |
| Ghidra extraction | `scripts/run_ghidra_extract.py`, `ghidra_scripts/DumpPcodeJson.java` | Built binaries | `data/pcode/{cwe}/{variant}/{opt}/{sample_id}.pcode.jsonl`, `data/pcode/{cwe}/{variant}/{opt}/{sample_id}.callsites.jsonl` |
| P-code normalization | `src/pcode/normalizer.py` | Raw P-code JSONL and callsite JSONL | Normalized in-memory records 또는 cached normalized JSONL |
| Rule loading | `src/analysis/rule_registry.py` | `configs/cwe_rules/*.yaml` | Loaded CWE rule registry |
| Source/sink extraction | `src/analysis/source_sink.py` | Normalized P-code, callsites, CWE rules | Source and sink event records |
| Trace building | `src/analysis/trace_builder.py` | Source/sink events and normalized def-use graph | `data/traces/{cwe}/{variant}/{opt}/{sample_id}.trace.jsonl` |
| Dataset writing | `scripts/build_dataset.py`, `src/dataset/writer.py` | Trace records and metadata | `data/datasets/*.jsonl` |
| Leakage checking | `src/dataset/leakage_check.py` | Model input and prompt text | Leakage report and pass/fail status |
| MVP stats | `scripts/report_mvp_stats.py` | Manifest, build metadata, traces, datasets | `reports/` |
| Coverage matrix | `scripts/report_coverage_matrix.py` | Rule registry and manifest | `reports/coverage_matrix.*` |

## Batch, Resume, and Cache Behavior

모든 stage는 restart 가능해야 한다. 공통 execution option은 다음을 포함해야 한다.

- `--cwe`: 하나 이상의 CWE 선택
- `--limit`: manifest row 개수 제한
- `--jobs`: parallel worker count
- `--resume`: successful existing output skip
- `--force`: output이 이미 있어도 rebuild 또는 re-extract

Stage status는 JSONL metadata로 저장해야 한다. Failed sample이 전체 pipeline을 중단해서는 안 된다.
