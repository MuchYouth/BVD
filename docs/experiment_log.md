# Experiment Log Requirements

이 문서는 각 dataset generation run을 재현하기 위해 필요한 정보를 정의한다.

각 experiment는 stable run id를 가져야 하며, `reports/` 또는 `data/manifests/` 아래에 machine-readable log를 남겨야 한다. 사람이 읽기 위한 note는 이 파일에 추가할 수 있지만, canonical run metadata는 JSON 또는 JSONL이어야 한다.

## Run Identity

다음을 기록한다.

- Run id
- Run timestamp
- Operator
- Project가 Git repository 안에 있을 경우 Git commit hash
- 가능한 경우 dirty working tree status
- Pipeline command
- Config file path
- Active CWEs
- Target CWEs
- Limit, resume, force, jobs settings

## Environment

다음을 기록한다.

- OS name and version
- Kernel version
- CPU architecture
- Container image 또는 VM image를 사용한 경우 해당 image
- Python version
- Java version
- Ghidra version
- Ghidra installation path
- Ghidra headless command path
- Relevant environment variables

## Juliet Corpus

다음을 기록한다.

- Juliet version
- Juliet download URL 또는 source
- Juliet root path
- 가능한 경우 corpus hash 또는 archive hash
- Discovery된 CWE directory 수
- Discovery된 testcase 수
- Active CWE testcase로 선택된 수

## Build Configuration

다음을 기록한다.

- Compiler name
- Compiler version
- Compiler path
- 가능한 경우 compiler target triple
- CFLAGS and CXXFLAGS
- Linker flags
- Optimization level
- Strip setting
- Debug symbol setting
- Include paths
- Library paths
- Build command template

MVP에서 기대하는 build profile은 다음과 같다.

```text
optimization: -O0
strip: false
debug_symbols: true when feasible
```

## Binary Metadata

각 binary마다 다음을 기록한다.

- Sample id
- CWE id
- Variant
- Source path metadata
- Output binary path
- Build status
- Build start and end time
- Compiler command
- Compiler stdout path
- Compiler stderr path
- Source file hash
- Binary hash
- Binary size
- Binary format
- Architecture

## Ghidra Extraction

각 Ghidra extraction run마다 다음을 기록한다.

- Sample id
- Binary path
- Binary hash
- Ghidra project path
- Ghidra script name
- Ghidra script version 또는 hash
- Import status
- Analysis status
- Extraction status
- Extracted function count
- Extracted P-code operation count
- Extracted callsite count
- Ghidra stdout path
- Ghidra stderr path
- Ghidra extraction errors

## CWE Rule Versions

다음을 기록한다.

- Rule registry version
- Rule file path
- Rule file hash
- CWE rule id
- CWE rule status
- Source rule version
- Sink rule version
- Trace rule version
- 해당하는 경우 unsupported CWE reason

## Trace Generation

각 trace generation batch마다 다음을 기록한다.

- Trace builder version
- P-code normalizer version
- Input P-code file path
- Input P-code file hash
- Input callsite file path
- Input callsite file hash
- Source event 수
- Sink event 수
- Trace candidate 수
- Validated trace candidate 수
- Rejected trace candidate 수
- Failure reason count

## Dataset Generation

다음을 기록한다.

- Dataset writer version
- Dataset schema version
- Input trace paths
- Input metadata paths
- Output dataset path
- Dataset hash
- Record 수
- Label distribution
- CWE distribution
- Variant distribution
- 사용하는 경우 train, validation, test split policy
- Leakage check version
- Leakage check result
- Leakage violation count

## LLM Reviewer

MVP는 mock LLM interface만 사용한다. 이후 real LLM review가 활성화되면 다음을 기록한다.

- Prompt version
- Prompt template hash
- LLM provider
- LLM model
- LLM API version
- Temperature
- Top-p
- Max output tokens
- 지원되는 경우 random seed
- Reviewer mode
- Input redaction policy
- Prompt submission 전 leakage check result

LLM output은 Juliet-derived label을 절대 overwrite하면 안 된다.

## Manual Notes

각 experiment에서 사람이 읽기 위한 observation은 이 section에 적는다.

### Run Template

```text
Run id:
Date:
Active CWEs:
Juliet version:
Compiler:
Ghidra version:
Optimization:
Summary:
Known issues:
Next action:
```
