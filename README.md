# Binary Vulnerability Trace Dataset MVP

이 저장소는 SARD Juliet C/C++ testcase로부터 binary vulnerability trace dataset을 만들기 위한 연구용 MVP 파이프라인입니다.

Primary path는 LLMDFA 중심입니다. Ghidra P-code/callsite는 LLMDFA 결과에 binary-level evidence를 붙이는 용도로만 사용하며, primary pipeline에서 P-code 기반 source/sink/def-use trace 판단을 직접 수행하지 않습니다.

## 실행 흐름

모든 명령은 기본적으로 `--config configs/default.yaml` 옵션을 받습니다.

1. LLMDFA를 준비합니다.

   ```bash
   python3 scripts/setup_external_repos.py --config configs/default.yaml
   ```

   또는 [configs/default.yaml](/home/dayoung/CVD_BIN/configs/default.yaml)의 `llmdfa.root`가 기존 LLMDFA checkout을 가리키도록 설정합니다.

2. 환경 설정을 확인합니다.

   ```bash
   python3 scripts/run_pipeline.py --config configs/default.yaml --dry-run --limit 1
   ```

   Ghidra를 실제로 실행하려면 `ghidra.install_dir`를 `support/analyzeHeadless`가 들어 있는 Ghidra 설치 디렉터리로 설정합니다.

3. Juliet testcase를 discovery합니다.

   ```bash
   python3 scripts/discover_juliet.py --config configs/default.yaml --cwe CWE78 --limit 5
   ```

4. 선택된 Juliet source를 binary로 빌드합니다.

   ```bash
   python3 scripts/build_juliet.py --config configs/default.yaml --cwe CWE78 --limit 5
   ```

5. Ghidra decompile/evidence extraction을 실행합니다.

   ```bash
   python3 scripts/run_ghidra_extract.py --config configs/default.yaml --cwe CWE78 --limit 5
   ```

   이 단계는 decompiled C-like code, P-code JSONL, callsite JSONL을 모두 생성합니다. Primary LLMDFA input은 decompiled output이고, P-code/callsite는 evidence입니다.

6. Decompiled code를 LLMDFA input으로 변환합니다.

   ```bash
   python3 -m src.llmdfa_adapter.input_converter --input-root data/pcode --output-root data/llmdfa_inputs
   ```

7. LLMDFA를 실행합니다.

   ```bash
   python3 -m src.llmdfa_adapter.runner --llmdfa-root external/LLMDFA --input-manifest data/llmdfa_inputs/manifest.jsonl
   ```

   Unmodified LLMDFA checkout이 converted C/C++ manifest를 직접 소비하지 못하는 경우 wrapper는 `blocked_needs_upstream_patch` 상태를 기록합니다. 이 경우 upstream LLMDFA arbitrary-input/minimal wrapper 연결이 필요합니다.

8. LLMDFA output을 parse합니다.

   ```bash
   python3 -m src.llmdfa_adapter.output_parser --output-root data/llmdfa_outputs --parsed-path data/llmdfa_outputs/parsed_results.jsonl
   ```

9. Ghidra evidence를 붙여 dataset을 생성합니다.

   ```bash
   python3 scripts/build_dataset.py --config configs/default.yaml --cwe CWE78
   ```

## FreeLLMAPI 10-function pilot

현재 `data/pcode`에서 CWE121 4개, CWE134 4개, CWE835 2개의
decompiled function을 선정하고 입력만 확인합니다.

```bash
python3 scripts/run_llmdfa_trace_pilot.py --dry-run
```

FreeLLMAPI는 OpenAI-compatible `POST /v1/chat/completions` endpoint를
사용합니다. Dashboard에서 발급한 unified key를 설정하고 pilot을 실행합니다.

```bash
export FREELLM_API_KEY='freellmapi-your-unified-key'
python3 scripts/run_llmdfa_trace_pilot.py --resume
```

기본 endpoint는 `http://127.0.0.1:3001/v1/chat/completions`, 모델은
`gpt-4o`, 일일 보호 한도는 50회입니다. OpenAI 크레딧을 사용하게 되면
동일한 runner를 다음처럼 전환합니다.

```bash
export OPENAI_API_KEY='...'
python3 scripts/run_llmdfa_trace_pilot.py --provider openai --model gpt-4o --resume
```

## 전체 파이프라인

```bash
python3 scripts/run_pipeline.py --config configs/default.yaml --cwe CWE78 --limit 5
```

Primary stages:

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

## 테스트

Primary test suite는 pytest로 실행합니다.

```bash
python3 -m pytest
```

P-code-native source/sink/trace_builder 테스트는 `tests/experimental/` 아래에 보존되어 있으며 primary suite에서는 제외됩니다.

## 현재 상태

구현된 primary 기능:

- Juliet discovery/build orchestration
- Ghidra decompiled C-like output extraction
- Ghidra P-code/callsite evidence extraction
- LLMDFA input conversion
- LLMDFA wrapper/output parser skeleton
- LLMDFA result와 Ghidra evidence linking
- dataset writing과 leakage check

Deprecated experimental 기능:

- P-code-native source/sink rule extraction
- P-code def-use/backward slicing trace builder
- CWE rule registry 기반 P-code-native trace 판단
