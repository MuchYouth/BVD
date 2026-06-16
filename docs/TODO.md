# TODO

## Must Do for MVP

- [done] `configs/`, `scripts/`, `ghidra_scripts/`, `src/`, `data/`, `reports/`, `tests/` 아래에 project directory skeleton 생성.
- [done] `target_cwes`, `active_cwes`, Juliet root, output root, build profile, Ghidra path, cache policy, batch option을 포함한 `configs/default.yaml` 정의.
- [done] `configs/cwe_rules/CWE78.yaml` 정의.
- [done] 다음 extension을 위한 preliminary `configs/cwe_rules/CWE134.yaml` 추가.
- [done] 특정 CWE를 hard-code하지 않는 Juliet discovery 구현.
- [done] `data/manifests/juliet_manifest.jsonl` 작성.
- [done] `--cwe`, `--limit`, active CWE config 기반 manifest filtering 구현.
- [done] 작은 CWE-78 subset을 위한 build manager 구현.
- [done] Bad variant와 good variant를 별도로 build.
- [done] MVP에서는 `-O0`, unstripped binary만 build.
- [done] Build metadata와 failed build status를 JSONL로 작성.
- [done] Ghidra headless wrapper 구현.
- [done] Function-level P-code JSONL과 callsite JSONL을 출력하는 `DumpPcodeJson.java` 구현.
- [done] P-code schema definition 구현.
- [done] P-code parser와 normalizer 구현.
- [done] YAML file에서 rule registry를 load하도록 구현.
- [done] CWE-78용 rule-based source/sink extraction 구현.
- [done] Intraprocedural def-use trace candidate generation 구현.
- [done] Trace candidate를 `data/traces/`에 작성.
- [done] Dataset schema와 writer 구현.
- [done] Metadata와 model input 분리.
- [done] Model input leakage check 구현.
- [done] Mock LLM trace reviewer interface 추가.
- [done] Discovery, build, extraction, trace, dataset count를 위한 MVP stats report 추가.
- [done] Rule loading, leakage checking, source/sink extraction, trace candidate construction에 대한 focused test 추가.

## Must Fix Before Research Run

- Real LLM request 전에 prompt leakage checking 추가. 현재 `model_input`은 검사하지만, `function_ops`, `source`, `sink`, `trace_candidate`로 조립된 최종 LLM prompt string은 review 직전에 검사하지 않는다.
- 명시적으로 non-label semantic evidence로 승인하지 않는 한 LLM prompt에서 `call_target_name`을 제거하거나 anonymize한다. 현재 prompt input에는 `getenv`, `system` 같은 name이 포함될 수 있다. 이는 Juliet label leakage는 아니지만 rule semantics를 드러낼 수 있으므로 config option으로 통제해야 한다.
- `build_metadata.jsonl`에 compiler version 기록. 예: compiler별로 `{compiler} --version`을 한 번 실행.
- `build_metadata.jsonl`에 source hash와 full build command 기록. 현재 metadata는 flags와 binary hash를 기록하지만 source hash와 complete command provenance는 아직 부족하다.
- Failed build에서 partial output이 존재하는 경우 binary hash를 기록하고, partial output을 제거했는지 유지했는지 기록.
- Ghidra log 또는 extraction metadata에 Ghidra version, `analyzeHeadless` path, `DumpPcodeJson.java` hash, command line, script hash 기록.
- Trace와 dataset metadata에 CWE rule file hash/version 및 rule registry version 기록.
- LLM이 disabled 상태일 때도 explicit disabled/mock provenance를 사용해 prompt template hash/version과 LLM model/temperature를 dataset metadata에 기록.
- OS, Python version, Java version, Ghidra version, compiler version, config path/hash, active CWEs, command-line arguments를 담는 machine-readable experiment run metadata file 추가.
- Final dataset `model_input`뿐 아니라 generated trace JSONL과 LLM prompt string에도 leakage check 추가.
- 명시적인 debug override가 없는 한 failed leakage check record는 warning만 남기지 말고 dataset writer에서 block 또는 quarantine 처리.
- `model_input`과 LLM prompt가 `bad`, `good`, `CWE`, Juliet filename, original function name, source path, source comment를 포함하지 않는지 검증하는 test 추가.
- Compiler와 Juliet corpus가 준비된 뒤 최소 하나의 CWE-78 testcase에 대한 real-Juliet smoke test 추가.
- Ghidra가 준비된 뒤 하나의 compiled binary로 Ghidra smoke test 추가. Non-empty P-code/callsite JSONL과 decompile error reporting을 확인.
- Supervised learning에 dataset record를 사용하기 전 Juliet metadata에서 파생된 explicit label/target 추가. 현재 dataset structure는 metadata와 model input을 분리하지만 finalized `target` field는 아직 없다.

## Must Preserve

- Juliet metadata가 label의 source이다.
- LLM output은 label을 overwrite하면 안 된다.
- CWE id, bad/good, filename, original function name은 기본적으로 model input에 나타나면 안 된다.
- CWE id, bad/good, Juliet filename, original function name, source path, source comment는 LLM prompt에 나타나면 안 된다.
- Unsupported CWE가 pipeline을 crash시키면 안 된다.
- 모든 stage는 reproducible output artifact를 남겨야 한다.
- Failed sample은 기록되어야 하며 batch execution은 계속되어야 한다.
- Cache와 resume behavior는 명시적이어야 한다.
- LLMDFA는 structural inspiration으로만 설명해야 한다. 즉 source/sink extraction, dataflow summarization, path validation을 P-code에 맞게 이식하는 것이지, P-code LLMDFA를 직접 재사용한다고 설명하면 안 된다.

## Later Extensions

- Juliet sample에서 format argument recovery와 constant-format filtering이 검증된 뒤 CWE-134 trace support를 완성하고 `partially_supported`에서 승격.
- `active_cwes: all` 추가.
- Interprocedural trace analysis 추가.
- Stack, heap, pointer alias, array, structure를 위한 memory model support 추가.
- Recovered call argument confidence scoring 개선.
- `unknown` path status propagation과 per-sink confidence를 포함한 call argument recovery failure handling 강화.
- 일반적인 Juliet buffer construction pattern에 대해 pointer/alias-aware def-use tracing 추가.
- Ghidra extraction이 나중에 comment 또는 debug string을 출력하는 경우 explicit handling 추가.
- `-O0`을 넘어 optimized binary support 추가.
- Stripped binary experiment 추가.
- Juliet coverage가 요구하는 경우 Windows API를 포함한 cross-platform sink support 추가.
- Prompt leakage check와 prompt template이 안정화된 뒤에만 real OpenAI LLM reviewer integration 추가.
- Trace ranking과 summarization 추가.
- Dataset split generation 추가.
- 모든 intermediate file에 대한 provenance hash 추가.
- Containerized reproducibility support 추가.
- Large-batch scheduling 추가.
- Failure triage를 위한 dashboard 또는 report 추가.
- Large Ghidra batch를 위한 retry/backoff와 resource limit 추가.
- Discovery된 모든 Juliet CWE에 대해 `unsupported` reason과 first-blocking capability를 포함한 generated support matrix entry 추가.
