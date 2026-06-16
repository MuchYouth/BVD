# Binary Vulnerability Trace Dataset MVP

이 저장소는 SARD Juliet C/C++ testcase로부터 binary vulnerability trace dataset을 만들기 위한 연구용 MVP 파이프라인입니다.

현재 MVP 대상은 CWE-78 OS Command Injection입니다. 다음 확장 대상은 CWE-134 Uncontrolled Format String입니다. 이 파이프라인은 Juliet C/C++ 전체 CWE corpus를 discovery할 수 있도록 설계하되, 실제 실행은 지원되는 active CWE만 대상으로 하도록 구성되어 있습니다.

## MVP 실행 순서

모든 명령은 `--config configs/default.yaml` 옵션을 받습니다.

1. Juliet testcase를 discovery하고 manifest를 생성합니다.

   ```bash
   python3 scripts/discover_juliet.py --config configs/default.yaml
   ```

   유용한 discovery 예시:

   ```bash
   python3 scripts/discover_juliet.py --config configs/default.yaml --cwe CWE78
   python3 scripts/discover_juliet.py --config configs/default.yaml --cwe all
   python3 scripts/discover_juliet.py --config configs/default.yaml --cwe CWE134 --limit 20 --dry-run
   python3 scripts/discover_juliet.py --config configs/default.yaml --output data/manifests/juliet_manifest.dev.jsonl
   ```

2. 선택된 active CWE testcase를 빌드합니다.

   ```bash
   python3 scripts/build_juliet.py --config configs/default.yaml --cwe CWE78 --limit 5
   ```

   유용한 build 예시:

   ```bash
   python3 scripts/build_juliet.py --config configs/default.yaml --cwe CWE78 --limit 5 --dry-run
   python3 scripts/build_juliet.py --config configs/default.yaml --cwe all --limit 20 --jobs 4 --resume
   python3 scripts/build_juliet.py --config configs/default.yaml --cwe CWE78 --limit 5 --force
   ```

3. Ghidra headless로 P-code와 callsite 정보를 추출합니다.

   [configs/default.yaml](/home/dayoung/CVD_BIN/configs/default.yaml)의 `ghidra.install_dir`를 `support/analyzeHeadless`가 들어 있는 Ghidra 설치 디렉터리로 설정합니다.

   예시:

   ```yaml
   ghidra:
     install_dir: /opt/ghidra_11.0_PUBLIC
   ```

   ```bash
   python3 scripts/run_ghidra_extract.py --config configs/default.yaml --cwe CWE78 --limit 5
   ```

   유용한 Ghidra extraction 예시:

   ```bash
   python3 scripts/run_ghidra_extract.py --config configs/default.yaml --cwe CWE78 --limit 5 --resume
   python3 scripts/run_ghidra_extract.py --config configs/default.yaml --cwe all --jobs 2
   python3 scripts/run_ghidra_extract.py --config configs/default.yaml --cwe CWE78 --force
   ```

4. trace candidate와 dataset record를 생성합니다.

   ```bash
   python3 scripts/build_dataset.py --config configs/default.yaml --cwe CWE78
   ```

   LLM review는 기본적으로 비활성화되어 있습니다.

   ```yaml
   llm:
     enabled: false
     provider: mock
     model: mock
     temperature: 0
   ```

   외부 API 호출 없이 mock reviewer만 사용하려면 다음처럼 설정합니다.

   ```yaml
   llm:
     enabled: true
     provider: mock
     model: mock
     temperature: 0
   ```

   이 MVP에서 OpenAI review는 skeleton adapter입니다. `OPENAI_API_KEY`가 없으면 실행되지 않으며, LLM output은 어떤 경우에도 label을 덮어쓰지 않습니다.

5. 전체 MVP 파이프라인을 실행합니다.

   ```bash
   python3 scripts/run_pipeline.py --config configs/default.yaml --cwe CWE78 --limit 5
   ```

   유용한 pipeline 예시:

   ```bash
   python3 scripts/run_pipeline.py --config configs/default.yaml --cwe CWE78 --limit 5
   python3 scripts/run_pipeline.py --config configs/default.yaml --start-from ghidra --cwe CWE78
   python3 scripts/run_pipeline.py --config configs/default.yaml --start-from dataset --cwe CWE78
   ```

6. MVP 실행 통계를 리포트로 생성합니다.

   ```bash
   python3 scripts/report_mvp_stats.py --config configs/default.yaml
   ```

   이 명령은 `reports/mvp_stats.md`를 생성합니다.

7. CWE rule coverage matrix를 생성합니다.

   ```bash
   python3 scripts/report_coverage_matrix.py --config configs/default.yaml
   ```

   이 명령은 `reports/cwe_support_matrix.md`를 생성합니다.

## 테스트

Python test suite는 pytest로 실행합니다.

```bash
python3 -m pytest
```

## 현재 상태

현재 discovery, manifest 기반 Juliet build orchestration, Ghidra headless extraction orchestration, P-code 정규화, source/sink extraction, trace candidate 생성, dataset writing, mock LLM review adapter, 리포트 생성 기능이 구현되어 있습니다. 실제 연구 실행 전에는 Juliet corpus, compiler, Ghidra가 준비된 환경에서 smoke test와 재현성 metadata 보강이 필요합니다.
