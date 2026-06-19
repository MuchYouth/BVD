import json
from dataclasses import dataclass
from pathlib import Path

from src.llmdfa_adapter.llm_client import ChatResult, client_from_settings
from src.llmdfa_adapter.pilot_selector import select_pilot_functions
from src.llmdfa_adapter.trace_runner import read_jsonl, run_trace_pilot


def write_jsonl(path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")


def decompiled_record(sample_id, function_id, name, code):
    return {
        "sample_id": sample_id,
        "function_id": function_id,
        "original_function_name": name,
        "function_entry": function_id.replace("func_", "0x40"),
        "decompiled_code": code,
        "decompile_success": True,
        "warnings": [],
    }


def long_code(name, body):
    return f"""
int {name}(char *input)
{{
    char local_buffer[128];
    int index = 0;
    if (input != (char *)0x0) {{
        {body}
        index = index + 1;
    }}
    return index + local_buffer[0];
}}
""" + ("/* decompiler context */\n" * 8)


def test_selector_balances_distribution_and_excludes_external_stubs(tmp_path):
    input_root = tmp_path / "pcode"
    expected = {
        ("CWE121", "bad"): 2,
        ("CWE121", "good"): 2,
        ("CWE134", "bad"): 2,
        ("CWE134", "good"): 2,
        ("CWE835", "bad"): 1,
        ("CWE835", "good"): 1,
    }
    bodies = {
        "CWE121": "memcpy(local_buffer, input, strlen(input));",
        "CWE134": "printf(input);",
        "CWE835": "while (input[index] != 0) { index++; }",
    }
    for (cwe, variant), count in expected.items():
        for index in range(count):
            sample = f"sample_{cwe}_{variant}_{index}"
            path = input_root / cwe / variant / "O0" / f"{sample}.decompiled.jsonl"
            write_jsonl(
                path,
                [
                    decompiled_record(
                        sample,
                        "func_0001",
                        "<EXTERNAL>::printf",
                        long_code("printf", "printf(input);"),
                    ),
                    decompiled_record(
                        sample,
                        "func_0002",
                        f"target_{index}",
                        long_code(f"target_{index}", bodies[cwe]),
                    ),
                ],
            )

    selected = select_pilot_functions(input_root, tmp_path / "pilot", limit=10)

    actual = {}
    record_ids = set()
    for record in selected:
        actual[(record.cwe, record.variant)] = actual.get((record.cwe, record.variant), 0) + 1
        record_ids.add(record.record_id)
        code = Path(record.source_path).read_text(encoding="utf-8")
        assert "<EXTERNAL>" not in code
        assert record.function_id == "func_0002"
    assert actual == expected
    assert len(record_ids) == 10


@dataclass
class FakeClient:
    provider: str = "freellm"
    model: str = "gpt-4o"
    calls: int = 0

    def health_check(self):
        return {"status": "ok"}

    def complete(self, *, system_prompt, user_prompt):
        self.calls += 1
        return ChatResult(
            text="Source input reaches the printf sink. Final verdict: trace found.",
            provider=self.provider,
            model=self.model,
            endpoint="http://localhost/test",
            usage={"total_tokens": 42},
            raw_response={"choices": []},
        )


def test_trace_runner_preserves_raw_trace_and_resumes(tmp_path):
    source = tmp_path / "func_0001.c"
    source.write_text("int func_0001(char *input) { printf(input); return 0; }", encoding="utf-8")
    manifest = [
        {
            "record_id": "pilot_1",
            "source_path": source.as_posix(),
            "function_id": "func_0001",
        }
    ]
    client = FakeClient()
    prompt = tmp_path / "prompt.md"
    prompt.write_text("Analyze:\n{code}", encoding="utf-8")

    first = run_trace_pilot(
        manifest,
        client=client,
        output_root=tmp_path / "outputs",
        prompt_path=prompt,
        daily_limit=50,
    )
    second = run_trace_pilot(
        manifest,
        client=client,
        output_root=tmp_path / "outputs",
        prompt_path=prompt,
        daily_limit=50,
    )

    parsed = read_jsonl(tmp_path / "outputs" / "parsed_results.jsonl")
    assert first.succeeded == 1
    assert second.skipped_resume == 1
    assert client.calls == 1
    assert parsed[0]["dataflow_result"]["raw_llmdfa_trace"].endswith("trace found.")
    assert parsed[0]["raw_output"]["response_text"].endswith("trace found.")


def test_trace_runner_honors_daily_quota(tmp_path):
    source = tmp_path / "func.c"
    source.write_text("int func(void) { return 0; }", encoding="utf-8")
    manifest = [
        {"record_id": f"pilot_{index}", "source_path": source.as_posix(), "function_id": f"func_{index}"}
        for index in range(2)
    ]
    client = FakeClient()
    prompt = tmp_path / "prompt.md"
    prompt.write_text("{code}", encoding="utf-8")

    summary = run_trace_pilot(
        manifest,
        client=client,
        output_root=tmp_path / "outputs",
        prompt_path=prompt,
        daily_limit=1,
    )

    assert summary.attempted == 1
    assert summary.skipped_quota == 1
    assert client.calls == 1


def test_provider_settings_share_openai_compatible_interface(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    freellm = client_from_settings(provider="freellm", model="gpt-4o")
    openai = client_from_settings(provider="openai", model="gpt-4o")

    assert freellm.model == openai.model == "gpt-4o"
    assert freellm.completion_paths[0] == openai.completion_paths[0] == "/v1/chat/completions"
    assert freellm.base_url == "http://127.0.0.1:3001"
    assert openai.base_url == "https://api.openai.com"
