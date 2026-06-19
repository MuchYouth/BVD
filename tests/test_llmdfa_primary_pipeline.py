import json

from src.dataset.writer import build_dataset_record
from src.ghidra_evidence.linker import attach_ghidra_evidence
from src.ghidra_evidence.loader import load_sample_evidence
from src.llmdfa_adapter.input_converter import convert_decompiled_jsonl


def write_jsonl(path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")


def test_ghidra_decompiled_output_converts_to_llmdfa_input(tmp_path):
    decompiled_path = tmp_path / "ghidra" / "sample.decompiled.jsonl"
    write_jsonl(
        decompiled_path,
        [
            {
                "sample_id": "CWE078_bad_case",
                "function_id": "func_0001",
                "original_function_name": "CWE078_bad",
                "function_entry": "0x401000",
                "decompile_success": True,
                "decompiled_code": "int CWE078_bad(int argc) { return argc; }",
            }
        ],
    )

    result = convert_decompiled_jsonl([decompiled_path], tmp_path / "llmdfa_inputs")

    assert len(result.converted) == 1
    converted = result.converted[0]
    assert converted.source_path.exists()
    assert "CWE" not in converted.source_path.read_text(encoding="utf-8")
    assert "bad" not in converted.source_path.read_text(encoding="utf-8")


def test_attach_ghidra_evidence_to_llmdfa_result(tmp_path):
    pcode_path = tmp_path / "sample.pcode.jsonl"
    callsites_path = tmp_path / "sample.callsites.jsonl"
    write_jsonl(
        pcode_path,
        [
            {
                "sample_id": "sample_original",
                "function_name": "CWE078_bad",
                "function_entry": "0x401000",
                "op_seq": 1,
                "op_address": "0x401010",
                "mnemonic": "CALL",
                "opcode": 8,
                "output_varnode": None,
                "input_varnodes": [{"space": "ram", "offset": "0x404000", "size": 8}],
            }
        ],
    )
    write_jsonl(
        callsites_path,
        [
            {
                "sample_id": "sample_original",
                "function_name": "CWE078_bad",
                "function_entry": "0x401000",
                "call_address": "0x401010",
                "call_target_address": "0x500000",
                "call_target_name": "system",
                "is_external": True,
                "raw_input_varnodes": [],
                "recovered_arguments": [{"index": 0, "varnode": {"space": "register", "offset": "0x0"}}],
                "argument_recovery_confidence": "raw_pcode_inputs",
            }
        ],
    )
    evidence = load_sample_evidence(
        pcode_path,
        callsites_path,
        sample_id="sample_original",
        function_id_by_entry={"0x401000": "func_0001"},
    )

    attached = attach_ghidra_evidence(
        {"record_id": "llmdfa_1", "warnings": []},
        evidence,
        function_entry="0x401000",
        function_id="func_0001",
    )

    assert attached["ghidra_evidence"]["function_id"] == "func_0001"
    assert attached["ghidra_evidence"]["pcode_ops"][0]["op_address"] == "0x401010"
    assert attached["ghidra_evidence"]["callsites"][0]["call_address"] == "0x401010"


def test_llmdfa_mock_output_builds_dataset_without_label_leakage():
    llmdfa_record = {
        "record_id": "llmdfa_1",
        "source_file": "data/llmdfa_inputs/sample_hash/func_0001.c",
        "source_sink_result": {"sources": [{"id": "src_1"}], "sinks": [{"id": "sink_1"}]},
        "dataflow_result": {"bug_candidates": [{"path": ["src_1", "sink_1"]}]},
        "path_validation_result": {"validation_result": "reachable"},
        "warnings": [],
    }
    conversion = {
        "original_sample_id": "CWE078_OS_Command_Injection__bad_01",
        "sample_id": "sample_hash",
        "function_id": "func_0001",
        "original_function_name": "CWE078_bad",
        "function_entry": "0x401000",
        "source_path": "data/llmdfa_inputs/sample_hash/func_0001.c",
        "warnings": [],
    }
    metadata = {
        "sample_id": "CWE078_OS_Command_Injection__bad_01",
        "cwe": "CWE78",
        "variant": "bad",
        "source_path": "CWE078_OS_Command_Injection__bad_01.c",
        "binary_path": "data/binaries/sample.out",
        "sha256": "abc",
        "opt_level": "O0",
    }

    record = build_dataset_record(
        llmdfa_record,
        conversion=conversion,
        metadata=metadata,
        ghidra_evidence={"function_id": "func_0001", "callsites": []},
    )

    assert record.leakage_check.status == "passed"
    model_input = json.dumps(record.model_input, sort_keys=True)
    assert "bad" not in model_input.lower()
    assert "good" not in model_input.lower()
    assert "cwe" not in model_input.lower()
    assert "juliet" not in model_input.lower()
    assert "CWE078_bad" not in model_input
