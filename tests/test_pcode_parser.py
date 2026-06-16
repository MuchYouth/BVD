import json

from src.pcode.parser import group_records_by_function, load_callsites_jsonl, load_pcode_jsonl


def write_jsonl(path, records):
    path.write_text("\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8")


def test_load_pcode_jsonl_records_errors_with_line_number(tmp_path):
    path = tmp_path / "sample.pcode.jsonl"
    path.write_text(
        json.dumps(
            {
                "sample_id": "s1",
                "function_name": "badSink",
                "function_entry": "00100000",
                "op_seq": 0,
                "op_address": "00100004",
                "mnemonic": "COPY",
                "opcode": 1,
                "output_varnode": {"space": "unique", "offset": 1, "size": 8},
                "input_varnodes": [{"space": "register", "offset": 2, "size": 8}],
                "warnings": [],
            }
        )
        + "\n"
        + "{broken json\n",
        encoding="utf-8",
    )

    result = load_pcode_jsonl(path)

    assert len(result.records) == 1
    assert result.records[0].sample_id == "s1"
    assert result.records[0].function_name == "badSink"
    assert len(result.errors) == 1
    assert result.errors[0].line_number == 2


def test_load_callsites_jsonl_and_group_by_function(tmp_path):
    pcode_path = tmp_path / "sample.pcode.jsonl"
    callsite_path = tmp_path / "sample.callsites.jsonl"
    write_jsonl(
        pcode_path,
        [
            {
                "sample_id": "s1",
                "function_name": "caller",
                "function_entry": "00100000",
                "op_seq": 1,
                "op_address": "00100008",
                "mnemonic": "CALL",
                "opcode": 8,
                "output_varnode": None,
                "input_varnodes": [],
                "warnings": [],
            }
        ],
    )
    write_jsonl(
        callsite_path,
        [
            {
                "sample_id": "s1",
                "function_name": "caller",
                "function_entry": "00100000",
                "call_address": "00100008",
                "call_target_address": "00200000",
                "call_target_name": "system",
                "is_external": True,
                "raw_input_varnodes": [{"space": "ram", "offset": 3, "size": 8}],
                "recovered_arguments": [],
                "argument_recovery_confidence": "raw_pcode_inputs",
                "warnings": [],
            }
        ],
    )

    pcode_result = load_pcode_jsonl(pcode_path)
    callsite_result = load_callsites_jsonl(callsite_path)
    functions = group_records_by_function(pcode_result, callsite_result)

    assert len(pcode_result.errors) == 0
    assert len(callsite_result.errors) == 0
    assert len(functions) == 1
    assert functions[0].original_function_name == "caller"
    assert len(functions[0].ops) == 1
    assert len(functions[0].callsites) == 1
