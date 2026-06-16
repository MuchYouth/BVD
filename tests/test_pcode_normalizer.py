from src.pcode.normalizer import (
    anonymize_function_name,
    build_function_id_map,
    group_by_function,
    normalize_varnode,
)
from src.pcode.schema import CallsiteRecord, FunctionPcode, PcodeOpRecord


def test_normalize_varnode_defaults_and_types():
    normalized = normalize_varnode({"space": "unique", "offset": "12", "size": "8", "is_register": 1})

    assert normalized["space"] == "unique"
    assert normalized["offset"] == 12
    assert normalized["size"] == 8
    assert normalized["is_register"] is True
    assert normalized["is_constant"] is False


def test_anonymize_function_name():
    assert anonymize_function_name(1) == "func_0001"
    assert anonymize_function_name(42) == "func_0042"


def test_build_function_id_map_is_deterministic():
    functions = [
        FunctionPcode("s1", "tmp", "z_func", "0020"),
        FunctionPcode("s1", "tmp", "a_func", "0010"),
    ]

    mapping = build_function_id_map(functions)

    assert mapping[("s1", "0010", "a_func")] == "func_0001"
    assert mapping[("s1", "0020", "z_func")] == "func_0002"


def test_group_by_function_anonymizes_model_visible_function_names():
    op = PcodeOpRecord(
        sample_id="s1",
        function_name="CWE078_badSink",
        function_entry="00100000",
        op_seq=0,
        op_address="00100004",
        mnemonic="COPY",
        opcode=1,
        output_varnode={"space": "unique", "offset": "1", "size": "8"},
        input_varnodes=[{"space": "register", "offset": "2", "size": "8"}],
        warnings=[],
    )
    callsite = CallsiteRecord(
        sample_id="s1",
        function_name="CWE078_badSink",
        function_entry="00100000",
        call_address="00100008",
        call_target_address="00200000",
        call_target_name="system",
        is_external=True,
        raw_input_varnodes=[{"space": "register", "offset": "2", "size": "8"}],
        recovered_arguments=[{"index": 0, "varnode": {"space": "unique", "offset": "1", "size": "8"}}],
        argument_recovery_confidence="raw_pcode_inputs",
        warnings=[],
    )

    functions = group_by_function([op], [callsite], anonymize_symbols=True)

    assert len(functions) == 1
    assert functions[0].function_id == "func_0001"
    assert functions[0].original_function_name == "CWE078_badSink"
    assert functions[0].ops[0].function_name == "func_0001"
    assert functions[0].callsites[0].function_name == "func_0001"
    assert functions[0].ops[0].output_varnode["offset"] == 1
    assert functions[0].callsites[0].recovered_arguments[0]["varnode"]["offset"] == 1
