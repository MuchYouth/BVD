from src.analysis.rule_registry import RuleRegistry
from src.analysis.source_sink import extract_sink_candidates, extract_source_sink_pairs
from src.pcode.schema import CallsiteRecord, FunctionPcode, PcodeOpRecord


RULE = RuleRegistry("configs/cwe_rules").get_rule("CWE78")


def vn(space, offset, *, constant=False):
    return {"space": space, "offset": offset, "size": 8, "is_constant": constant}


def callsite(target, address, args):
    return CallsiteRecord(
        sample_id="s1",
        function_name="func_0001",
        function_entry="00100000",
        call_address=address,
        call_target_address="00200000",
        call_target_name=target,
        is_external=True,
        raw_input_varnodes=[vn("ram", 0), *args],
        recovered_arguments=[{"index": index, "varnode": arg} for index, arg in enumerate(args)],
        argument_recovery_confidence="raw_pcode_inputs",
        warnings=[],
    )


def op(address, output=None):
    return PcodeOpRecord(
        sample_id="s1",
        function_name="func_0001",
        function_entry="00100000",
        op_seq=0,
        op_address=address,
        mnemonic="CALL",
        opcode=8,
        output_varnode=output,
        input_varnodes=[],
        warnings=[],
    )


def test_cwe78_getenv_to_system_pair_is_generated():
    function = FunctionPcode(
        sample_id="s1",
        function_id="func_0001",
        original_function_name="metadata_only_original",
        function_entry="00100000",
        ops=[op("00100010", output=vn("unique", 10)), op("00100020")],
        callsites=[
            callsite("getenv", "00100010", [vn("ram", 11, constant=True)]),
            callsite("system", "00100020", [vn("unique", 10)]),
        ],
    )

    pairs = extract_source_sink_pairs([function], RULE)

    assert len(pairs) == 1
    assert pairs[0].source.call_target_name == "getenv"
    assert pairs[0].sink.call_target_name == "system"
    assert pairs[0].sink.argument_indices == [0]
    assert pairs[0].sink.sink_varnodes == [vn("unique", 10)]
    assert pairs[0].analysis_cwe == "CWE78"


def test_cwe78_source_without_system_does_not_create_pair():
    function = FunctionPcode(
        sample_id="s1",
        function_id="func_0001",
        original_function_name="metadata_only_original",
        function_entry="00100000",
        ops=[op("00100020")],
        callsites=[callsite("system", "00100020", [vn("unique", 10)])],
    )

    pairs = extract_source_sink_pairs([function], RULE)

    assert pairs == []


def test_cwe78_exec_policy_keeps_all_arguments_generic_from_rule():
    function = FunctionPcode(
        sample_id="s1",
        function_id="func_0001",
        original_function_name="metadata_only_original",
        function_entry="00100000",
        callsites=[callsite("execv", "00100020", [vn("ram", 1), vn("ram", 2)])],
    )

    sinks = extract_sink_candidates(function, RULE)

    assert len(sinks) == 1
    assert sinks[0].argument_indices == [0, 1]
