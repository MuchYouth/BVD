from src.analysis.rule_registry import RuleRegistry
from src.analysis.source_sink import extract_sink_candidates, extract_source_sink_pairs
from src.pcode.schema import CallsiteRecord, FunctionPcode


RULE = RuleRegistry("configs/cwe_rules").get_rule("CWE134")


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


def test_cwe134_printf_data_format_argument_is_sink_candidate():
    function = FunctionPcode(
        sample_id="s1",
        function_id="func_0001",
        original_function_name="metadata_only_original",
        function_entry="00100000",
        callsites=[
            callsite("getenv", "00100010", [vn("ram", 1, constant=True)]),
            callsite("printf", "00100020", [vn("unique", 10)]),
        ],
    )

    pairs = extract_source_sink_pairs([function], RULE)

    assert len(pairs) == 1
    assert pairs[0].sink.call_target_name == "printf"
    assert pairs[0].sink.argument_indices == [0]
    assert pairs[0].sink.sink_varnodes == [vn("unique", 10)]
    assert "experimental_rule_status:partially_supported" in pairs[0].warnings


def test_cwe134_printf_constant_format_is_not_sink_candidate():
    function = FunctionPcode(
        sample_id="s1",
        function_id="func_0001",
        original_function_name="metadata_only_original",
        function_entry="00100000",
        callsites=[callsite("printf", "00100020", [vn("constant", 100, constant=True), vn("unique", 10)])],
    )

    sinks = extract_sink_candidates(function, RULE)

    assert sinks == []


def test_cwe134_fprintf_argument_index_one_is_format_sink():
    function = FunctionPcode(
        sample_id="s1",
        function_id="func_0001",
        original_function_name="metadata_only_original",
        function_entry="00100000",
        callsites=[callsite("fprintf", "00100020", [vn("ram", 2), vn("unique", 10)])],
    )

    sinks = extract_sink_candidates(function, RULE)

    assert len(sinks) == 1
    assert sinks[0].argument_indices == [1]
    assert sinks[0].sink_varnodes == [vn("unique", 10)]
