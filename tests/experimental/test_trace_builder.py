from src.analysis.source_sink import SinkCandidate, SourceCandidate, SourceSinkPairCandidate
from src.analysis.trace_builder import backward_slice_to_source, build_def_use_index, build_trace_candidates
from src.pcode.schema import PcodeOpRecord


def vn(space, offset):
    return {"space": space, "offset": offset, "size": 8, "is_constant": False}


def op(seq, address, mnemonic, output, inputs):
    return PcodeOpRecord(
        sample_id="s1",
        function_name="func_0001",
        function_entry="00100000",
        op_seq=seq,
        op_address=address,
        mnemonic=mnemonic,
        opcode=seq,
        output_varnode=output,
        input_varnodes=inputs,
        warnings=[],
    )


def source(varnodes):
    return SourceCandidate(
        sample_id="s1",
        function_id="func_0001",
        source_type="function_call",
        source_location="00100010",
        source_varnodes=varnodes,
        call_target_name="getenv",
    )


def sink(varnodes):
    return SinkCandidate(
        sample_id="s1",
        function_id="func_0001",
        sink_type="function_call_argument",
        sink_location="00100030",
        sink_varnodes=varnodes,
        call_target_name="system",
        argument_indices=[0],
    )


def test_build_def_use_index_maps_definitions_and_uses():
    a = vn("unique", 1)
    b = vn("unique", 2)
    ops = [op(1, "0010", "COPY", b, [a])]

    index = build_def_use_index(ops)

    assert index.defining_ops
    assert list(index.using_ops.values())[0] == [ops[0]]


def test_backward_slice_finds_source_copy_to_system_argument_path():
    a = vn("unique", 1)
    b = vn("unique", 2)
    ops = [
        op(1, "00100010", "CALL", a, []),
        op(2, "00100020", "COPY", b, [a]),
        op(3, "00100030", "CALL", None, [vn("ram", 100), b]),
    ]

    trace = backward_slice_to_source(ops, source([a]), sink([b]))

    assert trace.path_found is True
    assert trace.reason == "source_varnode_reached"
    assert [entry["op_address"] for entry in trace.trace_ops] == ["00100020"]


def test_backward_slice_records_no_path_when_source_and_sink_are_unconnected():
    a = vn("unique", 1)
    b = vn("unique", 2)
    c = vn("unique", 3)
    ops = [
        op(1, "00100010", "CALL", a, []),
        op(2, "00100020", "COPY", b, [c]),
        op(3, "00100030", "CALL", None, [vn("ram", 100), b]),
    ]

    trace = backward_slice_to_source(ops, source([a]), sink([b]))

    assert trace.path_found is False
    assert trace.reason == "no_path"


def test_backward_slice_unknown_when_sink_argument_varnode_is_missing():
    a = vn("unique", 1)
    ops = [op(1, "00100010", "CALL", a, [])]

    trace = backward_slice_to_source(ops, source([a]), sink([]))

    assert trace.path_found == "unknown"
    assert trace.reason == "sink_varnode_unknown"


def test_build_trace_candidates_carries_cwe_and_trace_type_metadata():
    a = vn("unique", 1)
    b = vn("unique", 2)
    ops = [
        op(1, "00100010", "CALL", a, []),
        op(2, "00100020", "COPY", b, [a]),
    ]
    pair = SourceSinkPairCandidate(
        sample_id="s1",
        function_id="func_0001",
        source=source([a]),
        sink=sink([b]),
        analysis_cwe="CWE78",
    )

    traces = build_trace_candidates(ops, [pair], trace_type="taint_to_call_argument")

    assert traces[0].path_found is True
    assert traces[0].analysis_cwe == "CWE78"
    assert traces[0].trace_type == "taint_to_call_argument"
