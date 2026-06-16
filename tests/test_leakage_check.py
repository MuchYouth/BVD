from src.dataset.leakage_check import check_model_input


def test_leakage_check_passes_anonymized_model_input():
    result = check_model_input(
        {
            "function_id": "func_0001",
            "trace": {"path_found": True, "trace_ops": [{"mnemonic": "COPY"}]},
        },
        source_filename="CWE078_OS_Command_Injection__bad.c",
        original_function_name="CWE078_badSink",
    )

    assert result.status == "passed"
    assert result.findings == []


def test_leakage_check_fails_on_cwe_and_bad_good_strings():
    result = check_model_input({"function_id": "CWE78_badSink", "variant": "good"})

    assert result.status == "failed"
    assert "CWE" in result.findings
    assert "bad" in result.findings
    assert "good" in result.findings


def test_leakage_check_catches_cwe_like_sample_id_in_model_input():
    result = check_model_input({"sample_id": "cwe78_deadbeef", "function_id": "func_0001"})

    assert result.status == "failed"
    assert "CWE" in result.findings


def test_leakage_check_fails_on_source_filename_and_original_function_name():
    result = check_model_input(
        {"comment": "uses testcase.c in original_func"},
        source_filename="testcase.c",
        original_function_name="original_func",
    )

    assert result.status == "failed"
    assert "testcase.c" in result.findings
    assert "original_func" in result.findings
