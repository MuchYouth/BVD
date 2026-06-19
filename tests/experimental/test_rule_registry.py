import unittest
from pathlib import Path

from src.analysis.rule_registry import RuleRegistry, get_rule, normalize_cwe_id
from src.analysis.source_sink import sink_argument_index, sink_function_names, source_function_names


RULE_DIR = Path("configs/cwe_rules")


class RuleRegistryTest(unittest.TestCase):
    def test_loads_cwe78_rule(self) -> None:
        registry = RuleRegistry(RULE_DIR)
        rule = registry.get_rule("CWE78")

        self.assertEqual(rule.cwe, "CWE78")
        self.assertEqual(rule.status, "supported")
        self.assertTrue(rule.is_supported)
        self.assertIn("getenv", source_function_names(rule))
        self.assertIn("system", sink_function_names(rule))
        self.assertEqual(rule.trace["type"], "taint_to_call_argument")
        self.assertEqual(rule.requires, {})

    def test_loads_cwe134_rule(self) -> None:
        registry = RuleRegistry(RULE_DIR)
        rule = registry.get_rule("CWE134")

        self.assertEqual(rule.cwe, "CWE134")
        self.assertEqual(rule.status, "partially_supported")
        self.assertTrue(rule.is_partially_supported)
        self.assertIn("recv", source_function_names(rule))
        self.assertIn("printf", sink_function_names(rule))
        self.assertEqual(sink_argument_index(rule, "snprintf"), 2)
        self.assertEqual(rule.trace["type"], "taint_to_format_argument")
        self.assertEqual(rule.requires["argument_recovery"]["on_failure"], "unknown")

    def test_missing_cwe_returns_unsupported(self) -> None:
        registry = RuleRegistry(RULE_DIR)
        rule = registry.get_rule("CWE999")

        self.assertEqual(rule.cwe, "CWE999")
        self.assertEqual(rule.status, "unsupported")
        self.assertTrue(rule.is_unsupported)
        self.assertEqual(rule.sources, {})
        self.assertEqual(rule.sinks, {})
        self.assertEqual(rule.trace, {})

    def test_module_level_get_rule(self) -> None:
        rule = get_rule("CWE-078", RULE_DIR)

        self.assertEqual(rule.cwe, "CWE78")
        self.assertEqual(rule.status, "supported")

    def test_normalize_cwe_id(self) -> None:
        self.assertEqual(normalize_cwe_id("CWE078_OS_Command_Injection"), "CWE78")
        self.assertEqual(normalize_cwe_id("cwe-134"), "CWE134")
        self.assertIsNone(normalize_cwe_id("not-a-cwe"))


if __name__ == "__main__":
    unittest.main()
