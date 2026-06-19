"""DEPRECATED for primary pipeline: dynamic CWE rule registry.

Rules are loaded from YAML files under `configs/cwe_rules` by default. The
registry normalizes every rule to the same shape so downstream modules can
apply source/sink logic without hard-coding CWE-specific details.

This remains available for reports or future optional P-code-native
experiments, but it must not drive primary source/sink/trace generation.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

LOGGER = logging.getLogger(__name__)

DEFAULT_RULE_DIR = Path("configs/cwe_rules")
SUPPORTED_STATUSES = {"supported", "partially_supported", "unsupported"}


@dataclass(frozen=True)
class CweRule:
    """Normalized CWE rule definition."""

    cwe: str
    name: str
    status: str
    sources: dict[str, Any] = field(default_factory=dict)
    sinks: dict[str, Any] = field(default_factory=dict)
    trace: dict[str, Any] = field(default_factory=dict)
    requires: dict[str, Any] = field(default_factory=dict)
    notes: str = ""
    rule_path: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_supported(self) -> bool:
        return self.status == "supported"

    @property
    def is_partially_supported(self) -> bool:
        return self.status == "partially_supported"

    @property
    def is_unsupported(self) -> bool:
        return self.status == "unsupported"

    @classmethod
    def unsupported(cls, cwe_id: str, *, notes: str = "No rule file found") -> "CweRule":
        cwe = normalize_cwe_id(cwe_id) or str(cwe_id)
        return cls(
            cwe=cwe,
            name="",
            status="unsupported",
            sources={},
            sinks={},
            trace={},
            requires={},
            notes=notes,
            raw={},
        )


class RuleRegistry:
    """Load and retrieve CWE rules from a directory of YAML files."""

    def __init__(self, rule_dir: str | Path = DEFAULT_RULE_DIR) -> None:
        self.rule_dir = Path(rule_dir)
        self._rules: dict[str, CweRule] = {}
        self._load_errors: dict[str, str] = {}
        self.load()

    @property
    def rules(self) -> Mapping[str, CweRule]:
        return self._rules

    @property
    def load_errors(self) -> Mapping[str, str]:
        return self._load_errors

    def load(self) -> None:
        """Load all `*.yaml` and `*.yml` files from the rule directory."""

        self._rules.clear()
        self._load_errors.clear()

        if not self.rule_dir.exists():
            LOGGER.warning("Rule directory does not exist: %s", self.rule_dir)
            return
        if not self.rule_dir.is_dir():
            LOGGER.warning("Rule path is not a directory: %s", self.rule_dir)
            return

        rule_paths = sorted([*self.rule_dir.glob("*.yaml"), *self.rule_dir.glob("*.yml")])
        for rule_path in rule_paths:
            try:
                rule = load_rule_file(rule_path)
            except Exception as exc:  # noqa: BLE001 - record and continue by design.
                LOGGER.warning("Failed to load rule file %s: %s", rule_path, exc)
                self._load_errors[str(rule_path)] = str(exc)
                continue
            self._rules[rule.cwe] = rule

    def get_rule(self, cwe_id: str) -> CweRule:
        """Return a normalized rule or an unsupported placeholder."""

        cwe = normalize_cwe_id(cwe_id)
        if not cwe:
            return CweRule.unsupported(cwe_id, notes="Invalid CWE id")
        return self._rules.get(cwe, CweRule.unsupported(cwe))

    def get_status(self, cwe_id: str) -> str:
        """Return supported, partially_supported, or unsupported."""

        return self.get_rule(cwe_id).status


def get_rule(cwe_id: str, rule_dir: str | Path = DEFAULT_RULE_DIR) -> CweRule:
    """Convenience function for one-off rule lookup."""

    return RuleRegistry(rule_dir).get_rule(cwe_id)


def get_status(cwe_id: str, rule_dir: str | Path = DEFAULT_RULE_DIR) -> str:
    """Convenience function for one-off status lookup."""

    return get_rule(cwe_id, rule_dir).status


def load_rule_file(path: str | Path) -> CweRule:
    """Load one YAML rule file and normalize its fields."""

    raw = _load_yaml(path)
    if not isinstance(raw, dict):
        raise ValueError("Rule YAML must contain a mapping at the top level")

    cwe = normalize_cwe_id(str(raw.get("cwe", "")))
    if not cwe:
        cwe = normalize_cwe_id(Path(path).stem)
    if not cwe:
        raise ValueError("Rule file must define a valid CWE id")

    status = str(raw.get("status", "unsupported")).strip().lower()
    if status not in SUPPORTED_STATUSES:
        LOGGER.warning("Unknown status %r in %s; treating as unsupported", status, path)
        status = "unsupported"

    return CweRule(
        cwe=cwe,
        name=str(raw.get("name", "")),
        status=status,
        sources=_as_dict(raw.get("sources")),
        sinks=_as_dict(raw.get("sinks")),
        trace=_as_dict(raw.get("trace")),
        requires=_normalize_requires(raw),
        notes=str(raw.get("notes", "")),
        rule_path=str(path),
        raw=dict(raw),
    )


def normalize_cwe_id(value: str) -> str | None:
    """Normalize CWE id spellings such as CWE078, CWE-78, or cwe_134."""

    match = re.search(r"CWE[-_]?0*(\d+)", value, re.IGNORECASE)
    if not match:
        return None
    return f"CWE{int(match.group(1))}"


def _load_yaml(path: str | Path) -> Any:
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - depends on local env
        raise RuntimeError("PyYAML is required to load CWE rule YAML files") from exc

    with Path(path).open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def _as_dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _normalize_requires(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Build a standard `requires` field from explicit or legacy rule fields."""

    requires = _as_dict(raw.get("requires"))
    argument_recovery = raw.get("argument_recovery")
    if argument_recovery is not None and "argument_recovery" not in requires:
        requires["argument_recovery"] = argument_recovery
    return requires
