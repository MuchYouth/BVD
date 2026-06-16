"""Juliet testcase discovery.

The discovery step is intentionally CWE-generic. It scans a Juliet C/C++
root for directories whose names contain a CWE identifier and emits a JSONL
manifest for source files found below those directories.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

LOGGER = logging.getLogger(__name__)

CWE_DIR_RE = re.compile(r"CWE0*(\d+)(?:_|$)", re.IGNORECASE)
SOURCE_EXTENSIONS = {".c": "c", ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp"}
SUPPORT_STEM_EXACT = {"io", "main"}
SUPPORT_STEM_SUBSTRINGS = ("support", "helper", "testcasesupport", "std_testcase")


@dataclass(frozen=True)
class DiscoveryResult:
    """Summary of a discovery run."""

    records: list[dict[str, Any]]
    output_path: Path | None
    dry_run: bool

    @property
    def total_records(self) -> int:
        return len(self.records)

    @property
    def build_candidates(self) -> int:
        return sum(1 for record in self.records if record.get("build_candidate") is True)

    @property
    def errors(self) -> int:
        return sum(1 for record in self.records if record.get("error"))


def load_config(path: str | Path) -> dict[str, Any]:
    """Load a YAML config file.

    PyYAML is used when available. The project config is YAML by design, so a
    clear error is better than silently accepting a partial parse.
    """

    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - depends on local env
        raise RuntimeError("PyYAML is required to read config YAML files") from exc

    with Path(path).open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Config must be a YAML mapping: {path}")
    return data


def normalize_cwe(value: str) -> str | None:
    """Normalize strings such as CWE078 or CWE-78 into CWE78."""

    match = re.search(r"CWE[-_]?0*(\d+)", value, re.IGNORECASE)
    if not match:
        return None
    return f"CWE{int(match.group(1))}"


def extract_cwe_from_dirname(dirname: str) -> str | None:
    """Extract a normalized CWE id from a Juliet CWE directory name."""

    match = CWE_DIR_RE.search(dirname)
    if not match:
        return None
    return f"CWE{int(match.group(1))}"


def selected_cwes_from_config(config: dict[str, Any]) -> set[str] | None:
    """Return configured active CWE selection.

    `None` means all discovered CWEs are in scope.
    """

    juliet_config = config.get("juliet", {})
    active = juliet_config.get("active_cwes", {})
    target = juliet_config.get("target_cwes", {})

    active_mode = str(active.get("mode", "selected")).lower()
    if active_mode == "all":
        return None

    selected = active.get("selected")
    if selected:
        return _normalize_cwe_set(selected)

    target_mode = str(target.get("mode", "selected")).lower()
    if target_mode == "all":
        return None
    return _normalize_cwe_set(target.get("selected", []))


def selected_cwes_from_cli(values: Iterable[str] | None) -> set[str] | None:
    """Return CLI CWE selection.

    `None` means all discovered CWEs are in scope.
    """

    if not values:
        return set()
    normalized: set[str] = set()
    for value in values:
        if value.lower() == "all":
            return None
        cwe = normalize_cwe(value)
        if cwe:
            normalized.add(cwe)
        else:
            LOGGER.warning("Ignoring invalid CWE filter: %s", value)
    return normalized


def resolve_cwe_scope(config: dict[str, Any], cli_cwes: Iterable[str] | None) -> set[str] | None:
    """Resolve discovery scope from CLI overrides and config defaults."""

    cli_scope = selected_cwes_from_cli(cli_cwes)
    if cli_scope is None:
        return None
    if cli_scope:
        return cli_scope
    return selected_cwes_from_config(config)


def discover_juliet(
    root: str | Path,
    *,
    cwe_scope: set[str] | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """Discover Juliet C/C++ source records under `root`."""

    root_path = Path(root)
    records: list[dict[str, Any]] = []

    if not root_path.exists():
        records.append(_error_record(root_path, "juliet_root_missing"))
        return records
    if not root_path.is_dir():
        records.append(_error_record(root_path, "juliet_root_not_directory"))
        return records

    cwe_dirs = find_cwe_directories(root_path)
    if not cwe_dirs:
        records.append(_error_record(root_path, "no_cwe_directories_found"))
        return records

    for cwe_dir in cwe_dirs:
        cwe = extract_cwe_from_dirname(cwe_dir.name)
        if not cwe:
            continue
        if cwe_scope is not None and cwe not in cwe_scope:
            continue

        try:
            source_files = iter_source_files(cwe_dir)
            found_for_dir = False
            for source_path in source_files:
                found_for_dir = True
                records.append(build_manifest_record(root_path, cwe_dir, source_path, cwe))
                if limit is not None and len(records) >= limit:
                    return records
            if not found_for_dir:
                records.append(_error_record(root_path, "no_source_files_found", cwe=cwe, cwe_dir=cwe_dir))
                if limit is not None and len(records) >= limit:
                    return records
        except OSError as exc:
            records.append(_error_record(root_path, str(exc), cwe=cwe, cwe_dir=cwe_dir))
            if limit is not None and len(records) >= limit:
                return records

    return records


def find_cwe_directories(root: Path) -> list[Path]:
    """Find directories whose basename looks like a Juliet CWE directory."""

    cwe_dirs: list[Path] = []
    if extract_cwe_from_dirname(root.name):
        cwe_dirs.append(root)
    for path in root.rglob("*"):
        if path.is_dir() and extract_cwe_from_dirname(path.name):
            cwe_dirs.append(path)
    return sorted(cwe_dirs)


def iter_source_files(cwe_dir: Path) -> list[Path]:
    """Return C/C++ source files below a CWE directory."""

    paths = [
        path
        for path in cwe_dir.rglob("*")
        if path.is_file() and path.suffix.lower() in SOURCE_EXTENSIONS
    ]
    return sorted(paths)


def build_manifest_record(root: Path, cwe_dir: Path, source_path: Path, cwe: str) -> dict[str, Any]:
    """Build a manifest record for one source file."""

    role = classify_role(source_path, cwe_dir)
    build_candidate = role == "testcase"
    reason_if_not_candidate = "" if build_candidate else f"role_{role}_not_build_candidate"
    rel_source = _safe_relative(source_path, root)
    rel_cwe_dir = _safe_relative(cwe_dir, root)

    return {
        "manifest_id": make_manifest_id(cwe, rel_source),
        "cwe": cwe,
        "cwe_dir": rel_cwe_dir,
        "source_path": rel_source,
        "filename": source_path.name,
        "language": SOURCE_EXTENSIONS[source_path.suffix.lower()],
        "testcase_family": testcase_family(source_path),
        "role": role,
        "build_candidate": build_candidate,
        "reason_if_not_candidate": reason_if_not_candidate,
    }


def classify_role(source_path: Path, cwe_dir: Path) -> str:
    """Classify source file role using Juliet filename/path conventions."""

    rel_parts = [part.lower() for part in source_path.relative_to(cwe_dir).parts]
    stem = source_path.stem.lower()

    if any("testcasesupport" in part for part in rel_parts):
        return "support"
    if stem == "main" or stem.endswith("_main"):
        return "support"
    if stem in SUPPORT_STEM_EXACT:
        return "support"
    if any(hint in stem for hint in SUPPORT_STEM_SUBSTRINGS):
        return "support"
    return "testcase"


def testcase_family(source_path: Path) -> str:
    """Derive a stable testcase family name from a Juliet source filename."""

    stem = source_path.stem
    return re.sub(r"_[0-9]{2}[a-z]?$", "", stem)


def make_manifest_id(cwe: str, rel_source_path: str) -> str:
    """Create a deterministic id for a manifest record."""

    digest = hashlib.sha1(f"{cwe}:{rel_source_path}".encode("utf-8")).hexdigest()[:16]
    return f"{cwe.lower()}_{digest}"


def write_manifest(records: Iterable[dict[str, Any]], output_path: str | Path) -> int:
    """Write manifest records as JSONL."""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
            count += 1
    return count


def run_discovery(
    config_path: str | Path,
    *,
    cli_cwes: Iterable[str] | None = None,
    limit: int | None = None,
    output_path: str | Path | None = None,
    dry_run: bool = False,
) -> DiscoveryResult:
    """Load config, discover records, and optionally write the manifest."""

    config = load_config(config_path)
    juliet_config = config.get("juliet", {})
    root = juliet_config.get("root", "data/raw_juliet")
    manifest_path = output_path or juliet_config.get("manifest_path", "data/manifests/juliet_manifest.jsonl")
    cwe_scope = resolve_cwe_scope(config, cli_cwes)

    LOGGER.info("Juliet root: %s", root)
    LOGGER.info("CWE scope: %s", "all" if cwe_scope is None else sorted(cwe_scope))
    records = discover_juliet(root, cwe_scope=cwe_scope, limit=limit)

    if dry_run:
        return DiscoveryResult(records=records, output_path=Path(manifest_path), dry_run=True)

    written = write_manifest(records, manifest_path)
    LOGGER.info("Wrote %s manifest records to %s", written, manifest_path)
    return DiscoveryResult(records=records, output_path=Path(manifest_path), dry_run=False)


def _normalize_cwe_set(values: Iterable[str]) -> set[str]:
    normalized = set()
    for value in values:
        cwe = normalize_cwe(str(value))
        if cwe:
            normalized.add(cwe)
    return normalized


def _error_record(root: Path, reason: str, *, cwe: str = "", cwe_dir: Path | None = None) -> dict[str, Any]:
    source_path = cwe_dir or root
    rel_source = _safe_relative(source_path, root)
    return {
        "manifest_id": make_manifest_id(cwe or "CWE0", f"error:{rel_source}:{reason}"),
        "cwe": cwe,
        "cwe_dir": _safe_relative(cwe_dir, root) if cwe_dir else "",
        "source_path": rel_source,
        "filename": source_path.name,
        "language": "",
        "testcase_family": "",
        "role": "unknown",
        "build_candidate": False,
        "reason_if_not_candidate": reason,
        "error": reason,
    }


def _safe_relative(path: Path | None, root: Path) -> str:
    if path is None:
        return ""
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()
