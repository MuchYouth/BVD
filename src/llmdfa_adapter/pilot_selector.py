"""Select a small, balanced set of decompiled functions for LLMDFA pilots."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from src.llmdfa_adapter.input_converter import anonymize_code


DEFAULT_DISTRIBUTION = {
    ("CWE121", "bad"): 2,
    ("CWE121", "good"): 2,
    ("CWE134", "bad"): 2,
    ("CWE134", "good"): 2,
    ("CWE835", "bad"): 1,
    ("CWE835", "good"): 1,
}
KEYWORDS = {
    "CWE121": ("strcpy", "strncpy", "memcpy", "memmove", "recv", "fgets", "alloca", "malloc", "char ["),
    "CWE134": ("printf", "fprintf", "sprintf", "snprintf", "vprintf", "recv", "fgets", "scanf"),
    "CWE835": ("while (", "while(", "for (", "for(", "do {", "break;", "continue;"),
}
EXCLUDED_NAMES = {
    "_init",
    "_start",
    "_fini",
    "__libc_csu_init",
    "__libc_csu_fini",
    "deregister_tm_clones",
    "register_tm_clones",
    "__do_global_dtors_aux",
    "frame_dummy",
}
WRAPPER_PATTERN = re.compile(
    r"^\s*(?:/\*.*?\*/\s*)*(?:[\w *]+)\([^)]*\)\s*\{\s*"
    r"(?:\w+\s*=\s*)?\(\*\(code \*\)PTR_[^)]+\)\([^;]*\);\s*(?:return\s+\w+;|return;)?\s*\}\s*$",
    re.DOTALL,
)


@dataclass(frozen=True)
class PilotFunction:
    record_id: str
    source_path: str
    original_decompiled_path: str
    sample_id: str
    function_id: str
    function_entry: str
    cwe: str
    variant: str
    selection_reason: str
    score: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "source_path": self.source_path,
            "original_decompiled_path": self.original_decompiled_path,
            "sample_id": self.sample_id,
            "function_id": self.function_id,
            "function_entry": self.function_entry,
            "cwe": self.cwe,
            "variant": self.variant,
            "selection_reason": self.selection_reason,
            "score": self.score,
        }


@dataclass(frozen=True)
class Candidate:
    input_path: Path
    cwe: str
    variant: str
    sample_id: str
    function_id: str
    function_entry: str
    original_function_name: str
    code: str
    score: int
    matched_keywords: tuple[str, ...]


def select_pilot_functions(
    input_root: str | Path,
    output_root: str | Path,
    *,
    limit: int = 10,
    distribution: dict[tuple[str, str], int] | None = None,
    manifest_name: str = "manifest_10.jsonl",
) -> list[PilotFunction]:
    """Select, anonymize, and materialize pilot functions.

    The default ten-record distribution is deterministic. For other limits,
    records are taken round-robin from the same ordered buckets.
    """

    root = Path(input_root)
    destination = Path(output_root)
    buckets = collect_candidates(root)
    selected = _select_candidates(buckets, limit=limit, distribution=distribution)

    records: list[PilotFunction] = []
    for candidate in selected:
        record_id = stable_record_id(candidate)
        source_path = destination / "sources" / record_id / f"{candidate.function_id}.c"
        warnings: list[str] = []
        sanitized = anonymize_code(
            candidate.code,
            function_id=candidate.function_id,
            original_function_name=candidate.original_function_name,
            warnings=warnings,
        )
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_text(sanitized, encoding="utf-8")
        keyword_text = ", ".join(candidate.matched_keywords) if candidate.matched_keywords else "structural complexity"
        records.append(
            PilotFunction(
                record_id=record_id,
                source_path=source_path.as_posix(),
                original_decompiled_path=candidate.input_path.as_posix(),
                sample_id=candidate.sample_id,
                function_id=candidate.function_id,
                function_entry=candidate.function_entry,
                cwe=candidate.cwe,
                variant=candidate.variant,
                selection_reason=f"matched {keyword_text}; score={candidate.score}",
                score=candidate.score,
            )
        )

    write_jsonl(destination / manifest_name, [record.to_dict() for record in records])
    return records


def collect_candidates(input_root: Path) -> dict[tuple[str, str], list[Candidate]]:
    buckets: dict[tuple[str, str], list[Candidate]] = {}
    for path in sorted(input_root.rglob("*.decompiled.jsonl")):
        relative = path.relative_to(input_root)
        if len(relative.parts) < 4:
            continue
        cwe, variant = relative.parts[0], relative.parts[1]
        if cwe not in KEYWORDS or variant not in {"bad", "good"}:
            continue
        for record in read_jsonl(path):
            candidate = candidate_from_record(path, cwe, variant, record)
            if candidate is not None:
                buckets.setdefault((cwe, variant), []).append(candidate)

    for candidates in buckets.values():
        candidates.sort(key=lambda item: (-item.score, item.sample_id, item.function_id))
    return buckets


def candidate_from_record(path: Path, cwe: str, variant: str, record: dict[str, Any]) -> Candidate | None:
    if record.get("decompile_success") is not True:
        return None
    code = str(record.get("decompiled_code", "")).strip()
    name = str(record.get("original_function_name", "")).strip()
    if not code or len(code) < 180 or excluded_function(name, code):
        return None

    lowered = code.lower()
    matched = tuple(keyword for keyword in KEYWORDS[cwe] if keyword.lower() in lowered)
    control_flow_count = sum(lowered.count(token) for token in ("if (", "if(", "while (", "while(", "for (", "for(", "switch ("))
    call_count = lowered.count("(") - control_flow_count
    score = len(matched) * 100 + min(control_flow_count, 20) * 8 + min(call_count, 30) + min(len(code) // 250, 20)
    if not matched:
        score -= 50

    return Candidate(
        input_path=path,
        cwe=cwe,
        variant=variant,
        sample_id=str(record.get("sample_id", path.name.removesuffix(".decompiled.jsonl"))),
        function_id=str(record.get("function_id", "")),
        function_entry=str(record.get("function_entry", "")),
        original_function_name=name,
        code=code,
        score=score,
        matched_keywords=matched,
    )


def excluded_function(name: str, code: str) -> bool:
    lowered_name = name.lower()
    if name in EXCLUDED_NAMES or name.startswith("<EXTERNAL>::"):
        return True
    if lowered_name.startswith("thunk_") or lowered_name.startswith("plt_"):
        return True
    if WRAPPER_PATTERN.match(code):
        return True
    return False


def _select_candidates(
    buckets: dict[tuple[str, str], list[Candidate]],
    *,
    limit: int,
    distribution: dict[tuple[str, str], int] | None,
) -> list[Candidate]:
    if limit < 1:
        return []
    requested = dict(distribution or DEFAULT_DISTRIBUTION)
    selected: list[Candidate] = []
    used_samples: set[tuple[str, str, str]] = set()

    if distribution is None and limit != sum(DEFAULT_DISTRIBUTION.values()):
        requested = {key: 0 for key in DEFAULT_DISTRIBUTION}
        keys = list(DEFAULT_DISTRIBUTION)
        for index in range(limit):
            requested[keys[index % len(keys)]] += 1

    for key, count in requested.items():
        for candidate in buckets.get(key, []):
            sample_key = (candidate.cwe, candidate.variant, candidate.sample_id)
            if sample_key in used_samples:
                continue
            selected.append(candidate)
            used_samples.add(sample_key)
            if sum(1 for item in selected if (item.cwe, item.variant) == key) >= count:
                break

    if len(selected) < limit:
        remaining = sorted(
            (item for candidates in buckets.values() for item in candidates if item not in selected),
            key=lambda item: (-item.score, item.cwe, item.variant, item.sample_id, item.function_id),
        )
        selected.extend(remaining[: limit - len(selected)])
    return selected[:limit]


def stable_record_id(candidate: Candidate) -> str:
    value = ":".join(
        (candidate.cwe, candidate.variant, candidate.sample_id, candidate.function_id, candidate.function_entry)
    )
    return f"pilot_{hashlib.sha1(value.encode('utf-8')).hexdigest()[:16]}"


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(payload, dict):
                    records.append(payload)
    except OSError:
        return []
    return records


def write_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
