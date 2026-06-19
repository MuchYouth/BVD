"""Convert Ghidra decompiled JSONL into anonymized LLMDFA source files."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


DEFAULT_INPUT_ROOT = Path("data/ghidra_decompiled")
DEFAULT_OUTPUT_ROOT = Path("data/llmdfa_inputs")
FORBIDDEN_PATTERN = re.compile(r"CWE[-_ ]?\d+|bad|good|juliet", re.IGNORECASE)
IDENTIFIER_PATTERN = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")


@dataclass(frozen=True)
class ConvertedFunction:
    original_sample_id: str
    sample_id: str
    function_id: str
    original_function_name: str
    function_entry: str
    source_path: Path
    language: str
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "original_sample_id": self.original_sample_id,
            "sample_id": self.sample_id,
            "function_id": self.function_id,
            "original_function_name": self.original_function_name,
            "function_entry": self.function_entry,
            "source_path": self.source_path.as_posix(),
            "language": self.language,
            "warnings": self.warnings,
        }


@dataclass(frozen=True)
class ConversionResult:
    input_paths: list[Path]
    output_root: Path
    converted: list[ConvertedFunction]
    skipped: int
    manifest_path: Path

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_paths": [path.as_posix() for path in self.input_paths],
            "output_root": self.output_root.as_posix(),
            "converted": [item.to_dict() for item in self.converted],
            "skipped": self.skipped,
            "manifest_path": self.manifest_path.as_posix(),
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-root", default=str(DEFAULT_INPUT_ROOT), help="Directory containing *.decompiled.jsonl files.")
    parser.add_argument("--output-root", default=str(DEFAULT_OUTPUT_ROOT), help="Directory for anonymized LLMDFA input files.")
    parser.add_argument("--language", choices=["c", "cpp"], default="c", help="Source extension for converted functions.")
    parser.add_argument("--manifest-name", default="manifest.jsonl", help="Conversion manifest filename under output root.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = convert_decompiled_tree(
        Path(args.input_root),
        Path(args.output_root),
        language=args.language,
        manifest_name=args.manifest_name,
    )
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0


def convert_decompiled_tree(
    input_root: Path = DEFAULT_INPUT_ROOT,
    output_root: Path = DEFAULT_OUTPUT_ROOT,
    *,
    language: str = "c",
    manifest_name: str = "manifest.jsonl",
) -> ConversionResult:
    paths = sorted(input_root.rglob("*.decompiled.jsonl"))
    return convert_decompiled_jsonl(paths, output_root, language=language, manifest_name=manifest_name)


def convert_decompiled_jsonl(
    input_paths: Iterable[str | Path],
    output_root: Path = DEFAULT_OUTPUT_ROOT,
    *,
    language: str = "c",
    manifest_name: str = "manifest.jsonl",
) -> ConversionResult:
    """Write anonymized function files and a conversion manifest."""

    paths = [Path(path) for path in input_paths]
    output_root.mkdir(parents=True, exist_ok=True)
    converted: list[ConvertedFunction] = []
    skipped = 0

    for input_path in paths:
        for record in read_jsonl(input_path):
            if record.get("decompile_success") is not True:
                skipped += 1
                continue
            decompiled_code = str(record.get("decompiled_code", ""))
            if not decompiled_code.strip():
                skipped += 1
                continue

            original_sample_id = str(record.get("sample_id", "sample"))
            sample_id = anonymized_sample_id(original_sample_id)
            function_id = safe_function_id(str(record.get("function_id", "")))
            original_function_name = str(record.get("original_function_name", ""))
            function_entry = str(record.get("function_entry", ""))
            extension = "cpp" if language == "cpp" else "c"
            source_dir = output_root / sample_id
            source_dir.mkdir(parents=True, exist_ok=True)
            source_path = source_dir / f"{function_id}.{extension}"
            warnings: list[str] = []
            sanitized_code = anonymize_code(
                decompiled_code,
                function_id=function_id,
                original_function_name=original_function_name,
                warnings=warnings,
            )
            source_path.write_text(sanitized_code, encoding="utf-8")
            converted.append(
                ConvertedFunction(
                    original_sample_id=original_sample_id,
                    sample_id=sample_id,
                    function_id=function_id,
                    original_function_name=original_function_name,
                    function_entry=function_entry,
                    source_path=source_path,
                    language=extension,
                    warnings=warnings,
                )
            )

    manifest_path = output_root / manifest_name
    write_jsonl(manifest_path, [item.to_dict() for item in converted])
    return ConversionResult(
        input_paths=paths,
        output_root=output_root,
        converted=converted,
        skipped=skipped,
        manifest_path=manifest_path,
    )


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not path.exists():
        return records
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                data = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict):
                records.append(data)
    return records


def write_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
            count += 1
    return count


def anonymized_sample_id(sample_id: str) -> str:
    digest = hashlib.sha1(sample_id.encode("utf-8")).hexdigest()[:16]
    return f"sample_{digest}"


def safe_function_id(function_id: str) -> str:
    if re.fullmatch(r"func_[0-9]{4,}", function_id):
        return function_id
    digest = hashlib.sha1(function_id.encode("utf-8")).hexdigest()[:8]
    return f"func_{digest}"


def anonymize_code(
    code: str,
    *,
    function_id: str,
    original_function_name: str,
    warnings: list[str],
) -> str:
    sanitized = code
    if original_function_name and IDENTIFIER_PATTERN.fullmatch(original_function_name):
        sanitized = re.sub(rf"\b{re.escape(original_function_name)}\b", function_id, sanitized)

    forbidden_hits = sorted(set(match.group(0) for match in FORBIDDEN_PATTERN.finditer(sanitized)))
    if forbidden_hits:
        warnings.extend(f"redacted_label_token:{hit}" for hit in forbidden_hits)
        sanitized = FORBIDDEN_PATTERN.sub("anon", sanitized)

    return sanitized


if __name__ == "__main__":
    raise SystemExit(main())
