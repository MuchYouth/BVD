"""Run a resumable LLMDFA-style trace pilot over selected C functions."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from src.llmdfa_adapter.llm_client import ChatClient


PROMPT_VERSION = "llmdfa_decompiled_trace_v1"
DEFAULT_PROMPT_PATH = Path("configs/prompts/llmdfa_decompiled_trace_v1.md")


@dataclass(frozen=True)
class TraceRunSummary:
    selected: int
    attempted: int
    succeeded: int
    failed: int
    skipped_resume: int
    skipped_quota: int
    output_root: str
    health: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "selected": self.selected,
            "attempted": self.attempted,
            "succeeded": self.succeeded,
            "failed": self.failed,
            "skipped_resume": self.skipped_resume,
            "skipped_quota": self.skipped_quota,
            "output_root": self.output_root,
            "health": self.health,
        }


def run_trace_pilot(
    manifest_records: Iterable[dict[str, Any]],
    *,
    client: ChatClient,
    output_root: str | Path,
    prompt_path: str | Path = DEFAULT_PROMPT_PATH,
    daily_limit: int = 50,
    resume: bool = True,
    force: bool = False,
    dry_run: bool = False,
    now: datetime | None = None,
) -> TraceRunSummary:
    records = list(manifest_records)
    destination = Path(output_root)
    destination.mkdir(parents=True, exist_ok=True)
    raw_path = destination / "raw_responses.jsonl"
    parsed_path = destination / "parsed_results.jsonl"
    ledger_path = destination / "quota_ledger.jsonl"
    summary_path = destination / "run_summary.json"

    prompt_template = Path(prompt_path).read_text(encoding="utf-8")
    completed = successful_record_ids(parsed_path) if resume and not force else set()
    current_time = now or datetime.now(timezone.utc)
    quota_date = current_time.date().isoformat()
    quota_used = count_daily_attempts(ledger_path, quota_date, client.provider, client.model)
    parsed_by_id = index_jsonl(parsed_path, "record_id")
    health = {"status": "dry_run"} if dry_run else client.health_check()

    attempted = succeeded = failed = skipped_resume = skipped_quota = 0
    for record in records:
        record_id = str(record.get("record_id", ""))
        if resume and not force and record_id in completed:
            skipped_resume += 1
            continue
        if dry_run:
            continue
        if quota_used >= daily_limit:
            skipped_quota += 1
            continue

        source_path = Path(str(record.get("source_path", "")))
        try:
            code = source_path.read_text(encoding="utf-8")
        except OSError as exc:
            failed += 1
            parsed_by_id[record_id] = failed_parsed_record(record, f"source_read_failed: {exc}")
            continue

        attempted += 1
        quota_used += 1
        attempt_time = datetime.now(timezone.utc).isoformat()
        append_jsonl(
            ledger_path,
            {
                "timestamp": attempt_time,
                "date": quota_date,
                "record_id": record_id,
                "provider": client.provider,
                "model": client.model,
                "event": "attempt",
            },
        )
        try:
            result = client.complete(
                system_prompt="You are a precise static data-flow analysis assistant.",
                user_prompt=prompt_template.format(code=code),
            )
        except Exception as exc:  # noqa: BLE001 - preserve provider failures for resume.
            error = str(exc)
            failed += 1
            append_jsonl(
                raw_path,
                {
                    "record_id": record_id,
                    "status": "failed",
                    "provider": client.provider,
                    "model": client.model,
                    "error": error,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            )
            append_jsonl(
                ledger_path,
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "date": quota_date,
                    "record_id": record_id,
                    "provider": client.provider,
                    "model": client.model,
                    "event": "failed",
                    "error": error,
                },
            )
            parsed_by_id[record_id] = failed_parsed_record(record, f"provider_request_failed: {error}")
            continue

        succeeded += 1
        raw_record = {
            "record_id": record_id,
            "status": "success",
            "source_file": record.get("source_path", ""),
            "function_id": record.get("function_id", ""),
            "provider": result.provider,
            "model": result.model,
            "endpoint": result.endpoint,
            "prompt_version": PROMPT_VERSION,
            "response_text": result.text,
            "usage": result.usage,
            "raw_provider_response": result.raw_response,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        append_jsonl(raw_path, raw_record)
        append_jsonl(
            ledger_path,
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "date": quota_date,
                "record_id": record_id,
                "provider": result.provider,
                "model": result.model,
                "event": "success",
            },
        )
        parsed_by_id[record_id] = {
            "record_id": record_id,
            "source_file": record.get("source_path", ""),
            "function_id": record.get("function_id", ""),
            "source_sink_result": {},
            "dataflow_result": {
                "raw_llmdfa_trace": result.text,
                "usage": result.usage,
            },
            "path_validation_result": {},
            "raw_output": raw_record,
            "warnings": [],
        }

    write_jsonl(parsed_path, parsed_by_id.values())
    summary = TraceRunSummary(
        selected=len(records),
        attempted=attempted,
        succeeded=succeeded,
        failed=failed,
        skipped_resume=skipped_resume,
        skipped_quota=skipped_quota,
        output_root=destination.as_posix(),
        health=health,
    )
    summary_path.write_text(json.dumps(summary.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    return summary


def failed_parsed_record(record: dict[str, Any], warning: str) -> dict[str, Any]:
    return {
        "record_id": record.get("record_id", ""),
        "source_file": record.get("source_path", ""),
        "function_id": record.get("function_id", ""),
        "source_sink_result": {},
        "dataflow_result": {},
        "path_validation_result": {},
        "raw_output": {},
        "warnings": [warning],
    }


def successful_record_ids(path: Path) -> set[str]:
    return {
        str(record.get("record_id", ""))
        for record in read_jsonl(path)
        if str(record.get("dataflow_result", {}).get("raw_llmdfa_trace", "")).strip()
    }


def count_daily_attempts(path: Path, date: str, provider: str, model: str) -> int:
    return sum(
        1
        for record in read_jsonl(path)
        if record.get("date") == date
        and record.get("provider") == provider
        and record.get("model") == model
        and record.get("event") == "attempt"
    )


def index_jsonl(path: Path, key: str) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for record in read_jsonl(path):
        value = str(record.get(key, ""))
        if value:
            indexed[value] = record
    return indexed


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                records.append(payload)
    return records


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def write_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
