#!/usr/bin/env python3
"""Select and run a ten-function LLMDFA trace pilot."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.juliet.discovery import load_config
from src.llmdfa_adapter.llm_client import LLMClientError, client_from_settings
from src.llmdfa_adapter.pilot_selector import select_pilot_functions
from src.llmdfa_adapter.trace_runner import run_trace_pilot


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="configs/default.yaml")
    parser.add_argument("--input-root", default=None)
    parser.add_argument("--pilot-input-root", default=None)
    parser.add_argument("--output-root", default=None)
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--provider", choices=["freellm", "openai"], default=None)
    parser.add_argument("--model", default=None)
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--daily-limit", type=int, default=None)
    parser.add_argument("--timeout-sec", type=int, default=None)
    parser.add_argument("--resume", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config = load_config(args.config)
    settings = resolved_settings(config, args)
    records = select_pilot_functions(
        settings["input_root"],
        settings["pilot_input_root"],
        limit=args.limit,
        manifest_name="manifest_10.jsonl" if args.limit == 10 else f"manifest_{args.limit}.jsonl",
    )

    selection = {
        "selected": len(records),
        "manifest": str(Path(settings["pilot_input_root"]) / ("manifest_10.jsonl" if args.limit == 10 else f"manifest_{args.limit}.jsonl")),
        "records": [record.to_dict() for record in records],
    }
    if args.dry_run:
        print(json.dumps(selection, indent=2, sort_keys=True))

    try:
        client = client_from_settings(
            provider=settings["provider"],
            model=settings["model"],
            base_url=settings["base_url"],
            api_key_env=settings["api_key_env"],
            temperature=settings["temperature"],
            timeout_sec=settings["timeout_sec"],
        )
    except LLMClientError as exc:
        print(json.dumps({"error": str(exc), **selection}, indent=2, sort_keys=True))
        return 1

    summary = run_trace_pilot(
        [record.to_dict() for record in records],
        client=client,
        output_root=settings["output_root"],
        prompt_path=settings["prompt_path"],
        daily_limit=settings["daily_limit"],
        resume=args.resume,
        force=args.force,
        dry_run=args.dry_run,
    )
    print(json.dumps(summary.to_dict(), indent=2, sort_keys=True))
    return 0 if args.dry_run or summary.failed == 0 else 1


def resolved_settings(config: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    pilot = config.get("llmdfa_pilot", {})
    provider = args.provider or str(pilot.get("provider", "freellm"))
    model = args.model or str(pilot.get("model", "gpt-4o"))
    default_output = f"data/llmdfa_outputs/pilot_{provider}_{model.replace('-', '')}"
    return {
        "input_root": args.input_root or str(pilot.get("input_root", "data/pcode")),
        "pilot_input_root": args.pilot_input_root or str(pilot.get("pilot_input_root", "data/llmdfa_pilot_inputs")),
        "output_root": args.output_root or str(pilot.get("output_root", default_output)),
        "provider": provider,
        "model": model,
        "base_url": args.base_url or pilot.get("base_url"),
        "api_key_env": str(
            pilot.get("api_key_env", "FREELLM_API_KEY" if provider == "freellm" else "OPENAI_API_KEY")
        ),
        "temperature": float(pilot.get("temperature", 0)),
        "timeout_sec": args.timeout_sec or int(pilot.get("timeout_sec", 120)),
        "daily_limit": args.daily_limit or int(pilot.get("daily_limit", 50)),
        "prompt_path": str(pilot.get("prompt_path", "configs/prompts/llmdfa_decompiled_trace_v1.md")),
    }


if __name__ == "__main__":
    raise SystemExit(main())
