#!/usr/bin/env python3
"""Prepare external repositories without modifying vendored source files."""

from __future__ import annotations

import argparse
import subprocess
from dataclasses import dataclass
from pathlib import Path


DEFAULT_LLMDFA_URL = "https://github.com/chengpeng-wang/LLMDFA.git"
DEFAULT_LLMDFA_PATH = Path("external/LLMDFA")


@dataclass(frozen=True)
class RepoStatus:
    path: Path
    exists: bool
    is_git_repo: bool
    head: str
    dirty: bool
    message: str

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path.as_posix(),
            "exists": self.exists,
            "is_git_repo": self.is_git_repo,
            "head": self.head,
            "dirty": self.dirty,
            "message": self.message,
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--llmdfa-url", default=DEFAULT_LLMDFA_URL, help="LLMDFA git URL.")
    parser.add_argument("--llmdfa-path", default=str(DEFAULT_LLMDFA_PATH), help="LLMDFA checkout path.")
    parser.add_argument("--dry-run", action="store_true", help="Print intended actions without cloning.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    status = ensure_llmdfa_repo(Path(args.llmdfa_path), args.llmdfa_url, dry_run=args.dry_run)
    print_status(status)
    return 0 if status.exists or args.dry_run else 1


def ensure_llmdfa_repo(path: Path, url: str, *, dry_run: bool = False) -> RepoStatus:
    """Clone LLMDFA when missing, otherwise report checkout status only."""

    if path.exists():
        return inspect_repo(path)

    if dry_run:
        return RepoStatus(
            path=path,
            exists=False,
            is_git_repo=False,
            head="",
            dirty=False,
            message=f"would clone {url} into {path}",
        )

    path.parent.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        ["git", "clone", url, str(path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return RepoStatus(
            path=path,
            exists=False,
            is_git_repo=False,
            head="",
            dirty=False,
            message=f"clone failed: {completed.stderr.strip()}",
        )
    return inspect_repo(path)


def inspect_repo(path: Path) -> RepoStatus:
    if not path.is_dir():
        return RepoStatus(path=path, exists=True, is_git_repo=False, head="", dirty=False, message="path exists but is not a directory")

    git_dir = path / ".git"
    is_git_repo = git_dir.exists()
    head = git_output(path, ["git", "rev-parse", "--short", "HEAD"]) if is_git_repo else ""
    porcelain = git_output(path, ["git", "status", "--short"]) if is_git_repo else ""
    dirty = bool(porcelain.strip())
    message = "LLMDFA checkout present"
    if not is_git_repo:
        message = "path exists but does not look like a git checkout"
    elif dirty:
        message = "LLMDFA checkout present with local changes/untracked files"
    return RepoStatus(path=path, exists=True, is_git_repo=is_git_repo, head=head.strip(), dirty=dirty, message=message)


def git_output(cwd: Path, command: list[str]) -> str:
    completed = subprocess.run(command, cwd=cwd, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        return ""
    return completed.stdout


def print_status(status: RepoStatus) -> None:
    print(f"path: {status.path}")
    print(f"exists: {status.exists}")
    print(f"is_git_repo: {status.is_git_repo}")
    print(f"head: {status.head}")
    print(f"dirty: {status.dirty}")
    print(f"message: {status.message}")


if __name__ == "__main__":
    raise SystemExit(main())
