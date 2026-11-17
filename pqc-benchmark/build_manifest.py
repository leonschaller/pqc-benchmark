#!/usr/bin/env python3
"""Build a deterministic SHA-256 manifest for the benchmark sources and outputs."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent

# These patterns cover only files in the project root; virtual environments and
# other dependency trees are not traversed.
INCLUDE_PATTERNS = (
    "*.py",
    "environment.txt",
    "environment.json",
    "*.csv",
    "*_table.txt",
    "*_tables.txt",
    "*.png",
    "*notes*.md",
    "setup.txt",
    "requirements*.txt",
)


def sha256_file(path: Path) -> str:
    """Return the lowercase SHA-256 digest of *path*."""
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def selected_files(output_path: Path) -> list[Path]:
    """Return sorted, de-duplicated root-level files to hash."""
    excluded = {
        (PROJECT_ROOT / "SHA256SUMS").resolve(),
        output_path.resolve(),
    }
    candidates: set[Path] = set()
    for pattern in INCLUDE_PATTERNS:
        for path in PROJECT_ROOT.glob(pattern):
            resolved = path.resolve()
            if path.is_file() and resolved not in excluded:
                candidates.add(path)

    return sorted(
        candidates,
        key=lambda path: path.relative_to(PROJECT_ROOT).as_posix(),
    )


def write_manifest(output_path: Path) -> int:
    """Write the manifest and return the number of hashed files."""
    files = selected_files(output_path)
    lines = [
        f"{sha256_file(path)}  {path.relative_to(PROJECT_ROOT).as_posix()}\n"
        for path in files
    ]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="\n") as output:
        output.write("".join(lines))
    return len(files)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Hash the benchmark sources and outputs."
    )
    parser.add_argument(
        "output",
        nargs="?",
        default="SHA256SUMS",
        help="manifest path (relative paths are resolved from the project root)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    requested = Path(args.output)
    output_path = requested if requested.is_absolute() else PROJECT_ROOT / requested
    count = write_manifest(output_path)
    print(f"Wrote {output_path} with {count} SHA-256 entries.")


if __name__ == "__main__":
    main()
