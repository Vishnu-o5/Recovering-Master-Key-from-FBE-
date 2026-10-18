"""
Thin wrapper around the external `aeskeyfind` tool
(https://github.com/makomk/aeskeyfind, GPL), which locates AES key
schedules resident in a raw memory image. The paper (Section 3.2) uses it
instead of parsing kernel structures directly, specifically because it is
robust against the partial memory corruption a cold boot attack causes.

aeskeyfind is not bundled here -- build it from its own repository and
point this module at the resulting binary.

Output format (verified against aeskeyfind.c's print_key()): run
*without* -v, its stdout is simply one contiguous hex string per found
key candidate, no labels -- 64 hex chars (32 bytes) for a 256-bit
candidate, 32 hex chars (16 bytes) for a 128-bit one. Progress reporting
goes to stderr, so stdout parsing doesn't need to filter it out, but we
pass -q anyway to keep stderr quiet.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Iterable, List

_HEX_CHARS = set("0123456789abcdefABCDEF")


def run_aeskeyfind(binary_path: str, memory_dump: str) -> List[bytes]:
    """Runs aeskeyfind against one memory dump file and returns every
    256-bit (32-byte) AES key candidate it reports. 128-bit candidates are
    ignored: the paper's attack only concerns the 256-bit DEKf fragments
    that make up Android's 512-bit FBE keys."""
    result = subprocess.run(
        [binary_path, "-q", memory_dump],
        check=True,
        capture_output=True,
        text=True,
    )
    return _parse_aeskeyfind_output(result.stdout)


def _parse_aeskeyfind_output(output: str) -> List[bytes]:
    keys: List[bytes] = []
    for line in output.splitlines():
        line = line.strip()
        if len(line) != 64 or not all(c in _HEX_CHARS for c in line):
            continue  # not a 256-bit key line (could be a 128-bit line, blank, etc.)
        keys.append(bytes.fromhex(line))
    return keys


def collect_candidate_keys(binary_path: str, memory_dumps: Iterable[str]) -> List[bytes]:
    """Runs aeskeyfind over every supplied memory dump (the paper splits
    large dumps into multiple files to avoid an aeskeyfind crash) and pools
    all 256-bit candidates into one list."""
    all_keys: List[bytes] = []
    for dump in memory_dumps:
        path = Path(dump)
        if not path.exists():
            raise FileNotFoundError(f"memory dump not found: {dump}")
        found = run_aeskeyfind(binary_path, str(path))
        print(f"[aeskeyfind] {dump}: {len(found)} candidate 256-bit keys")
        all_keys.extend(found)
    return all_keys
