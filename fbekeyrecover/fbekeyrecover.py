"""
fbekeyrecover -- CLI reproduction of the paper's Section 4.2 tool.

Given one or more RAM dumps and a copy of the device's userdata partition,
recovers candidate Android FBE master keys per key descriptor and writes
them in the same `id:key_part1:key_part2` format the paper's TSK patch
(flsK, istatK, icatK, ifindK's `-K` argument) consumes -- also the format
`fbe_forensic_toolkit.decrypt_tool` reads in this reproduction.

Usage:
    python3 -m fbekeyrecover.fbekeyrecover \
        --memory dump1.lime dump2.lime \
        --userdata userdata.img \
        --aeskeyfind /path/to/aeskeyfind \
        --out master_keys.txt
"""
from __future__ import annotations

import argparse
import sys

from fbe_common.ext4_inode_scanner import Ext4InodeScanner
from fbekeyrecover.aeskeyfind_runner import collect_candidate_keys
from fbekeyrecover.master_key_recovery import (
    build_master_key_candidates,
    group_nonces_by_descriptor,
    recover_master_key_halves,
)


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--memory", nargs="+", required=True, help="one or more RAM dump files"
    )
    parser.add_argument(
        "--userdata", required=True, help="raw EXT4 image of the userdata partition"
    )
    parser.add_argument(
        "--aeskeyfind", required=True, help="path to the aeskeyfind binary"
    )
    parser.add_argument(
        "--out", default="master_keys.txt", help="where to write recovered keys"
    )
    parser.add_argument(
        "--top-n",
        type=int,
        default=4,
        help="how many top-voted half-key candidates to print per descriptor",
    )
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)

    print("[1/3] Extracting fscrypt encryption contexts from the userdata image...")
    with Ext4InodeScanner(args.userdata) as scanner:
        contexts = list(scanner.scan_all_inodes())
    print(f"      found {len(contexts)} encrypted inode(s)")
    if not contexts:
        print("      no encrypted inodes found -- is this really an FBE userdata image?")
        return 1

    nonce_bins = group_nonces_by_descriptor(contexts)
    if not nonce_bins:
        print("      no descriptors eligible for this attack (all use the new KDF)")
        return 1
    for descriptor, nonces in nonce_bins.items():
        print(f"      descriptor {descriptor}: {len(nonces)} nonce(s)")

    print("\n[2/3] Running aeskeyfind over the supplied memory dump(s)...")
    candidate_keys = collect_candidate_keys(args.aeskeyfind, args.memory)
    print(f"      total candidate 256-bit keys collected: {len(candidate_keys)}")
    if not candidate_keys:
        print("      no AES-256 key candidates found in memory -- nothing to recover")
        return 1

    print("\n[3/3] Voting on master-key halves per descriptor...")
    recovered = []
    for descriptor, nonces in nonce_bins.items():
        halves = recover_master_key_halves(candidate_keys, nonces, top_n=args.top_n)
        if len(halves) < 2:
            print(f"  descriptor {descriptor}: not enough distinct candidates, skipping")
            continue

        print(f"  descriptor {descriptor}:")
        for h in halves:
            print(f"    {h.value.hex()}  (hits: {h.hits})")

        candidates = build_master_key_candidates(halves, max_candidates=2)
        # Pick the ordering built from the two highest-voted distinct halves.
        best = candidates[0] if candidates else None
        if best:
            part1, part2 = best[:32], best[32:]
            recovered.append((descriptor, part1, part2))
            print(f"    -> best master key candidate: {part1.hex()}:{part2.hex()}")

    if not recovered:
        print("\nNo master keys recovered.")
        return 1

    with open(args.out, "w") as f:
        for descriptor, part1, part2 in recovered:
            f.write(f"{descriptor}:{part1.hex()}:{part2.hex()}\n")
    print(f"\nWrote {len(recovered)} candidate master key(s) to {args.out}")
    print(
        "Verify each candidate with fbe_forensic_toolkit.decrypt_tool before "
        "trusting it (e.g. decrypt a filename and confirm it's printable/sane) -- "
        "the vote only tells you which half recurred most, not that it's certainly correct."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
