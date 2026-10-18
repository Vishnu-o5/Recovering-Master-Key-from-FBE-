"""
Synthetic end-to-end validation of the attack chain (no real device, RAM
dump, or disk image needed): generates a random master key and several
file nonces, derives each file's DEKf the same way Android's kernel does
(fbe_forensic_toolkit.fbe_crypto.derive_file_key), splits those DEKf's
into 256-bit halves to stand in for what aeskeyfind would find scattered
in RAM, mixes in random noise keys/nonces, and checks that
master_key_recovery correctly recovers the original master key purely
from voting -- the same algorithm fbekeyrecover.py runs against a real
RAM dump + userdata image.

Run with: python3 -m fbekeyrecover.selftest
"""
from __future__ import annotations

import os

from fbe_forensic_toolkit.fbe_crypto import derive_file_key
from fbekeyrecover.master_key_recovery import (
    build_master_key_candidates,
    recover_master_key_halves,
)


def main() -> None:
    master_key = os.urandom(64)
    nonces = [os.urandom(16) for _ in range(6)]

    # Simulate aeskeyfind's output: the real DEKf halves for each file,
    # plus a pile of unrelated noise keys (as if from other
    # processes/buffers in the same memory dump).
    candidate_keys = []
    for nonce in nonces:
        dekf = derive_file_key(master_key, nonce)
        candidate_keys.append(dekf[:32])
        candidate_keys.append(dekf[32:])
    candidate_keys += [os.urandom(32) for _ in range(500)]

    halves = recover_master_key_halves(candidate_keys, nonces, top_n=4)
    print("Top voted halves:")
    for h in halves:
        print(f"  {h.value.hex()}  hits={h.hits}")

    candidates = build_master_key_candidates(halves, max_candidates=2)
    assert master_key in candidates, "master key NOT recovered -- attack chain is broken"
    print(f"\nOK: original master key recovered among {len(candidates)} candidate(s).")


if __name__ == "__main__":
    main()
