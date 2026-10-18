"""
Stands in for the paper's TSK extension (Section 4.1): given a recovered
master key and a file/folder's fscrypt encryption context (key
descriptor, nonce, content/filename mode), derive that file's per-file key
and decrypt its filename or content. This is a plain reimplementation on
top of the shared EXT4 reader rather than an actual patch to TSK's C
codebase, since forking and rebuilding TSK isn't practical for a course
project -- but it exercises exactly the same cryptography TSK's `-K`
extension would.

Correctness note on CBC-CTS (used below for filename decryption): this is
hand-derived directly from the AES-CBC encryption equations (see the long
comment on `cbc_cts_decrypt`) rather than recalled from a spec, so it is
internally consistent (round-trips correctly, see `_self_test` at the
bottom) and algebraically sound, but has NOT been cross-checked against
ciphertext produced by a real Android kernel. Verify it against a known
device sample before relying on it for anything but coursework.
"""
from __future__ import annotations

from typing import Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

AES_BLOCK = 16


# ---------------------------------------------------------------------------
# Per-file key derivation (same primitive as master_key_recovery.py, applied
# forwards instead of inverted: paper Listing 1, derive_key_aes).
# ---------------------------------------------------------------------------


def derive_file_key(master_key_512: bytes, nonce16: bytes) -> bytes:
    """DEKf = AES-128-ECB-Encrypt(key=nonce, plaintext=master_key), applied
    blockwise over the 512-bit (4-block) master key."""
    if len(master_key_512) != 64:
        raise ValueError("master key must be 64 bytes (512 bits)")
    if len(nonce16) != 16:
        raise ValueError("nonce must be 16 bytes")
    encryptor = Cipher(algorithms.AES(nonce16), modes.ECB()).encryptor()
    return encryptor.update(master_key_512) + encryptor.finalize()


# ---------------------------------------------------------------------------
# Content decryption: AES-256-XTS, keyed by the full 64-byte DEKf (the
# `cryptography` library's XTS mode takes a single key blob twice the
# normal AES key length and splits it into the data/tweak key halves
# per the XTS spec -- exactly matching our 512-bit DEKf convention).
#
# fscrypt's tweak for the "direct key" / default policy is the file's
# logical block number, little-endian, zero-extended to 16 bytes
# (see Documentation/filesystems/fscrypt.rst, "IV computation").
# ---------------------------------------------------------------------------


def _xts_tweak_for_block(block_index: int) -> bytes:
    return block_index.to_bytes(8, "little") + b"\x00" * 8


def decrypt_file_content(dekf: bytes, ciphertext: bytes, block_size: int = 4096, start_block_index: int = 0) -> bytes:
    if len(dekf) != 64:
        raise ValueError("DEKf must be 64 bytes (512 bits) for AES-256-XTS")
    if len(ciphertext) % block_size != 0:
        raise ValueError(f"ciphertext length must be a multiple of block_size={block_size}")

    out = bytearray()
    for i, offset in enumerate(range(0, len(ciphertext), block_size)):
        chunk = ciphertext[offset : offset + block_size]
        tweak = _xts_tweak_for_block(start_block_index + i)
        decryptor = Cipher(algorithms.AES(dekf), modes.XTS(tweak)).decryptor()
        out += decryptor.update(chunk) + decryptor.finalize()
    return bytes(out)


# ---------------------------------------------------------------------------
# Filename decryption: AES-256-CBC with ciphertext stealing (fscrypt's
# AES-256-CTS mode), zero IV, keyed directly by DEKf.
#
# Derivation of the ciphertext-stealing boundary case (CS3), worked out
# from the CBC equations themselves rather than recalled from a spec:
#
# Split the (zero-right-padded-to-a-block-boundary) plaintext into blocks
# P_1 .. P_{n-1} (all full) and P_n (the real, possibly-partial, final
# block of r bytes, its tail conceptually zero-padded to P_n' for the
# purposes of this derivation). Standard CBC would produce:
#
#     C_i = AES_Encrypt(K, P_i XOR C_{i-1})      for i = 1..n-2
#     C_{n-1} = AES_Encrypt(K, P_{n-1} XOR C_{n-2})
#     C_n     = AES_Encrypt(K, P_n' XOR C_{n-1})
#
# CS3 transmits C_1..C_{n-2} unchanged, but swaps the last two blocks and
# truncates: it sends C_n in full (in position n-1) and only the first r
# bytes of C_{n-1} (in the final position). To decrypt given only those r
# bytes of C_{n-1} (call them D_n') plus the full C_n:
#
#     X := AES_Decrypt(K, C_n) = P_n' XOR C_{n-1}
#
# Since P_n' is `P_n` (r real bytes) followed by zero padding:
#     X[0:r]  = P_n XOR C_{n-1}[0:r] = P_n XOR D_n'   =>  P_n = X[0:r] XOR D_n'
#     X[r:bs] = 0   XOR C_{n-1}[r:bs]                 =>  C_{n-1}[r:bs] = X[r:bs]
#
# which reconstructs C_{n-1} in full (= D_n' || X[r:bs]), letting P_{n-1}
# and everything before it be recovered with plain CBC decryption.
# ---------------------------------------------------------------------------


def _aes_cbc_decrypt_nopad(key: bytes, iv: bytes, data: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return decryptor.update(data) + decryptor.finalize()


def _aes_cbc_encrypt_nopad(key: bytes, iv: bytes, data: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def _aes_ecb_decrypt_block(key: bytes, block: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return decryptor.update(block) + decryptor.finalize()


def _aes_ecb_encrypt_block(key: bytes, block: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


def cbc_cts_encrypt(key: bytes, plaintext: bytes, iv: bytes = b"\x00" * 16) -> bytes:
    """AES-CBC with ciphertext stealing (CS3). `plaintext` must be at
    least one full AES block (16 bytes) -- a block cipher fundamentally
    can't produce invertible output shorter than one block, so (matching
    real fscrypt behavior) callers must zero-pad names shorter than 16
    bytes up to 16 bytes *before* calling this. Ciphertext stealing then
    only ever applies to the true final partial block, if any, above
    that floor; the wire-format ciphertext is the same length as the
    (padded) plaintext."""
    if len(plaintext) < AES_BLOCK:
        raise ValueError(f"plaintext must be at least {AES_BLOCK} bytes")
    n_full, r = divmod(len(plaintext), AES_BLOCK)
    if r == 0:
        n = n_full
        r = AES_BLOCK
    else:
        n = n_full + 1

    if n == 1:
        # Exactly one block (r == AES_BLOCK here): plain CBC, no stealing.
        return _aes_cbc_encrypt_nopad(key, iv, plaintext)

    p_prefix = plaintext[: (n - 2) * AES_BLOCK]
    p_second_last = plaintext[(n - 2) * AES_BLOCK : (n - 1) * AES_BLOCK]
    p_last = plaintext[(n - 1) * AES_BLOCK :]  # length r, 1 <= r <= AES_BLOCK

    c_prefix = _aes_cbc_encrypt_nopad(key, iv, p_prefix) if p_prefix else b""
    c_prev = c_prefix[-AES_BLOCK:] if c_prefix else iv

    c_second_last = _aes_ecb_encrypt_block(key, _xor(c_prev, p_second_last))

    p_last_padded = p_last + b"\x00" * (AES_BLOCK - r)
    c_last = _aes_ecb_encrypt_block(key, _xor(c_second_last, p_last_padded))

    # Transmitted order: prefix, then C_n (full), then the first r bytes of C_{n-1}.
    return c_prefix + c_last + c_second_last[:r]


def cbc_cts_decrypt(key: bytes, ciphertext: bytes, original_length: int, iv: bytes = b"\x00" * 16) -> bytes:
    """Inverse of `cbc_cts_encrypt`. `original_length` (the padded
    plaintext length used when encrypting, >= 16) must be supplied --
    ciphertext stealing doesn't self-encode it."""
    if original_length < AES_BLOCK:
        raise ValueError(f"original_length must be at least {AES_BLOCK} bytes")
    n_full, r = divmod(original_length, AES_BLOCK)
    if r == 0:
        n = n_full
        r = AES_BLOCK
    else:
        n = n_full + 1

    if n == 1:
        return _aes_cbc_decrypt_nopad(key, iv, ciphertext)

    c_prefix = ciphertext[: (n - 2) * AES_BLOCK]
    c_last_full = ciphertext[(n - 2) * AES_BLOCK : (n - 1) * AES_BLOCK]  # this is C_n
    d_tail = ciphertext[(n - 1) * AES_BLOCK :]  # first r bytes of C_{n-1}

    x = _aes_ecb_decrypt_block(key, c_last_full)
    p_last = _xor(x[:r], d_tail)
    c_second_last = d_tail + x[r:]

    c_prev = c_prefix[-AES_BLOCK:] if c_prefix else iv
    p_second_last = _xor(_aes_ecb_decrypt_block(key, c_second_last), c_prev)

    p_prefix = _aes_cbc_decrypt_nopad(key, iv, c_prefix) if c_prefix else b""

    return p_prefix + p_second_last + p_last


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def decrypt_filename(dekf: bytes, ciphertext: bytes, original_length: Optional[int] = None) -> bytes:
    """Decrypts an fscrypt AES-256-CTS-encrypted filename. `original_length`
    defaults to len(ciphertext) (the common case where the on-disk name
    wasn't padded past a block boundary); pass it explicitly if you know
    the name was padded up from something shorter than 16 bytes."""
    if len(dekf) != 64:
        raise ValueError("DEKf must be 64 bytes (512 bits)")
    key = dekf[:32]  # AES-256-CTS uses the first 256-bit half, per fscrypt
    length = original_length if original_length is not None else len(ciphertext)
    return cbc_cts_decrypt(key, ciphertext, len(ciphertext))[:length]


def _self_test() -> None:
    """Round-trip sanity check for cbc_cts_encrypt/decrypt across lengths
    that exercise every boundary case (exact block multiples, one byte
    over/under a block, single block, multi-block)."""
    import os

    key = os.urandom(32)
    for length in (16, 17, 20, 31, 32, 33, 64, 100):
        plaintext = os.urandom(length)
        ciphertext = cbc_cts_encrypt(key, plaintext)
        assert len(ciphertext) == length, f"length mismatch at {length}"
        recovered = cbc_cts_decrypt(key, ciphertext, length)
        assert recovered == plaintext, f"round-trip failed at length {length}"
    print("fbe_crypto self-test: all CBC-CTS round trips OK")


if __name__ == "__main__":
    _self_test()
