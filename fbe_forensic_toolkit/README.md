# fbe_forensic_toolkit

Reproduces the *capability* the paper's TSK (Section 4.1) and Plaso
(Section 4.3) extensions add — decrypting FBE filenames/content once you
have a master key — without forking either upstream project. See
[`plaso_notes.md`](plaso_notes.md) for why, and how to wire this into a
real Plaso run if you want to go further.

## Modules

- [`fbe_crypto.py`](fbe_crypto.py) — the cryptography:
  - `derive_file_key(master_key, nonce)` — per-file key derivation
    (`derive_key_aes`, paper Listing 1).
  - `decrypt_file_content(dekf, ciphertext, block_size)` — AES-256-XTS
    content decryption, tweak = little-endian block index (fscrypt
    default IV policy).
  - `decrypt_filename(dekf, ciphertext, original_length)` —
    AES-256-CTS (CBC with ciphertext stealing) filename decryption.
    Run `python3 -m fbe_forensic_toolkit.fbe_crypto` to execute its
    built-in round-trip self-test.
- [`decrypt_tool.py`](decrypt_tool.py) — CLI: given `master_keys.txt`
  (from `fbekeyrecover`) and an inode number, decrypts that inode's
  filename or content.

## ⚠️ Verify before trusting on real evidence

`decrypt_file_content`'s AES-XTS usage is a standard, directly-supported
mode (`cryptography`'s `modes.XTS`) and should be correct as-is.

`decrypt_filename`'s CBC-CTS implementation was hand-derived algebraically
from the AES-CBC equations (see the long comment above `cbc_cts_decrypt`
in `fbe_crypto.py`) rather than copied from a reference implementation.
It passes its own round-trip self-test, which proves internal
consistency, but has **not** been cross-checked against ciphertext
produced by a real Android kernel. Before relying on it for anything
beyond this course exercise, validate it against one known
plaintext/ciphertext filename pair from an actual device or AVD image.

## Usage

```bash
pip install -r requirements.txt

# from the package/ root:
python3 -m fbe_forensic_toolkit.decrypt_tool \
    --userdata userdata.img \
    --master-keys ../fbekeyrecover/master_keys.txt \
    --inode 131099 \
    --mode filename --ciphertext-hex <hex bytes from a directory entry>
```
