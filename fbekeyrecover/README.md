# fbekeyrecover

Reproduction of the paper's Section 4.2 tool: recovers Android FBE master
keys from a RAM dump plus a copy of the userdata partition.

## How it works (paper Section 3.2)

1. **Nonces** (unencrypted, one per file/folder) are read from the EXT4
   image's `fscrypt` extended attribute via
   [`fbe_common/ext4_inode_scanner.py`](../fbe_common/ext4_inode_scanner.py),
   grouped ("binned") by which master-key descriptor they belong to.
2. **Candidate key fragments** are read out of the RAM dump with the
   external [`aeskeyfind`](https://github.com/makomk/aeskeyfind) tool,
   which locates AES-256 key schedules anywhere in memory (robust against
   the partial bit-rot a cold boot attack causes).
3. For each descriptor's bin, every `(candidate key, nonce)` pair is
   decrypted with `AES-128-ECB(key=nonce, data=candidate)` (inverting
   `derive_key_aes`, see [`master_key_recovery.py`](master_key_recovery.py)).
   Wrong pairings decrypt to noise; the *real* master-key halves recur
   across many different pairings and dominate the vote (paper Fig. 4).
4. The two top-voted distinct 256-bit values are concatenated into a
   512-bit master key candidate and written to `master_keys.txt` in the
   `descriptor:part1:part2` format consumed by
   [`fbe_forensic_toolkit`](../fbe_forensic_toolkit).

Only two file keys derived from the same master key need to still be
present in RAM for this to work, which is why the paper calls it robust
against the partial memory loss typical of a cold boot attack.

## Setup

```bash
pip install -r requirements.txt

# Build aeskeyfind separately (GPL, not vendored here):
git clone https://github.com/makomk/aeskeyfind
cd aeskeyfind && make
```

`aeskeyfind_runner.py` invokes it as `aeskeyfind -q <dump>` (no `-v`), and
parses its exact stdout format from the upstream source (`print_key()` in
`aeskeyfind.c`): one bare hex string per found key candidate, no labels
— 64 hex chars for a 256-bit candidate, 32 for a 128-bit one (ignored).

## Usage

Run from the `package/` root (so the `fbe_common` package resolves):

```bash
python3 -m fbekeyrecover.fbekeyrecover \
    --memory dump1.lime dump2.lime \
    --userdata userdata.img \
    --aeskeyfind ./aeskeyfind/aeskeyfind \
    --out master_keys.txt
```

Pass multiple `--memory` files if your capture tooling split a large dump
(the paper does this to work around an `aeskeyfind` crash on very large
images).

## Limitation

This only recovers keys derived with the *old* KDF. The paper found a
second KDF (Listing 2) used when `AES-256-HEH` is the filenames encryption
mode; this tool detects and skips those descriptors automatically (see
`group_nonces_by_descriptor`), printing a warning instead of a wrong
answer.
