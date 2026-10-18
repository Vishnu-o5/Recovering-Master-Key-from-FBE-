# FBE Master Key Recovery — Reproduction

Reproduction of the techniques from:

> T. Groß, M. Busch, T. Müller, **"One key to rule them all: Recovering the master
> key from RAM to break Android's file-based encryption,"** Forensic Science
> International: Digital Investigation 36 (2021) 301113.

The paper's attack: Android's File-Based Encryption (FBE) derives a per-file
256/512-bit data encryption key (`DEKf`) from a master key (`MK`) and a
per-file nonce, using `AES-ECB` with the **nonce as the encryption key** and
the **master key as the data being "encrypted"** (see `fs/crypto/keyinfo.c`,
`derive_key_aes`). Because AES is a permutation, this is trivially invertible:
if you can find `DEKf` fragments in a RAM dump (they get expanded into AES
key schedules by the kernel crypto API, which tools like `aeskeyfind` can
locate) and you know the matching file's nonce (stored, unencrypted, as an
EXT4 extended attribute), you can recover `MK` directly — no brute force
needed. The paper calls this a flaw in the KDF, since it uses non-secret data
(the nonce) as a key.

## Legal / ethical note

This is coursework reproducing a published, peer-reviewed forensic technique.
Only run these tools against devices, images, and memory dumps you own or are
explicitly authorized to analyze (e.g. your own test device, an Android
Virtual Device, or lab-provided evidence images). Recovering encryption keys
from a device you don't own or lack authorization for is illegal in most
jurisdictions.

## Layout — paper section → component

| Paper section | What it describes | Component here |
|---|---|---|
| §3.2, §4.2 | `fbekeyrecover`: find `DEKf` fragments in RAM with `aeskeyfind`, pair with nonces from the filesystem, vote on the most likely master key | [`fbekeyrecover/`](fbekeyrecover/) |
| §4.1 (TSK extension) | Decrypt filenames/content given a recovered master key | [`fbe_forensic_toolkit/`](fbe_forensic_toolkit/) (`fbe_crypto.py`, `decrypt_tool.py`) |
| §4.3 (Plaso extension) | Feed decrypted FBE files into timeline reconstruction | [`fbe_forensic_toolkit/plaso_notes.md`](fbe_forensic_toolkit/plaso_notes.md) |
| §5 (Table 2 evaluation methodology) | On-device probe reporting content/filename encryption mode via `ioctl(FS_IOC_GET_ENCRYPTION_POLICY)`, to decide if a device is vulnerable | [`android-fbe-probe/`](android-fbe-probe/) (Android Studio project) |

Shared EXT4 parsing code (reading the on-disk extended attribute that stores
each file's nonce/key-descriptor/encryption mode) lives in
[`fbe_common/ext4_inode_scanner.py`](fbe_common/ext4_inode_scanner.py) and is
used by both `fbekeyrecover` and `fbe_forensic_toolkit`. It's a pure-Python,
dependency-free EXT4 reader — not a fork of The Sleuth Kit — since actually
forking and rebuilding TSK's C codebase isn't practical as a course project,
but the EXT4 extended-attribute layout it reads is identical either way.

## Quick start

```bash
# 1. Probe a device's encryption scheme (Android Studio project)
#    -> open android-fbe-probe/ in Android Studio, run on a device/emulator.

# 2. Recover a master key from a RAM dump + userdata image
cd "package"
python3 -m fbekeyrecover.fbekeyrecover \
    --memory ram_dump1.lime ram_dump2.lime \
    --userdata userdata.img \
    --aeskeyfind /path/to/aeskeyfind \
    --out master_keys.txt

# 3. Use the recovered key(s) to decrypt a filename or file content
python3 -m fbe_forensic_toolkit.decrypt_tool \
    --userdata userdata.img \
    --master-keys master_keys.txt \
    --inode 131099 \
    --mode filename --ciphertext-hex <bytes from a directory entry>
```

See each component's own README for details.
