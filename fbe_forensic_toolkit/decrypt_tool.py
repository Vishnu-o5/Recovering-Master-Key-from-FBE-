"""
decrypt_tool -- CLI reproduction of the paper's extended `icat`/`ifind`
(Section 4.1): given recovered master keys (from `fbekeyrecover`) and an
inode on the userdata image, derive that inode's file key and decrypt
either its filename ciphertext or its content.

Usage:
    # Decrypt a filename ciphertext (e.g. pulled from a directory entry
    # with a plain, non-decrypting EXT4 tool, or by hand from the image):
    python3 -m fbe_forensic_toolkit.decrypt_tool \
        --userdata userdata.img --master-keys master_keys.txt \
        --inode 131099 --mode filename \
        --ciphertext-hex 3f1a9c...  --real-length 12

    # Decrypt a file's content, reading the ciphertext straight from the
    # image at a known byte offset (e.g. found via `blkcat`/`icat`):
    python3 -m fbe_forensic_toolkit.decrypt_tool \
        --userdata userdata.img --master-keys master_keys.txt \
        --inode 131100 --mode content \
        --content-offset 8257536 --content-length 4096
"""
from __future__ import annotations

import argparse
import sys
from typing import Dict, Tuple

from fbe_common.ext4_inode_scanner import Ext4InodeScanner
from fbe_forensic_toolkit.fbe_crypto import decrypt_file_content, decrypt_filename, derive_file_key


def load_master_keys(path: str) -> Dict[str, bytes]:
    """Reads the `descriptor:part1_hex:part2_hex` format written by
    fbekeyrecover (and consumed, per the paper, by TSK's `-K` argument)."""
    keys: Dict[str, bytes] = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            descriptor, part1, part2 = line.split(":")
            keys[descriptor] = bytes.fromhex(part1) + bytes.fromhex(part2)
    return keys


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--userdata", required=True)
    parser.add_argument("--master-keys", required=True)
    parser.add_argument("--inode", type=int, required=True)
    parser.add_argument("--mode", choices=["filename", "content"], required=True)
    parser.add_argument("--ciphertext-hex", help="required for --mode filename")
    parser.add_argument("--real-length", type=int, help="original filename length, if padded")
    parser.add_argument("--content-offset", type=int, help="byte offset of ciphertext, for --mode content")
    parser.add_argument("--content-length", type=int, help="byte length to read/decrypt, for --mode content")
    parser.add_argument("--block-size", type=int, default=4096)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)

    master_keys = load_master_keys(args.master_keys)
    if not master_keys:
        print("no master keys loaded", file=sys.stderr)
        return 1

    with Ext4InodeScanner(args.userdata) as scanner:
        ctx = scanner.get_encryption_context(args.inode)
        if ctx is None:
            print(f"inode {args.inode} has no fscrypt encryption context", file=sys.stderr)
            return 1

        mk = master_keys.get(ctx.key_descriptor_hex)
        if mk is None:
            print(
                f"no master key for descriptor {ctx.key_descriptor_hex} "
                f"(have: {', '.join(master_keys) or 'none'})",
                file=sys.stderr,
            )
            return 1

        dekf = derive_file_key(mk, ctx.nonce)
        print(f"inode {args.inode}: descriptor={ctx.key_descriptor_hex} DEKf={dekf.hex()}")

        if args.mode == "filename":
            if not args.ciphertext_hex:
                print("--ciphertext-hex is required for --mode filename", file=sys.stderr)
                return 1
            ciphertext = bytes.fromhex(args.ciphertext_hex)
            plaintext = decrypt_filename(dekf, ciphertext, args.real_length)
            print(f"decrypted filename: {plaintext!r}")
            return 0

        # --mode content
        if args.content_offset is None or args.content_length is None:
            print("--content-offset and --content-length are required for --mode content", file=sys.stderr)
            return 1
        with open(args.userdata, "rb") as f:
            f.seek(args.content_offset)
            ciphertext = f.read(args.content_length)
        plaintext = decrypt_file_content(dekf, ciphertext, block_size=args.block_size)
        sys.stdout.buffer.write(plaintext)
        return 0


if __name__ == "__main__":
    sys.exit(main())
