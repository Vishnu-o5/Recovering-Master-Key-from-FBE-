"""
Byte-level unit test for Ext4InodeScanner: hand-builds a minimal,
synthetic EXT4 image (superblock + one group descriptor + one inode
carrying an inline fscrypt xattr) and checks the parser recovers exactly
the encryption context we wrote in.

Real mkfs.ext4 + e4crypt tooling needs a Linux kernel (not available on
macOS), so this hand-built image is how the on-disk struct offsets in
ext4_inode_scanner.py are verified without one.

Run with: python3 -m fbe_common.test_ext4_inode_scanner
"""
from __future__ import annotations

import os
import struct
import tempfile

from fbe_common.ext4_inode_scanner import (
    EXT4_XATTR_INDEX_ENCRYPTION,
    EXT4_XATTR_MAGIC,
    Ext4InodeScanner,
)

BLOCK_SIZE = 4096
INODE_SIZE = 256
INODES_PER_GROUP = 8
BLOCKS_PER_GROUP = 64
INODES_COUNT = 8
INODE_TABLE_BLOCK = 5  # arbitrary, just needs to be past sb+gdt+bitmaps


def build_superblock() -> bytes:
    sb = bytearray(1024)
    struct.pack_into("<I", sb, 0, INODES_COUNT)
    struct.pack_into("<I", sb, 24, 2)  # log_block_size: 1024 << 2 = 4096
    struct.pack_into("<I", sb, 32, BLOCKS_PER_GROUP)
    struct.pack_into("<I", sb, 40, INODES_PER_GROUP)
    struct.pack_into("<H", sb, 56, 0xEF53)  # magic
    struct.pack_into("<H", sb, 88, INODE_SIZE)
    struct.pack_into("<I", sb, 96, 0)  # feature_incompat: no 64bit flag
    return bytes(sb)


def build_group_descriptor() -> bytes:
    gd = bytearray(32)
    struct.pack_into("<I", gd, 8, INODE_TABLE_BLOCK)  # bg_inode_table_lo
    return bytes(gd)


def build_inode_with_encryption_xattr(
    contents_mode: int, filenames_mode: int, key_descriptor: bytes, nonce: bytes
) -> bytes:
    inode = bytearray(INODE_SIZE)
    struct.pack_into("<H", inode, 0, 0x8180)  # i_mode: regular file, rw-------
    extra_isize = 32
    struct.pack_into("<H", inode, 128, extra_isize)

    header_off = 128 + extra_isize
    struct.pack_into("<I", inode, header_off, EXT4_XATTR_MAGIC)

    entries_off = header_off + 4
    name = b""  # name_len = 0 is fine; only e_name_index matters for our lookup
    name_len = len(name)
    value = struct.pack("<BBB B 8s 16s", 1, contents_mode, filenames_mode, 0, key_descriptor, nonce)
    assert len(value) == 28

    value_area_start = entries_off + 16 + ((name_len + 3) & ~3) + 16  # leave room for terminator entry
    struct.pack_into(
        "<BBHIII",
        inode,
        entries_off,
        name_len,
        EXT4_XATTR_INDEX_ENCRYPTION,
        value_area_start - header_off,  # e_value_offs, relative to header start
        0,  # e_value_block
        len(value),  # e_value_size
        0,  # e_hash
    )
    inode[value_area_start - header_off + header_off : value_area_start - header_off + header_off + len(value)] = value
    # (terminator entry left as zero bytes, already the case for a fresh bytearray)
    return bytes(inode)


def main() -> None:
    key_descriptor = bytes.fromhex("0102030405060708")
    nonce = bytes.fromhex("0a0b0c0d0e0f101112131415161718191a1b1c")[:16]
    contents_mode = 1  # AES-256-XTS
    filenames_mode = 4  # AES-256-CTS

    image = bytearray(INODE_TABLE_BLOCK * BLOCK_SIZE + INODES_PER_GROUP * INODE_SIZE)
    image[1024 : 1024 + 1024] = build_superblock()
    image[BLOCK_SIZE : BLOCK_SIZE + 32] = build_group_descriptor()

    target_inode_num = 3
    inode_bytes = build_inode_with_encryption_xattr(contents_mode, filenames_mode, key_descriptor, nonce)
    offset = INODE_TABLE_BLOCK * BLOCK_SIZE + (target_inode_num - 1) * INODE_SIZE
    image[offset : offset + INODE_SIZE] = inode_bytes

    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(image)
        path = f.name

    try:
        with Ext4InodeScanner(path) as scanner:
            assert scanner.block_size == BLOCK_SIZE
            assert scanner.inode_size == INODE_SIZE

            ctx = scanner.get_encryption_context(target_inode_num)
            assert ctx is not None, "expected an encryption context, got None"
            assert ctx.key_descriptor == key_descriptor, ctx.key_descriptor.hex()
            assert ctx.nonce == nonce, ctx.nonce.hex()
            assert ctx.contents_mode == contents_mode
            assert ctx.filenames_mode == filenames_mode
            assert not ctx.uses_new_kdf

            other_inode = scanner.get_encryption_context(target_inode_num + 1)
            assert other_inode is None, "unencrypted inode should yield no context"

            found = list(scanner.scan_all_inodes())
            assert len(found) == 1 and found[0].inode == target_inode_num

        print("ext4_inode_scanner self-test: OK")
        print(f"  parsed: {ctx!r}")
    finally:
        os.unlink(path)


if __name__ == "__main__":
    main()
