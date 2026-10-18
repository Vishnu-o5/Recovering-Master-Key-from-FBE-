"""
Minimal, dependency-free EXT4 reader whose only job is to recover the
fscrypt encryption context (key descriptor, nonce, content/filename
encryption mode) stored as an extended attribute on every encrypted
inode.

This deliberately does NOT implement directory traversal, extent trees,
or file content extraction -- that's all The Sleuth Kit's job, and the
paper's actual TSK patch. All the key-recovery attack (Section 3.2) needs
is: for every encrypted inode, its key descriptor and nonce. Scanning the
raw inode table directly for inodes carrying a valid fscrypt xattr is
sufficient for that and is far simpler than reimplementing TSK.

References (public, stable on-disk formats):
  - https://www.kernel.org/doc/html/latest/filesystems/ext4/globals.html
  - https://www.kernel.org/doc/html/latest/filesystems/ext4/attributes.html
  - https://www.kernel.org/doc/html/latest/filesystems/fscrypt.html
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator, Optional

EXT4_SUPERBLOCK_OFFSET = 1024
EXT4_MAGIC = 0xEF53

EXT4_XATTR_MAGIC = 0xEA020000
EXT4_XATTR_INDEX_ENCRYPTION = 9  # paper: EXT2_EA_IDX_ENCRYPTION

# fscrypt_context_v1 payload layout (28 bytes), see kernel fs/crypto/policy.c:
#   u8 version; u8 contents_mode; u8 filenames_mode; u8 flags;
#   u8 master_key_descriptor[8]; u8 nonce[16];
FSCRYPT_CONTEXT_V1_SIZE = 1 + 1 + 1 + 1 + 8 + 16
FSCRYPT_CONTEXT_V1_FORMAT = "<BBBB8s16s"

# fscrypt content/filename mode constants, as named in the paper (Section 4.1).
MODE_NAMES = {
    0: "invalid",
    1: "AES-256-XTS",
    2: "AES-256-GCM",
    3: "AES-256-CBC",
    4: "AES-256-CTS",
    126: "AES-256-HEH",
    127: "private",
}
MODE_AES_256_HEH = 126  # indicates the new KDF; our attack does not apply


@dataclass
class EncryptionContext:
    inode: int
    version: int
    contents_mode: int
    filenames_mode: int
    flags: int
    key_descriptor: bytes  # 8 bytes
    nonce: bytes  # 16 bytes

    @property
    def key_descriptor_hex(self) -> str:
        return self.key_descriptor.hex()

    @property
    def uses_new_kdf(self) -> bool:
        return self.filenames_mode == MODE_AES_256_HEH

    def __repr__(self) -> str:
        return (
            f"EncryptionContext(inode={self.inode}, "
            f"contents={MODE_NAMES.get(self.contents_mode, self.contents_mode)}, "
            f"filenames={MODE_NAMES.get(self.filenames_mode, self.filenames_mode)}, "
            f"descriptor={self.key_descriptor_hex}, nonce={self.nonce.hex()})"
        )


class Ext4InodeScanner:
    def __init__(self, path: str):
        self._path = path
        self._fh: BinaryIO = open(path, "rb")
        self._read_superblock()
        self._read_group_descriptors()

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> "Ext4InodeScanner":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---- superblock / group descriptors -----------------------------------

    def _read_superblock(self) -> None:
        self._fh.seek(EXT4_SUPERBLOCK_OFFSET)
        sb = self._fh.read(1024)

        magic = struct.unpack_from("<H", sb, 56)[0]
        if magic != EXT4_MAGIC:
            raise ValueError(
                f"{self._path}: not an EXT4 image (bad superblock magic "
                f"0x{magic:04x}, expected 0x{EXT4_MAGIC:04x})"
            )

        self.inodes_count = struct.unpack_from("<I", sb, 0)[0]
        log_block_size = struct.unpack_from("<I", sb, 24)[0]
        self.block_size = 1024 << log_block_size
        self.blocks_per_group = struct.unpack_from("<I", sb, 32)[0]
        self.inodes_per_group = struct.unpack_from("<I", sb, 40)[0]

        inode_size = struct.unpack_from("<H", sb, 88)[0]
        self.inode_size = inode_size if inode_size else 128

        feature_incompat = struct.unpack_from("<I", sb, 96)[0]
        self._is_64bit = bool(feature_incompat & 0x80)  # INCOMPAT_64BIT

        desc_size = struct.unpack_from("<H", sb, 254)[0] if len(sb) >= 256 else 0
        self.group_desc_size = desc_size if self._is_64bit and desc_size else 32

        self.groups_count = (
            self.inodes_count + self.inodes_per_group - 1
        ) // self.inodes_per_group

        # The superblock always starts at byte offset 1024. When
        # block_size == 1024, that's the start of block 1 (block 0 is
        # reserved/boot block), so the group descriptor table starts at
        # block 2. For any larger block size, byte 1024 falls inside
        # block 0, and the GDT starts at block 1.
        self._gdt_start_block = 2 if self.block_size == 1024 else 1

    def _read_group_descriptors(self) -> None:
        self._fh.seek(self._gdt_start_block * self.block_size)
        raw = self._fh.read(self.groups_count * self.group_desc_size)

        self._inode_table_block = []
        for i in range(self.groups_count):
            off = i * self.group_desc_size
            lo = struct.unpack_from("<I", raw, off + 8)[0]
            hi = 0
            if self.group_desc_size >= 32 + 8:
                hi = struct.unpack_from("<I", raw, off + 0x28)[0]
            self._inode_table_block.append(lo | (hi << 32))

    # ---- inode access -------------------------------------------------------

    def _raw_inode(self, inode_num: int) -> bytes:
        """inode_num is 1-based, as on disk."""
        idx = inode_num - 1
        group = idx // self.inodes_per_group
        index_in_group = idx % self.inodes_per_group

        table_block = self._inode_table_block[group]
        offset = table_block * self.block_size + index_in_group * self.inode_size

        self._fh.seek(offset)
        return self._fh.read(self.inode_size)

    def get_encryption_context(self, inode_num: int) -> Optional[EncryptionContext]:
        raw = self._raw_inode(inode_num)
        if len(raw) < 132:
            return None

        i_flags = struct.unpack_from("<I", raw, 32)[0]
        i_file_acl_lo = struct.unpack_from("<I", raw, 104)[0]
        i_file_acl_hi = struct.unpack_from("<H", raw, 118)[0] if len(raw) >= 120 else 0
        file_acl_block = i_file_acl_lo | (i_file_acl_hi << 32)

        ctx = None

        # Internal (in-inode) extended attributes.
        if self.inode_size > 128 and len(raw) >= 132:
            extra_isize = struct.unpack_from("<H", raw, 128)[0]
            header_off = 128 + extra_isize
            if 0 < extra_isize and header_off + 4 <= len(raw):
                magic = struct.unpack_from("<I", raw, header_off)[0]
                if magic == EXT4_XATTR_MAGIC:
                    entries_start = header_off + 4
                    ctx = self._scan_xattr_entries(
                        raw, entries_start, len(raw), value_base=header_off
                    )

        # External (separate block) extended attributes.
        if ctx is None and file_acl_block:
            block = self._read_block(file_acl_block)
            if len(block) >= 32:
                magic = struct.unpack_from("<I", block, 0)[0]
                if magic == EXT4_XATTR_MAGIC:
                    ctx = self._scan_xattr_entries(
                        block, 32, len(block), value_base=0
                    )

        if ctx is None:
            return None

        version, contents_mode, filenames_mode, flags, descriptor, nonce = ctx
        return EncryptionContext(
            inode=inode_num,
            version=version,
            contents_mode=contents_mode,
            filenames_mode=filenames_mode,
            flags=flags,
            key_descriptor=descriptor,
            nonce=nonce,
        )

    def _read_block(self, block_num: int) -> bytes:
        self._fh.seek(block_num * self.block_size)
        return self._fh.read(self.block_size)

    @staticmethod
    def _scan_xattr_entries(buf: bytes, start: int, end: int, value_base: int):
        """Walk ext4_xattr_entry records in buf[start:end], looking for the
        encryption attribute (name_index == 9). Returns the parsed
        fscrypt_context_v1 tuple, or None if not found."""
        pos = start
        while pos + 16 <= end:
            name_len = buf[pos]
            name_index = buf[pos + 1]
            if name_len == 0 and name_index == 0:
                break  # terminator entry

            value_offs = struct.unpack_from("<H", buf, pos + 2)[0]
            value_size = struct.unpack_from("<I", buf, pos + 8)[0]

            if name_index == EXT4_XATTR_INDEX_ENCRYPTION and value_size == FSCRYPT_CONTEXT_V1_SIZE:
                value_off = value_base + value_offs
                if value_off + FSCRYPT_CONTEXT_V1_SIZE <= len(buf):
                    payload = buf[value_off : value_off + FSCRYPT_CONTEXT_V1_SIZE]
                    return struct.unpack(FSCRYPT_CONTEXT_V1_FORMAT, payload)

            # advance to next entry: fixed 16-byte header + name, padded to 4 bytes
            entry_len = 16 + ((name_len + 3) & ~3)
            pos += entry_len
        return None

    def scan_all_inodes(self) -> Iterator[EncryptionContext]:
        """Yields an EncryptionContext for every inode on the filesystem
        that carries a valid fscrypt encryption attribute. Unencrypted or
        unallocated inodes are skipped (their xattr area won't carry the
        magic + a plausible 28-byte encryption value)."""
        # Inode 0 doesn't exist; EXT4 reserves inodes 1-10 for internal use,
        # but scanning from 1 is cheap and harmless.
        for inode_num in range(1, self.inodes_count + 1):
            try:
                ctx = self.get_encryption_context(inode_num)
            except (struct.error, OSError):
                continue
            if ctx is not None:
                yield ctx
