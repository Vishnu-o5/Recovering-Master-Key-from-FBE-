# Plaso extension (paper Section 4.3) — what's reproduced here, and what isn't

The paper's Plaso/dfVFS patch doesn't do any cryptography of its own. Its
whole job is **plumbing**: let a master key reach the point in `dfVFS`
where `pytsk3` opens the EXT4 filesystem (`TSKFileSystem._open`), so that
TSK's (patched) `FS_Info` object can decrypt filenames and content
transparently as Plaso's existing parsers walk the image. Once that's
wired up, Plaso's SQLite/log/browser-history parsers work completely
unmodified — they just see decrypted bytes.

Actually forking and rebuilding Plaso + dfVFS + pytsk3 (three separate
upstream C/Python projects) isn't practical as a course project, and
doing so wouldn't teach you anything beyond plumbing. What's reproduced
instead, in [`fbe_crypto.py`](fbe_crypto.py) and
[`decrypt_tool.py`](decrypt_tool.py), is the cryptographic core the
plumbing exists to serve: deriving a per-file key and decrypting a
filename or content block given a recovered master key.

If you do want to wire this into a real Plaso run, the integration point
is exactly where the paper put it:

1. In `dfvfs/vfs/tsk_file_system.py`, `TSKFileSystem._open()` calls
   `pytsk3.FS_Info(img_info)`. After that call, iterate every inode,
   call `scanner.get_encryption_context(inode)` (this repo's
   `fbe_common.ext4_inode_scanner`), and cache `(descriptor -> nonce)`
   per inode somewhere `TSKFileEntry` can reach it.
2. In `dfvfs/vfs/tsk_file_entry.py`, wherever file content or a directory
   entry's name is read, call `derive_file_key` + `decrypt_file_content`
   / `decrypt_filename` before handing bytes back to Plaso's parser layer.
3. Add a `credential` type (the paper calls theirs `ext4_master`) to
   Plaso's `CredentialConfiguration` so `log2timeline --credential
   ext4_master:<descriptor>,<part1>,<part2>` can supply the master key(s)
   produced by `fbekeyrecover`.

None of that requires patching TSK's C code the way the paper did (TSK's
own `istat`/`fls`/`icat` binaries only need decryption built in if you
want to use *those specific CLI tools* against an encrypted image) — a
Python-level dfVFS shim calling into this repo's `fbe_crypto` module is
enough to unblock Plaso.
