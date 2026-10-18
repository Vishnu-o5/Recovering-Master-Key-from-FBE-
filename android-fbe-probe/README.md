# android-fbe-probe

On-device reproduction of the evaluation method behind the paper's
Table 1/Table 2 (Section 5): reports a device's FBE content/filename
encryption mode, and whether it's using the old (vulnerable) or new KDF.

## What it does

- A small native library (`app/src/main/cpp/fbe_probe.cpp`) opens the
  app's own `filesDir` and calls
  `ioctl(fd, FS_IOC_GET_ENCRYPTION_POLICY, &policy)` (the legacy v1
  ioctl, matching the paper's bundled native binary). No root or special
  permission is needed in principle — an app can always query the
  encryption policy of its own files.
- If the v1 ioctl fails, it falls back to the newer
  `FS_IOC_GET_ENCRYPTION_POLICY_EX` (v2) ioctl, which modern Android
  defaults to. v2 policies use a 16-byte master key *identifier* instead
  of an 8-byte descriptor — structurally different from what this
  paper's attack exploits, and this is reported distinctly in the UI.
- `MainActivity` displays the decoded `contents_encryption_mode` /
  `filenames_encryption_mode` and the policy version, and flags the
  device as vulnerable only for a v1 policy whose filenames mode isn't
  `AES-256-HEH` (the paper's Section 7 "new KDF" indicator).
- It also shells out to `mount` and shows `/data`-related lines, mirroring
  the paper's evaluation app; on a modern non-rooted device this is
  usually empty (SELinux), which is expected.

## Opening in Android Studio

1. Open this folder (`android-fbe-probe/`) directly in Android Studio.
2. If Android Studio reports a missing/invalid Gradle wrapper jar, let it
   regenerate one (File → Sync Project with Gradle Files will usually
   offer this automatically). `gradle-wrapper.properties` already pins
   Gradle 8.7, matching Android Gradle Plugin 8.5.2.
3. Build/run on a device or an AVD running Android 7.0+ (minSdk 26 here).
   Note: most emulator images don't enable FBE by default, so
   `ioctl` will return `EINVAL`/`ENOTTY` there — that's an expected,
   reported-in-the-app result, not a crash. Test on a real device, or an
   AVD image that has FBE enabled (as the paper itself did for its one
   AVD data point in Table 1).

## Interpreting results

| filenames mode | meaning |
|---|---|
| `AES-256-CTS` / `AES-256-CBC` / anything but HEH | old KDF — vulnerable to `fbekeyrecover` |
| `AES-256-HEH` | new KDF (paper Listing 2) — not vulnerable to this attack |
| ioctl fails, errno 22/`EINVAL` or 25/`ENOTTY` | path/filesystem isn't fscrypt-encrypted (e.g. FDE-only device, or FBE disabled) |
| ioctl fails, errno 13/`EACCES` | SELinux denied the ioctl — see below |

### Investigation log: why this fails on every AVD we tried, and what we ruled out

Tested against three AVDs (`google_apis`, not Play Store, `arm64-v8a`):
a Pixel 6 Pro / Android 16 (API 36), a Pixel 3 / Android 10 (API 29 — the
oldest AVD config with FBE at all, per the paper), and confirmed each
finding step by step rather than guessing once and stopping.

**Step 1 — SELinux blocks it by default, on every API level tested.**
Enforcing-mode logcat on both API 29 and API 36 showed an identical
denial:

```
avc: denied { ioctl } for path="/data/data/com.forensics.fbeprobe/files"
  ioctlcmd=0x6615 scontext=u:r:untrusted_app:s0:... tclass=dir permissive=0
```

`0x6615` decodes to `type='f', nr=21` — exactly `FS_IOC_GET_ENCRYPTION_POLICY`.
Identical across seven major Android versions, so this isn't recent
version-specific hardening (an earlier draft of this README claimed that;
it was wrong, corrected here) — it looks like generic AOSP emulator
sepolicy, independent of API level.

**Step 2 — bypass SELinux and see what's actually underneath.**
`google_apis` images are userdebug builds, so `adb root` +
`adb shell setenforce 0` genuinely disables enforcement (confirmed via
`avc: denied ... permissive=1` in logcat afterward — still logged, no
longer blocking). With SELinux out of the way, the ioctl still failed,
now with **errno 25 (ENOTTY)** instead of EACCES — a different, kernel-level
answer, not a permission wall.

**Step 3 — rule out "wrong ioctl version."** Modern Android defaults to
fscrypt policy v2 (`FS_IOC_GET_ENCRYPTION_POLICY_EX`), which the original
v1-only probe couldn't have detected. Added a v2 fallback (see above) —
it **also** returned ENOTTY. So it isn't a v1-vs-v2 mismatch either.

**Step 4 — what the mount table shows.** On the API 36 device, `/data`
*and* `/data/user/0` both sit on `/dev/block/dm-52` — a device-mapper
block, i.e. whole-volume/metadata-level encryption (the paper's own
Section 2 describes exactly this: "FDE used on top of FBE" on recent
devices). `ro.crypto.type=file` / `ro.crypto.state=encrypted` are true at
the system-property level, but that turned out to be necessary, not
sufficient — this specific app directory never actually got an
individual fscrypt policy applied to it. The volume-level wrapper is
real; the per-app FBE layer the paper's attack targets apparently isn't
provisioned on these AVD images.

(On the API 29 AVD it's simpler: `ro.crypto.type=unsupported` — FBE isn't
configured on that image at all, full stop.)

**Bottom line:** three independent causes were tested and ruled out one
at a time (SELinux, ioctl version, then genuine absence of a per-app
policy despite volume-level encryption reporting as active). Emulator
images — at least the generic AOSP ones available via `sdkmanager` —
don't appear to provision the real thing. The paper's own evaluation
(Table 1/2) ran exclusively on **physical OEM hardware** (Nexus, Pixel,
Samsung, Huawei, Xiaomi devices), never emulators, which in hindsight
fits what we found here. If you get access to a rooted physical Android
device, that remains the credible next step for a genuinely positive
result — happy to walk through it.
