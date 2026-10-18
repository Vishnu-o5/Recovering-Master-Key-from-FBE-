package com.forensics.fbeprobe

object NativeProbe {
    init {
        System.loadLibrary("fbeprobe")
    }

    /**
     * Queries the fscrypt encryption policy of [path] (a file or
     * directory the calling app owns) via
     * ioctl(FS_IOC_GET_ENCRYPTION_POLICY). No special permission is
     * required to probe your own app's own files.
     */
    external fun getEncryptionPolicy(path: String): EncryptionPolicyResult
}
