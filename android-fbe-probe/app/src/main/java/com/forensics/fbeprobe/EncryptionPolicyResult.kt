package com.forensics.fbeprobe

/**
 * Mirrors either struct fscrypt_policy_v1 or fscrypt_policy_v2 (whichever
 * the kernel actually reports), plus the errno from the open()/ioctl()
 * calls (0 if a policy was successfully read). Constructed from native
 * code: see fbe_probe.cpp's JNI signature "(IIIII[B)V" -- keep these in
 * sync.
 *
 * [policyVersion]: 0 = no policy found / call failed, 1 = legacy
 * fscrypt_policy_v1 (8-byte master key descriptor -- what the paper's
 * attack targets), 2 = fscrypt_policy_v2 (16-byte master key
 * *identifier* -- not a descriptor, not vulnerable to this attack).
 * [keyBytes] is 8 bytes for v1, 16 bytes for v2.
 */
data class EncryptionPolicyResult(
    val errno: Int,
    val policyVersion: Int,
    val contentsEncryptionMode: Int,
    val filenamesEncryptionMode: Int,
    val flags: Int,
    val keyBytes: ByteArray
) {
    val succeeded: Boolean get() = errno == 0 && policyVersion != 0

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is EncryptionPolicyResult) return false
        return errno == other.errno &&
            policyVersion == other.policyVersion &&
            contentsEncryptionMode == other.contentsEncryptionMode &&
            filenamesEncryptionMode == other.filenamesEncryptionMode &&
            flags == other.flags &&
            keyBytes.contentEquals(other.keyBytes)
    }

    override fun hashCode(): Int {
        var result = errno
        result = 31 * result + policyVersion
        result = 31 * result + contentsEncryptionMode
        result = 31 * result + filenamesEncryptionMode
        result = 31 * result + flags
        result = 31 * result + keyBytes.contentHashCode()
        return result
    }
}
