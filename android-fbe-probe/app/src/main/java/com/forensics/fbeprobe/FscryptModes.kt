package com.forensics.fbeprobe

/**
 * fscrypt content/filenames encryption mode constants, as named in the
 * paper (Section 4.1) and the Android kernel's fs/crypto headers.
 */
object FscryptModes {
    const val INVALID = 0
    const val AES_256_XTS = 1
    const val AES_256_GCM = 2
    const val AES_256_CBC = 3
    const val AES_256_CTS = 4
    const val AES_256_HEH = 126
    const val PRIVATE = 127

    fun name(mode: Int): String = when (mode) {
        INVALID -> "invalid"
        AES_256_XTS -> "AES-256-XTS"
        AES_256_GCM -> "AES-256-GCM"
        AES_256_CBC -> "AES-256-CBC"
        AES_256_CTS -> "AES-256-CTS (CBC-CTS)"
        AES_256_HEH -> "AES-256-HEH"
        PRIVATE -> "private (hardware-wrapped)"
        else -> "unknown ($mode)"
    }

    /**
     * Per the paper (Sections 3.2 and 7): devices whose filenames
     * encryption mode is AES-256-HEH use a second, newer KDF
     * (Listing 2) that this attack does not break. Every other mode
     * indicates the original, vulnerable KDF (Listing 1).
     */
    fun usesOldVulnerableKdf(filenamesMode: Int): Boolean =
        filenamesMode != AES_256_HEH && filenamesMode != INVALID
}
