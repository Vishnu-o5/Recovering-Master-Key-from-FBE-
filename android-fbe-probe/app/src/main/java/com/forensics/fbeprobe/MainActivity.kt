package com.forensics.fbeprobe

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.forensics.fbeprobe.databinding.ActivityMainBinding
import java.io.BufferedReader
import java.io.InputStreamReader

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.runProbeButton.setOnClickListener { runProbe() }
    }

    private fun runProbe() {
        val report = StringBuilder()

        val targetPath = filesDir.absolutePath
        report.appendLine("Probing: $targetPath")
        report.appendLine()

        val policy = NativeProbe.getEncryptionPolicy(targetPath)
        if (!policy.succeeded) {
            report.appendLine("ioctl(FS_IOC_GET_ENCRYPTION_POLICY[_EX]) failed, errno=${policy.errno}")
            report.appendLine(
                when (policy.errno) {
                    13 -> "(errno 13/EACCES: SELinux denied this ioctl to the " +
                        "untrusted_app domain -- check logcat for an \"avc: denied { ioctl }\" " +
                        "line. Seen on google_apis AVD images across multiple API levels (29 " +
                        "and 36 both), so this looks like generic AOSP emulator sepolicy, not " +
                        "something version-specific -- try `adb root` + `adb shell setenforce 0` " +
                        "to rule SELinux out, or test on a rooted physical device.)"
                    22, 25 -> "(errno 22/EINVAL or 25/ENOTTY, with the v2 fallback also failing: " +
                        "this specific directory has no fscrypt policy applied to it. Note " +
                        "`ro.crypto.type=file` is NOT sufficient evidence this directory is " +
                        "covered -- on AVDs we've seen /data sit on a dm-* device (volume/" +
                        "metadata-level encryption) while the per-app directory itself was " +
                        "never individually provisioned with its own FBE policy. Confirmed with " +
                        "`adb root` + `setenforce 0` (rules out SELinux) and checking " +
                        "`avc: denied ... permissive=1` in logcat (proves the ioctl reached the " +
                        "kernel and genuinely got ENOTTY, not a blocked call).)"
                    else -> "(see errno(3) for what errno ${policy.errno} means on this device.)"
                }
            )
        } else {
            val contentsName = FscryptModes.name(policy.contentsEncryptionMode)
            val filenamesName = FscryptModes.name(policy.filenamesEncryptionMode)

            report.appendLine("Policy version: fscrypt v${policy.policyVersion}")
            report.appendLine("Contents encryption mode:  $contentsName (${policy.contentsEncryptionMode})")
            report.appendLine("Filenames encryption mode: $filenamesName (${policy.filenamesEncryptionMode})")
            report.appendLine("Flags: 0x${Integer.toHexString(policy.flags)}")
            report.appendLine(
                if (policy.policyVersion == 1) "Key descriptor: ${policy.keyBytes.toHex()}"
                else "Key identifier: ${policy.keyBytes.toHex()}"
            )
            report.appendLine()

            val oldKdf = policy.policyVersion == 1 &&
                FscryptModes.usesOldVulnerableKdf(policy.filenamesEncryptionMode)
            report.appendLine(
                when {
                    policy.policyVersion == 2 ->
                        "-> fscrypt policy v2: this device uses a 16-byte master key " +
                            "*identifier*, not an 8-byte descriptor -- structurally different " +
                            "from what the paper's KDF flaw exploits (paper Section 7 " +
                            "anticipated this as the \"new KDF\"; v2 is its actual on-disk " +
                            "policy format on modern Android). fbekeyrecover does not apply here."
                    oldKdf ->
                        "-> Old KDF in use: VULNERABLE to the master-key-recovery attack (paper Section 3.2)."
                    else ->
                        "-> AES-256-HEH filenames mode detected: this device uses the NEW KDF " +
                            "(paper Listing 2) -- fbekeyrecover does not apply."
                }
            )
        }

        report.appendLine()
        report.appendLine("--- mount (filtered to /data) ---")
        report.appendLine(runMountCommand())

        binding.outputText.text = report.toString()
    }

    /**
     * Mirrors the other half of the paper's Section 5 evaluation app,
     * which also inspected `mount` output. On modern, non-rooted devices
     * this is commonly empty/restricted by SELinux -- that's expected
     * and matches what the paper notes about platform security
     * restricting this kind of inspection on fully patched devices.
     */
    private fun runMountCommand(): String {
        return try {
            val process = ProcessBuilder("mount").redirectErrorStream(true).start()
            val lines = BufferedReader(InputStreamReader(process.inputStream)).readLines()
            process.waitFor()
            val relevant = lines.filter { it.contains("/data") }
            if (relevant.isEmpty()) "(no /data lines returned -- likely blocked by SELinux)"
            else relevant.joinToString("\n")
        } catch (e: Exception) {
            "(failed to run mount: ${e.message})"
        }
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
