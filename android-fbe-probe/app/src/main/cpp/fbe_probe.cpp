// Native half of the paper's Section 5 evaluation method: "a bundled
// native binary [that] reads the encryption metadata of the own data
// folder with the help of an EXT4_IOC_GET_ENCRYPTION_POLICY request via
// ioctl." No root or special permission is needed -- an app can always
// query the encryption policy of its own files/directories.
//
// Tries the legacy v1 ioctl first (what the paper's attack targets: an
// 8-byte master key descriptor). If the kernel reports the inode's
// policy isn't v1 (ENOTTY/EINVAL from FS_IOC_GET_ENCRYPTION_POLICY),
// falls back to the newer v2 ioctl (FS_IOC_GET_ENCRYPTION_POLICY_EX) so
// we can empirically confirm *why* -- modern Android defaults to fscrypt
// policy v2, which uses a 16-byte key *identifier* instead of a master
// key descriptor, and isn't vulnerable to this paper's attack (Section 7
// already anticipated a "new KDF" that the old method can't touch; v2 is
// that KDF's actual on-disk policy format).
#include <jni.h>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define FSCRYPT_KEY_DESCRIPTOR_SIZE 8
#define FSCRYPT_KEY_IDENTIFIER_SIZE 16

// See include/uapi/linux/fscrypt.h in the Android kernel sources.
struct fscrypt_policy_v1 {
    uint8_t version;
    uint8_t contents_encryption_mode;
    uint8_t filenames_encryption_mode;
    uint8_t flags;
    uint8_t master_key_descriptor[FSCRYPT_KEY_DESCRIPTOR_SIZE];
};

struct fscrypt_policy_v2 {
    uint8_t version;
    uint8_t contents_encryption_mode;
    uint8_t filenames_encryption_mode;
    uint8_t flags;
    uint8_t log2_data_unit_size;
    uint8_t __reserved[3];
    uint8_t master_key_identifier[FSCRYPT_KEY_IDENTIFIER_SIZE];
};

struct fscrypt_get_policy_ex_arg {
    uint64_t policy_size; /* input/output */
    union {
        uint8_t version;
        struct fscrypt_policy_v1 v1;
        struct fscrypt_policy_v2 v2;
    } policy;
};

// _IOR('f', 21, struct fscrypt_policy_v1)
#define FS_IOC_GET_ENCRYPTION_POLICY _IOR('f', 21, struct fscrypt_policy_v1)
// _IOWR('f', 22, struct fscrypt_get_policy_ex_arg)
#define FS_IOC_GET_ENCRYPTION_POLICY_EX _IOWR('f', 22, struct fscrypt_get_policy_ex_arg)

extern "C" JNIEXPORT jobject JNICALL
Java_com_forensics_fbeprobe_NativeProbe_getEncryptionPolicy(
        JNIEnv *env, jobject /* thiz */, jstring pathJ) {
    const char *path = env->GetStringUTFChars(pathJ, nullptr);

    int policyVersion = 0; // 0 = unknown/none, 1 = v1, 2 = v2
    int contentsMode = 0, filenamesMode = 0, flags = 0;
    uint8_t keyBytes[FSCRYPT_KEY_IDENTIFIER_SIZE] = {0};
    int keyBytesLen = FSCRYPT_KEY_DESCRIPTOR_SIZE;
    int saved_errno = 0;
    int v1_errno = 0;

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        saved_errno = errno;
    } else {
        struct fscrypt_policy_v1 v1{};
        memset(&v1, 0, sizeof(v1));
        if (ioctl(fd, FS_IOC_GET_ENCRYPTION_POLICY, &v1) == 0) {
            policyVersion = 1;
            contentsMode = v1.contents_encryption_mode;
            filenamesMode = v1.filenames_encryption_mode;
            flags = v1.flags;
            keyBytesLen = FSCRYPT_KEY_DESCRIPTOR_SIZE;
            memcpy(keyBytes, v1.master_key_descriptor, FSCRYPT_KEY_DESCRIPTOR_SIZE);
        } else {
            v1_errno = errno;

            // Fall back to the v2 (_EX) ioctl to see if this inode has a
            // policy at all, just not one the legacy ioctl can represent.
            struct fscrypt_get_policy_ex_arg ex{};
            memset(&ex, 0, sizeof(ex));
            ex.policy_size = sizeof(ex.policy);
            if (ioctl(fd, FS_IOC_GET_ENCRYPTION_POLICY_EX, &ex) == 0 &&
                ex.policy.version == 2) {
                policyVersion = 2;
                contentsMode = ex.policy.v2.contents_encryption_mode;
                filenamesMode = ex.policy.v2.filenames_encryption_mode;
                flags = ex.policy.v2.flags;
                keyBytesLen = FSCRYPT_KEY_IDENTIFIER_SIZE;
                memcpy(keyBytes, ex.policy.v2.master_key_identifier, FSCRYPT_KEY_IDENTIFIER_SIZE);
                saved_errno = 0; // v2 succeeded; report that, not the v1 failure
            } else {
                // Neither worked -- report the original v1 errno, since
                // that's the ioctl the paper's method actually needs.
                saved_errno = v1_errno;
            }
        }
        close(fd);
    }

    env->ReleaseStringUTFChars(pathJ, path);

    jclass resultClass = env->FindClass("com/forensics/fbeprobe/EncryptionPolicyResult");
    jmethodID ctor = env->GetMethodID(resultClass, "<init>", "(IIIII[B)V");

    jbyteArray keyArray = env->NewByteArray(keyBytesLen);
    env->SetByteArrayRegion(keyArray, 0, keyBytesLen, reinterpret_cast<jbyte *>(keyBytes));

    return env->NewObject(
            resultClass, ctor,
            static_cast<jint>(saved_errno),
            static_cast<jint>(policyVersion),
            static_cast<jint>(contentsMode),
            static_cast<jint>(filenamesMode),
            static_cast<jint>(flags),
            keyArray);
}
