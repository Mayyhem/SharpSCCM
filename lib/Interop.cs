using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpSCCM
{
    public class Interop
    {
        public enum CryptAlg : uint
        {
            CALG_MD2 = (CryptAlgClass.ALG_CLASS_HASH | CryptAlgType.ALG_TYPE_ANY | CryptAlgSID.ALG_SID_MD2),
            CALG_MD4 = (CryptAlgClass.ALG_CLASS_HASH | CryptAlgType.ALG_TYPE_ANY | CryptAlgSID.ALG_SID_MD4),
            CALG_MD5 = (CryptAlgClass.ALG_CLASS_HASH | CryptAlgType.ALG_TYPE_ANY | CryptAlgSID.ALG_SID_MD5),
            CALG_SHA = (CryptAlgClass.ALG_CLASS_HASH | CryptAlgType.ALG_TYPE_ANY | CryptAlgSID.ALG_SID_SHA),
            CALG_SHA1 = (CryptAlgClass.ALG_CLASS_HASH | CryptAlgType.ALG_TYPE_ANY | CryptAlgSID.ALG_SID_SHA1),
            CALG_MAC = (CryptAlgClass.ALG_CLASS_HASH | CryptAlgType.ALG_TYPE_ANY | CryptAlgSID.ALG_SID_MAC),
            CALG_RSA_SIGN = (CryptAlgClass.ALG_CLASS_SIGNATURE | CryptAlgType.ALG_TYPE_RSA | CryptAlgSID.ALG_SID_RSA_ANY),
            CALG_DSS_SIGN = (CryptAlgClass.ALG_CLASS_SIGNATURE | CryptAlgType.ALG_TYPE_DSS | CryptAlgSID.ALG_SID_DSS_ANY),
            CALG_NO_SIGN = (CryptAlgClass.ALG_CLASS_SIGNATURE | CryptAlgType.ALG_TYPE_ANY | CryptAlgSID.ALG_SID_ANY),
            CALG_RSA_KEYX = (CryptAlgClass.ALG_CLASS_KEY_EXCHANGE | CryptAlgType.ALG_TYPE_RSA | CryptAlgSID.ALG_SID_RSA_ANY),
            CALG_DES = (CryptAlgClass.ALG_CLASS_DATA_ENCRYPT | CryptAlgType.ALG_TYPE_BLOCK | CryptAlgSID.ALG_SID_DES),
            CALG_3DES_112 = (CryptAlgClass.ALG_CLASS_DATA_ENCRYPT | CryptAlgType.ALG_TYPE_BLOCK | CryptAlgSID.ALG_SID_3DES_112),
            CALG_3DES = (CryptAlgClass.ALG_CLASS_DATA_ENCRYPT | CryptAlgType.ALG_TYPE_BLOCK | CryptAlgSID.ALG_SID_3DES),
            CALG_DESX = (CryptAlgClass.ALG_CLASS_DATA_ENCRYPT | CryptAlgType.ALG_TYPE_BLOCK | CryptAlgSID.ALG_SID_DESX),
            CALG_RC2 = (CryptAlgClass.ALG_CLASS_DATA_ENCRYPT | CryptAlgType.ALG_TYPE_BLOCK | CryptAlgSID.ALG_SID_RC2),
            CALG_RC4 = (CryptAlgClass.ALG_CLASS_DATA_ENCRYPT | CryptAlgType.ALG_TYPE_STREAM | CryptAlgSID.ALG_SID_RC4),
            CALG_SEAL = (CryptAlgClass.ALG_CLASS_DATA_ENCRYPT | CryptAlgType.ALG_TYPE_STREAM | CryptAlgSID.ALG_SID_SEAL),
            CALG_DH_SF = (CryptAlgClass.ALG_CLASS_KEY_EXCHANGE | CryptAlgType.ALG_TYPE_DH | CryptAlgSID.ALG_SID_DH_SANDF),
            CALG_DH_EPHEM = (CryptAlgClass.ALG_CLASS_KEY_EXCHANGE | CryptAlgType.ALG_TYPE_DH | CryptAlgSID.ALG_SID_DH_EPHEM),
            CALG_AGREEDKEY_ANY = (CryptAlgClass.ALG_CLASS_KEY_EXCHANGE | CryptAlgType.ALG_TYPE_DH | CryptAlgSID.ALG_SID_AGREED_KEY_ANY),
            CALG_KEA_KEYX = (CryptAlgClass.ALG_CLASS_KEY_EXCHANGE | CryptAlgType.ALG_TYPE_DH | CryptAlgSID.ALG_SID_KEA),
            CALG_HUGHES_MD5 = (CryptAlgClass.ALG_CLASS_KEY_EXCHANGE | CryptAlgType.ALG_TYPE_ANY | CryptAlgSID.ALG_SID_MD5),
            CALG_SKIPJACK = (CryptAlgClass.ALG_CLASS_DATA_ENCRYPT | CryptAlgType.ALG_TYPE_BLOCK | CryptAlgSID.ALG_SID_SKIPJACK),
            CALG_TEK = (CryptAlgClass.ALG_CLASS_DATA_ENCRYPT | CryptAlgType.ALG_TYPE_BLOCK | CryptAlgSID.ALG_SID_TEK),
            CALG_CYLINK_MEK = (CryptAlgClass.ALG_CLASS_DATA_ENCRYPT | CryptAlgType.ALG_TYPE_BLOCK | CryptAlgSID.ALG_SID_CYLINK_MEK),
            CALG_SSL3_SHAMD5 = (CryptAlgClass.ALG_CLASS_HASH | CryptAlgType.ALG_TYPE_ANY | CryptAlgSID.ALG_SID_SSL3SHAMD5),
            CALG_SSL3_MASTER = (CryptAlgClass.ALG_CLASS_MSG_ENCRYPT | CryptAlgType.ALG_TYPE_SECURECHANNEL | CryptAlgSID.ALG_SID_SSL3_MASTER),
            CALG_SCHANNEL_MASTER_HASH = (CryptAlgClass.ALG_CLASS_MSG_ENCRYPT | CryptAlgType.ALG_TYPE_SECURECHANNEL | CryptAlgSID.ALG_SID_SCHANNEL_MASTER_HASH),
            CALG_SCHANNEL_MAC_KEY = (CryptAlgClass.ALG_CLASS_MSG_ENCRYPT | CryptAlgType.ALG_TYPE_SECURECHANNEL | CryptAlgSID.ALG_SID_SCHANNEL_MAC_KEY),
            CALG_SCHANNEL_ENC_KEY = (CryptAlgClass.ALG_CLASS_MSG_ENCRYPT | CryptAlgType.ALG_TYPE_SECURECHANNEL | CryptAlgSID.ALG_SID_SCHANNEL_ENC_KEY),
            CALG_PCT1_MASTER = (CryptAlgClass.ALG_CLASS_MSG_ENCRYPT | CryptAlgType.ALG_TYPE_SECURECHANNEL | CryptAlgSID.ALG_SID_PCT1_MASTER),
            CALG_SSL2_MASTER = (CryptAlgClass.ALG_CLASS_MSG_ENCRYPT | CryptAlgType.ALG_TYPE_SECURECHANNEL | CryptAlgSID.ALG_SID_SSL2_MASTER),
            CALG_TLS1_MASTER = (CryptAlgClass.ALG_CLASS_MSG_ENCRYPT | CryptAlgType.ALG_TYPE_SECURECHANNEL | CryptAlgSID.ALG_SID_TLS1_MASTER),
            CALG_RC5 = (CryptAlgClass.ALG_CLASS_DATA_ENCRYPT | CryptAlgType.ALG_TYPE_BLOCK | CryptAlgSID.ALG_SID_RC5),
            CALG_HMAC = (CryptAlgClass.ALG_CLASS_HASH | CryptAlgType.ALG_TYPE_ANY | CryptAlgSID.ALG_SID_HMAC),
            CALG_TLS1PRF = (CryptAlgClass.ALG_CLASS_HASH | CryptAlgType.ALG_TYPE_ANY | CryptAlgSID.ALG_SID_TLS1PRF),
            CALG_HASH_REPLACE_OWF = (CryptAlgClass.ALG_CLASS_HASH | CryptAlgType.ALG_TYPE_ANY | CryptAlgSID.ALG_SID_HASH_REPLACE_OWF),
            CALG_AES_128 = (CryptAlgClass.ALG_CLASS_DATA_ENCRYPT | CryptAlgType.ALG_TYPE_BLOCK | CryptAlgSID.ALG_SID_AES_128),
            CALG_AES_192 = (CryptAlgClass.ALG_CLASS_DATA_ENCRYPT | CryptAlgType.ALG_TYPE_BLOCK | CryptAlgSID.ALG_SID_AES_192),
            CALG_AES_256 = (CryptAlgClass.ALG_CLASS_DATA_ENCRYPT | CryptAlgType.ALG_TYPE_BLOCK | CryptAlgSID.ALG_SID_AES_256),
            CALG_AES = (CryptAlgClass.ALG_CLASS_DATA_ENCRYPT | CryptAlgType.ALG_TYPE_BLOCK | CryptAlgSID.ALG_SID_AES),
            CALG_SHA_256 = (CryptAlgClass.ALG_CLASS_HASH | CryptAlgType.ALG_TYPE_ANY | CryptAlgSID.ALG_SID_SHA_256),
            CALG_SHA_384 = (CryptAlgClass.ALG_CLASS_HASH | CryptAlgType.ALG_TYPE_ANY | CryptAlgSID.ALG_SID_SHA_384),
            CALG_SHA_512 = (CryptAlgClass.ALG_CLASS_HASH | CryptAlgType.ALG_TYPE_ANY | CryptAlgSID.ALG_SID_SHA_512),
            CALG_ECDH = (CryptAlgClass.ALG_CLASS_KEY_EXCHANGE | CryptAlgType.ALG_TYPE_DH | CryptAlgSID.ALG_SID_ECDH),
            CALG_ECMQV = (CryptAlgClass.ALG_CLASS_KEY_EXCHANGE | CryptAlgType.ALG_TYPE_ANY | CryptAlgSID.ALG_SID_ECMQV),
            CALG_ECDSA = (CryptAlgClass.ALG_CLASS_SIGNATURE | CryptAlgType.ALG_TYPE_DSS | CryptAlgSID.ALG_SID_ECDSA)
        }

        public enum CryptAlgClass : uint
        {
            ALG_CLASS_ANY = (0),
            ALG_CLASS_SIGNATURE = (1 << 13),
            ALG_CLASS_MSG_ENCRYPT = (2 << 13),
            ALG_CLASS_DATA_ENCRYPT = (3 << 13),
            ALG_CLASS_HASH = (4 << 13),
            ALG_CLASS_KEY_EXCHANGE = (5 << 13),
            ALG_CLASS_ALL = (7 << 13)
        }

        public enum CryptAlgSID : uint
        {
            ALG_SID_ANY = (0),
            ALG_SID_RSA_ANY = 0,
            ALG_SID_RSA_PKCS = 1,
            ALG_SID_RSA_MSATWORK = 2,
            ALG_SID_RSA_ENTRUST = 3,
            ALG_SID_RSA_PGP = 4,
            ALG_SID_DSS_ANY = 0,
            ALG_SID_DSS_PKCS = 1,
            ALG_SID_DSS_DMS = 2,
            ALG_SID_ECDSA = 3,
            ALG_SID_DES = 1,
            ALG_SID_3DES = 3,
            ALG_SID_DESX = 4,
            ALG_SID_IDEA = 5,
            ALG_SID_CAST = 6,
            ALG_SID_SAFERSK64 = 7,
            ALG_SID_SAFERSK128 = 8,
            ALG_SID_3DES_112 = 9,
            ALG_SID_CYLINK_MEK = 12,
            ALG_SID_RC5 = 13,
            ALG_SID_AES_128 = 14,
            ALG_SID_AES_192 = 15,
            ALG_SID_AES_256 = 16,
            ALG_SID_AES = 17,
            ALG_SID_SKIPJACK = 10,
            ALG_SID_TEK = 11,
            ALG_SID_RC2 = 2,
            ALG_SID_RC4 = 1,
            ALG_SID_SEAL = 2,
            ALG_SID_DH_SANDF = 1,
            ALG_SID_DH_EPHEM = 2,
            ALG_SID_AGREED_KEY_ANY = 3,
            ALG_SID_KEA = 4,
            ALG_SID_ECDH = 5,
            ALG_SID_MD2 = 1,
            ALG_SID_MD4 = 2,
            ALG_SID_MD5 = 3,
            ALG_SID_SHA = 4,
            ALG_SID_SHA1 = 4,
            ALG_SID_MAC = 5,
            ALG_SID_RIPEMD = 6,
            ALG_SID_RIPEMD160 = 7,
            ALG_SID_SSL3SHAMD5 = 8,
            ALG_SID_HMAC = 9,
            ALG_SID_TLS1PRF = 10,
            ALG_SID_HASH_REPLACE_OWF = 11,
            ALG_SID_SHA_256 = 12,
            ALG_SID_SHA_384 = 13,
            ALG_SID_SHA_512 = 14,
            ALG_SID_SSL3_MASTER = 1,
            ALG_SID_SCHANNEL_MASTER_HASH = 2,
            ALG_SID_SCHANNEL_MAC_KEY = 3,
            ALG_SID_PCT1_MASTER = 4,
            ALG_SID_SSL2_MASTER = 5,
            ALG_SID_TLS1_MASTER = 6,
            ALG_SID_SCHANNEL_ENC_KEY = 7,
            ALG_SID_ECMQV = 1
        }

        public enum CryptAlgType : uint
        {
            ALG_TYPE_ANY = (0),
            ALG_TYPE_DSS = (1 << 9),
            ALG_TYPE_RSA = (2 << 9),
            ALG_TYPE_BLOCK = (3 << 9),
            ALG_TYPE_STREAM = (4 << 9),
            ALG_TYPE_DH = (5 << 9),
            ALG_TYPE_SECURECHANNEL = (6 << 9)
        }

        // For unicode detection
        [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
        public static extern bool IsTextUnicode
        (
            byte[] buf,
            int len,
            ref IsTextUnicodeFlags opt
        );

        [Flags]
        public enum IsTextUnicodeFlags : int
        {
            IS_TEXT_UNICODE_ASCII16 = 0x0001,
            IS_TEXT_UNICODE_REVERSE_ASCII16 = 0x0010,

            IS_TEXT_UNICODE_STATISTICS = 0x0002,
            IS_TEXT_UNICODE_REVERSE_STATISTICS = 0x0020,

            IS_TEXT_UNICODE_CONTROLS = 0x0004,
            IS_TEXT_UNICODE_REVERSE_CONTROLS = 0x0040,

            IS_TEXT_UNICODE_SIGNATURE = 0x0008,
            IS_TEXT_UNICODE_REVERSE_SIGNATURE = 0x0080,

            IS_TEXT_UNICODE_ILLEGAL_CHARS = 0x0100,
            IS_TEXT_UNICODE_ODD_LENGTH = 0x0200,
            IS_TEXT_UNICODE_DBCS_LEADBYTE = 0x0400,
            IS_TEXT_UNICODE_NULL_BYTES = 0x1000,

            IS_TEXT_UNICODE_UNICODE_MASK = 0x000F,
            IS_TEXT_UNICODE_REVERSE_MASK = 0x00F0,
            IS_TEXT_UNICODE_NOT_UNICODE_MASK = 0x0F00,
            IS_TEXT_UNICODE_NOT_ASCII_MASK = 0xF000
        }

        // for GetSystem()
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            UInt32 DesiredAccess,
            out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool DuplicateToken(
            IntPtr ExistingTokenHandle,
            int SECURITY_IMPERSONATION_LEVEL,
            ref IntPtr DuplicateTokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ImpersonateLoggedOnUser(
            IntPtr hToken);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(
            IntPtr hObject
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool RevertToSelf();

        // for LSA Secrets Dump
        [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
        public static extern int RegOpenKeyEx(
            uint hKey,
            string subKey,
            int ulOptions,
            int samDesired,
            ref IntPtr hkResult
        );

        [DllImport("advapi32.dll")]
        public static extern int RegQueryInfoKey(
            IntPtr hkey,
            StringBuilder lpClass,
            ref int lpcbClass,
            int lpReserved,
            ref IntPtr lpcSubKeys,
            ref IntPtr lpcbMaxSubKeyLen,
            ref IntPtr lpcbMaxClassLen,
            ref IntPtr lpcValues,
            ref IntPtr lpcbMaxValueNameLen,
            ref IntPtr lpcbMaxValueLen,
            ref IntPtr lpcbSecurityDescriptor,
            IntPtr lpftLastWriteTime
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern int RegQueryValueEx(
            IntPtr hKey,
            string lpValueName,
            int lpReserved,
            IntPtr type,
            IntPtr lpData,
            ref int lpcbData
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern int RegCloseKey(
            IntPtr hKey
        );
    }
}