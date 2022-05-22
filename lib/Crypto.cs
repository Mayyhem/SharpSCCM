using System;
using System.Security.Cryptography;

namespace SharpSCCM
{
    public class Crypto
    {
        // This code is credited to Will Schroeder @harmj0y and his SharpDPAPI project: https://github.com/GhostPack/SharpDPAPI
        public static byte[] DecryptBlob(byte[] ciphertext, byte[] key, int algCrypt, PaddingMode padding = PaddingMode.Zeros)
        {
            // Decrypts a DPAPI blob using 3DES or AES
            // reference: https://docs.microsoft.com/en-us/windows/desktop/seccrypto/alg-id

            switch (algCrypt)
            {
                case 26115: // 26115 == CALG_3DES
                {
                    // takes a byte array of ciphertext bytes and a key array, decrypt the blob with 3DES
                    var desCryptoProvider = new TripleDESCryptoServiceProvider();

                    var ivBytes = new byte[8];

                    desCryptoProvider.Key = key;
                    desCryptoProvider.IV = ivBytes;
                    desCryptoProvider.Mode = CipherMode.CBC;
                    desCryptoProvider.Padding = padding;
                    try
                    {
                        var plaintextBytes = desCryptoProvider.CreateDecryptor().TransformFinalBlock(ciphertext, 0, ciphertext.Length);
                        return plaintextBytes;
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("[X] An exception occured: {0}", e);
                    }

                    return new byte[0];
                }
                case 26128: // 25128 == CALG_AES_256
                {
                    // takes a byte array of ciphertext bytes and a key array, decrypt the blob with AES256
                    var aesCryptoProvider = new AesManaged();
                    var ivBytes = new byte[16];

                    aesCryptoProvider.Key = key;
                    aesCryptoProvider.IV = ivBytes;
                    aesCryptoProvider.Mode = CipherMode.CBC;
                    aesCryptoProvider.Padding = padding;

                    var plaintextBytes = aesCryptoProvider.CreateDecryptor().TransformFinalBlock(ciphertext, 0, ciphertext.Length);

                    return plaintextBytes;
                }
                default:
                    throw new Exception($"Could not decrypt blob. Unsupported algorithm: {algCrypt}");
            }
        }

        public static byte[] DeriveKey(byte[] keyBytes, byte[] saltBytes, int algHash)
        {
            // derives a dpapi session key using Microsoft crypto "magic"

            //Console.WriteLine("[*] key       : {0}", BitConverter.ToString(keyBytes).Replace("-", ""));
            //Console.WriteLine("[*] saltBytes : {0}", BitConverter.ToString(saltBytes).Replace("-", ""));
            //Console.WriteLine("[*] entropy   : {0}", BitConverter.ToString(entropy).Replace("-", ""));
            //Console.WriteLine("[*] algHash   : {0}", algHash)

            if (algHash == 32782)
            {
                // Calculate the session key -> HMAC(salt) where the SHA1(masterkey) is the key
                // 32782 == CALC_SHA_512
                // https://github.com/gentilkiwi/mimikatz/blob/fa42ed93aa4d5aa73825295e2ab757ac96005581/modules/kull_m_dpapi.c#L500
                return HMACSha512(keyBytes, saltBytes);
            }
            else if (algHash == 32772)
            {
                // 32772 == CALG_SHA1

                var ipad = new byte[64];
                var opad = new byte[64];

                // "...wut" - anyone reading Microsoft crypto
                for (var i = 0; i < 64; i++)
                {
                    ipad[i] = Convert.ToByte('6');
                    opad[i] = Convert.ToByte('\\');
                }

                for (var i = 0; i < keyBytes.Length; i++)
                {
                    ipad[i] ^= keyBytes[i];
                    opad[i] ^= keyBytes[i];
                }

                byte[] bufferI = Helpers.Combine(ipad, saltBytes);

                using (var sha1 = new SHA1Managed())
                {
                    var sha1BufferI = sha1.ComputeHash(bufferI);

                    byte[] bufferO = Helpers.Combine(opad, sha1BufferI);

                    var sha1Buffer0 = sha1.ComputeHash(bufferO);

                    return DeriveKeyRaw(sha1Buffer0, algHash);
                }
            }
            else
            {
                return new byte[0];
            }
        }

        // Adapted from https://github.com/gentilkiwi/mimikatz/blob/fa42ed93aa4d5aa73825295e2ab757ac96005581/modules/kull_m_crypto.c#L79-L101
        public static byte[] DeriveKeyRaw(byte[] hashBytes, int algHash)
        {
            var ipad = new byte[64];
            var opad = new byte[64];

            for (var i = 0; i < 64; i++)
            {
                ipad[i] = Convert.ToByte('6');
                opad[i] = Convert.ToByte('\\');
            }

            for (var i = 0; i < hashBytes.Length; i++)
            {
                ipad[i] ^= hashBytes[i];
                opad[i] ^= hashBytes[i];
            }

            if (algHash == 32772)
            {
                using (var sha1 = new SHA1Managed())
                {
                    var ipadSHA1bytes = sha1.ComputeHash(ipad);
                    var ppadSHA1bytes = sha1.ComputeHash(opad);

                    return Helpers.Combine(ipadSHA1bytes, ppadSHA1bytes);
                }
            }
            else
            {
                Console.WriteLine("[X] Alghash not yet implemented: {0}", algHash);
                return new byte[0];
            }
        }

        public static byte[] HMACSha512(byte[] keyBytes, byte[] saltBytes)
        {
            var hmac = new HMACSHA512(keyBytes);
            var sessionKeyBytes = hmac.ComputeHash(saltBytes);

            return sessionKeyBytes;
        }

        public static byte[] LSASHA256Hash(byte[] key, byte[] rawData)
        {
            // yay
            using (var sha256Hash = SHA256.Create())
            {
                var buffer = new byte[key.Length + (rawData.Length * 1000)];
                Array.Copy(key, 0, buffer, 0, key.Length);
                for (var i = 0; i < 1000; ++i)
                {
                    Array.Copy(rawData, 0, buffer, key.Length + (i * rawData.Length), rawData.Length);
                }
                return sha256Hash.ComputeHash(buffer);
            }
}