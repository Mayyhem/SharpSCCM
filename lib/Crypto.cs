using System;
using System.Security.Cryptography;

namespace SharpSCCM
{
    public class Crypto
    {
        // This code is credited to Will Schroeder (@harmj0y) and his SharpDPAPI project: https://github.com/GhostPack/SharpDPAPI
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

        public static byte[] LSAAESDecrypt(byte[] key, byte[] data)
        {
            var aesCryptoProvider = new AesManaged();

            aesCryptoProvider.Key = key;
            aesCryptoProvider.IV = new byte[16];
            aesCryptoProvider.Mode = CipherMode.CBC;
            aesCryptoProvider.BlockSize = 128;
            aesCryptoProvider.Padding = PaddingMode.Zeros;
            var transform = aesCryptoProvider.CreateDecryptor();

            var chunks = Decimal.ToInt32(Math.Ceiling((decimal)data.Length / (decimal)16));
            var plaintext = new byte[chunks * 16];

            for (var i = 0; i < chunks; ++i)
            {
                var offset = i * 16;
                var chunk = new byte[16];
                Array.Copy(data, offset, chunk, 0, 16);

                var chunkPlaintextBytes = transform.TransformFinalBlock(chunk, 0, chunk.Length);
                Array.Copy(chunkPlaintextBytes, 0, plaintext, i * 16, 16);
            }

            return plaintext;
        }


        // Based on https://github.com/Mayyhem/SharpSCCM/blob/main/DeobfuscateSecretString/DeobfuscateSecretString.cpp
        // Ported to C#
        public static bool DecryptDESBuffer(byte[] key, DESEncGarbledDataTHeaderInfo header, byte[] encryptedData, out byte[] plainData)
        {
            bool bSuccess = false;
            IntPtr hProv = IntPtr.Zero;
            IntPtr hHash = IntPtr.Zero;
            IntPtr hKey = IntPtr.Zero;
            plainData = new byte[0];
            try
            {
                const int PROV_RSA_AES = 24; // https://learn.microsoft.com/en-us/windows/win32/seccrypto/prov-rsa-aes
                const uint CRYPT_VERIFYCONTEXT = 0xF0000000; // https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta
                //public const int CALG_SHA = 32772;
                if (Interop.CryptAcquireContext(out hProv, null, null, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
                {
                    if (Interop.CryptCreateHash(hProv, (uint)Interop.CryptAlg.CALG_SHA, IntPtr.Zero, 0, out hHash))
                    {
                        if (Interop.CryptHashData(hHash, key, (uint)key.Length, 0))
                        {
                            // In our testing header.nAlgorithm was CALG_3DES (e.g. 0x6603)
                            if (Interop.CryptDeriveKey(hProv, (uint)header.nAlgorithm, hHash, (uint)header.nFlag, out hKey))
                            {
                                IntPtr pData = System.Runtime.InteropServices.Marshal.AllocHGlobal(encryptedData.Length);
                                //IntPtr ptrPlainData = Marshal.AllocHGlobal(100000);
                                System.Runtime.InteropServices.Marshal.Copy(encryptedData, 0, pData, encryptedData.Length);
                                uint dwDecryptedLen = (uint)header.nPlainSize;
                                plainData = new byte[dwDecryptedLen];
                                if (Interop.CryptDecrypt(hKey, IntPtr.Zero, true, 0, pData, ref dwDecryptedLen))
                                {
                                    System.Runtime.InteropServices.Marshal.Copy(pData, plainData, 0, (int)dwDecryptedLen);
                                    bSuccess = true;
                                }
                                Interop.CryptDestroyKey(hKey);
                                System.Runtime.InteropServices.Marshal.FreeHGlobal(pData);
                            }
                        }
                        Interop.CryptDestroyHash(hHash);
                    }
                    Interop.CryptReleaseContext(hProv, 0);
                }
            }
            catch (Exception)
            {
                // Handle any exceptions here
            }
            finally
            {
                if (hKey != IntPtr.Zero)
                {
                    Interop.CryptDestroyKey(hKey);
                }
                if (hHash != IntPtr.Zero)
                {
                    Interop.CryptDestroyHash(hHash);
                }
                if (hProv != IntPtr.Zero)
                {
                    Interop.CryptReleaseContext(hProv, 0);
                }
            }

            return bSuccess;
        }
    }
}