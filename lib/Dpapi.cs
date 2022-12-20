// This code was taken/derived from Will Schroeder's (@harmj0y) SharpDPAPI project
// https://github.com/GhostPack/SharpDPAPI

using PBKDF2;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace SharpSCCM
{
    public class Dpapi
    {
        public static byte[] DecryptBlob(byte[] ciphertext, byte[] key, int algCrypt, PaddingMode padding = PaddingMode.Zeros)
        {
            // decrypts a DPAPI blob using AES

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

        public static byte[] DescribeDPAPIBlob(byte[] blobBytes, Dictionary<string, string> MasterKeys)
        {
            // Parses a DPAPI blob returning the decrypted plaintext

            var offset = 24; // Set to 24 since we're only working with 'blob' blobType
            var guidMasterKeyBytes = new byte[16];
            Array.Copy(blobBytes, offset, guidMasterKeyBytes, 0, 16);
            var guidMasterKey = new Guid(guidMasterKeyBytes);
            var guidString = $"{{{guidMasterKey}}}";

            //Console.WriteLine("    guidMasterKey    : {0}", guidString);
            offset += 16;
            //Console.WriteLine("    size             : {0}", blobBytes.Length);

            var flags = BitConverter.ToUInt32(blobBytes, offset);
            offset += 4;

            //Console.WriteLine("    flags            : 0x{0}", flags.ToString("X"));
            if ((flags != 0) && ((flags & 0x20000000) == flags))
            {
                //Console.Write(" (CRYPTPROTECT_SYSTEM)");
            }
            //Console.WriteLine();

            var descLength = BitConverter.ToInt32(blobBytes, offset);
            offset += 4;
            var description = Encoding.Unicode.GetString(blobBytes, offset, descLength);
            offset += descLength;

            var algCrypt = BitConverter.ToInt32(blobBytes, offset);
            offset += 4;

            var algCryptLen = BitConverter.ToInt32(blobBytes, offset);
            offset += 4;

            var saltLen = BitConverter.ToInt32(blobBytes, offset);
            offset += 4;

            var saltBytes = new byte[saltLen];
            Array.Copy(blobBytes, offset, saltBytes, 0, saltLen);
            offset += saltLen;

            var hmacKeyLen = BitConverter.ToInt32(blobBytes, offset);
            offset += 4 + hmacKeyLen;

            var alghash = BitConverter.ToInt32(blobBytes, offset);
            offset += 4;

            var algHashLen = BitConverter.ToInt32(blobBytes, offset);
            offset += 4;

            var hmac2KeyLen = BitConverter.ToInt32(blobBytes, offset);
            offset += 4 + hmac2KeyLen;

            var dataLen = BitConverter.ToInt32(blobBytes, offset);
            offset += 4;
            var dataBytes = new byte[dataLen];
            Array.Copy(blobBytes, offset, dataBytes, 0, dataLen);

            if (MasterKeys.ContainsKey(guidString))
            {
                // if this key is present, decrypt this blob
                if (alghash == 32782)
                {
                    // grab the sha1(masterkey) from the cache
                    try
                    {
                        var keyBytes = Helpers.StringToByteArray(MasterKeys[guidString].ToString());

                        // derive the session key
                        var derivedKeyBytes = Crypto.DeriveKey(keyBytes, saltBytes, alghash);
                        var finalKeyBytes = new byte[algCryptLen / 8];
                        Array.Copy(derivedKeyBytes, finalKeyBytes, algCryptLen / 8);

                        return Crypto.DecryptBlob(dataBytes, finalKeyBytes, algCrypt);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("    [!] Error retrieving GUID:SHA1 from cache {0} : {1}", guidString, ex.Message);
                    }
                }
            }
            return new byte[0]; //temp
        }

        public static Dictionary<string, string> TriageSystemMasterKeys(bool reg)
        {
            // retrieve the DPAPI_SYSTEM key and use it to decrypt any SYSTEM DPAPI masterkeys
            var mappings = new Dictionary<string, string>();
            if (Helpers.IsHighIntegrity())
            {
                // get the system and user DPAPI backup keys, showing the machine DPAPI keys
                //  { machine , user }
                var keys = LSADump.GetDPAPIKeys(true, reg);
                string systemFolder = "";

                if (!Environment.Is64BitProcess)
                {
                    systemFolder = $"{Environment.GetEnvironmentVariable("SystemDrive")}\\Windows\\Sysnative\\Microsoft\\Protect\\";
                }
                else
                {
                    systemFolder = $"{Environment.GetEnvironmentVariable("SystemDrive")}\\Windows\\System32\\Microsoft\\Protect\\";
                }
                
                if (Directory.Exists(systemFolder))
                {
                    try
                    {
                        string[] systemDirs = Directory.GetDirectories(systemFolder);

                        foreach (var directory in systemDirs)
                        {
                            var machineFiles = Directory.GetFiles(directory);
                            var userFiles = new string[0];

                            if (Directory.Exists($"{directory}\\User\\"))
                            {
                                userFiles = Directory.GetFiles($"{directory}\\User\\");
                            }

                            foreach (var file in machineFiles)
                            {
                                if (!Regex.IsMatch(file,
                                        @".*\\[0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}"))
                                    continue;
                                var masteyKeyBytes = File.ReadAllBytes(file);
                                try
                                {
                                    // use the "machine" DPAPI key
                                    var plaintextMasterkey = Dpapi.DecryptMasterKeyWithSha(masteyKeyBytes, keys[0]);
                                    mappings.Add(plaintextMasterkey.Key, plaintextMasterkey.Value);
                                }
                                catch (Exception ex)
                                {
                                    Console.WriteLine("[!] Error triaging {0} : {1}", file, ex.Message);
                                }
                            }

                            foreach (var file in userFiles)
                            {
                                if (!Regex.IsMatch(file,
                                        @".*\\[0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}"))
                                    continue;
                                var masteyKeyBytes = File.ReadAllBytes(file);
                                try
                                {
                                    // use the "user" DPAPI key
                                    var plaintextMasterKey = Dpapi.DecryptMasterKeyWithSha(masteyKeyBytes, keys[1]);
                                    mappings.Add(plaintextMasterKey.Key, plaintextMasterKey.Value);
                                }
                                catch (Exception ex)
                                {
                                    Console.WriteLine("[!] Error triaging {0} : {1}", file, ex.Message);
                                }
                            }
                        }
                        Console.WriteLine("\r\n[+] SYSTEM master key cache:");
                        foreach (KeyValuePair<string, string> kvp in mappings)
                        {
                            Console.WriteLine("    {0}:{1}", kvp.Key, kvp.Value);
                        }
                    }
                    catch (Exception)
                    {

                    }
                }
            }
            else
            {
                Console.WriteLine("\r\n[!] Must be elevated to triage SYSTEM masterkeys!\r\n");
            }
            return mappings;
        }

        public static KeyValuePair<string, string> DecryptMasterKeyWithSha(byte[] masterKeyBytes, byte[] shaBytes)
        {
            // takes masterkey bytes and SYSTEM_DPAPI masterkey sha bytes, returns a dictionary of guid:sha1 masterkey mappings
            var guidMasterKey = $"{{{Encoding.Unicode.GetString(masterKeyBytes, 12, 72)}}}";

            var mkBytes = GetMasterKey(masterKeyBytes);

            var offset = 4;
            var salt = new byte[16];
            Array.Copy(mkBytes, 4, salt, 0, 16);
            offset += 16;

            var rounds = BitConverter.ToInt32(mkBytes, offset);
            offset += 4;

            var algHash = BitConverter.ToInt32(mkBytes, offset);
            offset += 4;

            var algCrypt = BitConverter.ToInt32(mkBytes, offset);
            offset += 4;

            var encData = new byte[mkBytes.Length - offset];
            Array.Copy(mkBytes, offset, encData, 0, encData.Length);

            var derivedPreKey = DerivePreKey(shaBytes, algHash, salt, rounds);

            switch (algCrypt)
            {
                // CALG_AES_256 == 26128 , CALG_SHA_512 == 32782
                case 26128 when (algHash == 32782):
                    {
                        var masterKeySha1 = DecryptAes256HmacSha512(shaBytes, derivedPreKey, encData);
                        var masterKeyStr = BitConverter.ToString(masterKeySha1).Replace("-", "");

                        return new KeyValuePair<string, string>(guidMasterKey, masterKeyStr);
                    }

                // Support for 32777(CALG_HMAC) / 26115(CALG_3DES)
                case 26115 when (algHash == 32777 || algHash == 32772):
                    {
                        var masterKeySha1 = DecryptTripleDESHmac(derivedPreKey, encData);
                        var masterKeyStr = BitConverter.ToString(masterKeySha1).Replace("-", "");

                        return new KeyValuePair<string, string>(guidMasterKey, masterKeyStr);
                    }

                default:
                    throw new Exception($"Alg crypt '{algCrypt} / 0x{algCrypt:X8}' not currently supported!");
            }

        }

        public static byte[] GetMasterKey(byte[] masterKeyBytes)
        {
            // helper to extract domain masterkey subbytes from a master key blob

            var offset = 96;

            var masterKeyLen = BitConverter.ToInt64(masterKeyBytes, offset);
            offset += 4 * 8; // skip the key length headers

            var masterKeySubBytes = new byte[masterKeyLen];
            Array.Copy(masterKeyBytes, offset, masterKeySubBytes, 0, masterKeyLen);

            return masterKeySubBytes;
        }

        private static byte[] DerivePreKey(byte[] shaBytes, int algHash, byte[] salt, int rounds)
        {
            byte[] derivedPreKey;

            switch (algHash)
            {
                // CALG_SHA_512 == 32782
                case 32782:
                    {
                        // derive the "Pbkdf2/SHA512" key for the masterkey, using MS' silliness
                        using (var hmac = new HMACSHA512())
                        {
                            var df = new Pbkdf2(hmac, shaBytes, salt, rounds);
                            derivedPreKey = df.GetBytes(48);
                        }

                        break;
                    }

                case 32777:
                    {
                        // derive the "Pbkdf2/SHA1" key for the masterkey, using MS' silliness
                        using (var hmac = new HMACSHA1())
                        {
                            var df = new Pbkdf2(hmac, shaBytes, salt, rounds);
                            derivedPreKey = df.GetBytes(32);
                        }

                        break;
                    }

                default:
                    throw new Exception($"alg hash  '{algHash} / 0x{algHash:X8}' not currently supported!");
            }

            return derivedPreKey;
        }

        private static byte[] DecryptAes256HmacSha512(byte[] shaBytes, byte[] final, byte[] encData)
        {
            var HMACLen = (new HMACSHA512()).HashSize / 8;
            var aesCryptoProvider = new AesManaged();

            var ivBytes = new byte[16];
            Array.Copy(final, 32, ivBytes, 0, 16);

            var key = new byte[32];
            Array.Copy(final, 0, key, 0, 32);

            aesCryptoProvider.Key = key;
            aesCryptoProvider.IV = ivBytes;
            aesCryptoProvider.Mode = CipherMode.CBC;
            aesCryptoProvider.Padding = PaddingMode.Zeros;

            // decrypt the encrypted data using the Pbkdf2-derived key
            var plaintextBytes = aesCryptoProvider.CreateDecryptor().TransformFinalBlock(encData, 0, encData.Length);

            var outLen = plaintextBytes.Length;
            var outputLen = outLen - 16 - HMACLen;

            var masterKeyFull = new byte[HMACLen];

            // outLen - outputLen == 80 in this case
            Array.Copy(plaintextBytes, outLen - outputLen, masterKeyFull, 0, masterKeyFull.Length);

            using (var sha1 = new SHA1Managed())
            {
                var masterKeySha1 = sha1.ComputeHash(masterKeyFull);

                // we're HMAC'ing the first 16 bytes of the decrypted buffer with the shaBytes as the key
                var plaintextCryptBuffer = new byte[16];
                Array.Copy(plaintextBytes, plaintextCryptBuffer, 16);
                var hmac1 = new HMACSHA512(shaBytes);
                var round1Hmac = hmac1.ComputeHash(plaintextCryptBuffer);

                // round 2
                var round2buffer = new byte[outputLen];
                Array.Copy(plaintextBytes, outLen - outputLen, round2buffer, 0, outputLen);
                var hmac2 = new HMACSHA512(round1Hmac);
                var round2Hmac = hmac2.ComputeHash(round2buffer);

                // compare the second HMAC value to the original plaintextBytes, starting at index 16
                var comparison = new byte[64];
                Array.Copy(plaintextBytes, 16, comparison, 0, comparison.Length);

                if (comparison.SequenceEqual(round2Hmac))
                {
                    return masterKeySha1;
                }

                throw new Exception("HMAC integrity check failed!");

            }
        }

        private static byte[] DecryptTripleDESHmac(byte[] final, byte[] encData)
        {
            var desCryptoProvider = new TripleDESCryptoServiceProvider();

            var ivBytes = new byte[8];
            var key = new byte[24];

            Array.Copy(final, 24, ivBytes, 0, 8);
            Array.Copy(final, 0, key, 0, 24);

            desCryptoProvider.Key = key;
            desCryptoProvider.IV = ivBytes;
            desCryptoProvider.Mode = CipherMode.CBC;
            desCryptoProvider.Padding = PaddingMode.Zeros;

            var plaintextBytes = desCryptoProvider.CreateDecryptor().TransformFinalBlock(encData, 0, encData.Length);
            var decryptedkey = new byte[64];

            Array.Copy(plaintextBytes, 40, decryptedkey, 0, 64);
            using (var sha1 = new SHA1Managed())
            {
                var masterKeySha1 = sha1.ComputeHash(decryptedkey);
                return masterKeySha1;
            }
        }


        //public static void Execute(string blob, string masterkey)
        public static string Execute(string blob, Dictionary<string, string> masterkeys)
        {
            byte[] blobBytes = new byte[blob.Length / 2];
            for (int i = 0; i < blob.Length; i += 2)
            {
                blobBytes[i / 2] = Byte.Parse(blob.Substring(i, 2), System.Globalization.NumberStyles.HexNumber);
            }

            // NAA has a header larger than a normal DPAPI blob. Remove the first 4 bytes from the array.
            var offset = 4;
            byte[] unmangledArray = new byte[blob.Length / 2];
            Buffer.BlockCopy(blobBytes, 4, unmangledArray, 0, blobBytes.Length - offset);

            // Copy the demangled array back into blobBytes
            blobBytes = unmangledArray;

            if (blobBytes.Length > 0)
            {

                byte[] decBytesRaw = DescribeDPAPIBlob(blobBytes, masterkeys);

                if ((decBytesRaw != null) && (decBytesRaw.Length != 0))
                {
                    if (Helpers.IsUnicode(decBytesRaw))
                    {
                        string data = "";
                        int finalIndex = Array.LastIndexOf(decBytesRaw, (byte)0);
                        if (finalIndex > 1)
                        {
                            byte[] decBytes = new byte[finalIndex + 1];
                            Array.Copy(decBytesRaw, 0, decBytes, 0, finalIndex);
                            data = Encoding.Unicode.GetString(decBytes);
                            return data;
                        }
                        else
                        {
                            data = Encoding.ASCII.GetString(decBytesRaw);
                            return data;
                        }
                    }
                    else
                    {
                        string hexData = BitConverter.ToString(decBytesRaw).Replace("-", " ");
                        return hexData;
                    }
                }
                else
                {
                    return null;
                }
            }
            else
            {
                return null;
            }
        }
    }
}