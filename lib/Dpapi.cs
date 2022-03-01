using System;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;


namespace SharpSCCM
{
    public class Dpapi
    {
        // Stolen from SharpDPAPI: https://github.com/GhostPack/SharpDPAPI
        public static void Execute(string blob, string masterkey)
        {
            Console.WriteLine("\r\n[*] Action: Describe DPAPI blob");

            // 1. Read in the hex dpapi blob
            // 2. Convert it to bytes
            // 3. Trim the extra header

            byte[] blobBytes = new byte[blob.Length / 2];
            for (int i = 0; i < blob.Length; i+=2)
            {
                blobBytes[i/2] = Byte.Parse(blob.Substring(i, 2), System.Globalization.NumberStyles.HexNumber);
            }

            // NAA has a header larger than a normal DPAPI blob. Remove the first 4 bytes from the array.
            var offset = 4;
            byte[] unmangledArray = new byte[blob.Length / 2];
            Buffer.BlockCopy(blobBytes, 4, unmangledArray, 0, blobBytes.Length - offset);
            
            // Super pro debug printing
            //foreach(byte b in unmangledArray)
            //{
            //    Console.Write("0x" + b.ToString("X2") + " ");
            //}

            // Copy the demangled array back into blobBytes
            blobBytes = unmangledArray;


            // Use SharpDPAPI to get masterkey and pass to this function, store in file
            // Temporarily set static path to masterkey file
            Dictionary<string, string> masterkeys = new Dictionary<string, string>();

            //string filePath = "C:\\users\\hurin.thalion\\Desktop\\keys.txt";
            
            masterkeys = Helpers.ParseMasterKeyCmdLine(masterkey);

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
                        }
                        else
                        {
                            data = Encoding.ASCII.GetString(decBytesRaw);
                        }
                        Console.WriteLine("    dec(blob)        : {0}", data);
                    }
                    else
                    {
                        string hexData = BitConverter.ToString(decBytesRaw).Replace("-", " ");
                        Console.WriteLine("    dec(blob)        : {0}", hexData);
                    }
                }
            }
        }

        public static byte[] DescribeDPAPIBlob(byte[] blobBytes, Dictionary<string, string> MasterKeys)
        {
            // Parses a DPAPI blob returning the decrypted plaintext

            var offset = 24; // Set to 24 since we're only working with 'blob' blobType
            var guidMasterKeyBytes = new byte[16];
            Array.Copy(blobBytes, offset, guidMasterKeyBytes, 0, 16);
            var guidMasterKey = new Guid(guidMasterKeyBytes);
            var guidString = $"{{{guidMasterKey}}}";

            Console.WriteLine("    guidMasterKey    : {0}", guidString);
            offset += 16;
            Console.WriteLine("    size             : {0}", blobBytes.Length);

            var flags = BitConverter.ToUInt32(blobBytes, offset);
            offset += 4;

            Console.WriteLine("    flags            : 0x{0}", flags.ToString("X"));
            if ((flags != 0) && ((flags & 0x20000000) == flags))
            {
                Console.Write(" (CRYPTPROTECT_SYSTEM)");
            }
            Console.WriteLine();

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

            Console.WriteLine("    algHash/algCrypt : {0} ({1}) / {2} ({3})", alghash, (Interop.CryptAlg)alghash, algCrypt, (Interop.CryptAlg)algCrypt);
            Console.WriteLine("    description      : {0}", description);

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
                    catch (Exception e)
                    {
                        Console.WriteLine("    [X] Error retrieving GUID:SHA1 from cache {0} : {1}", guidString, e.Message);
                    }
                }
            }

            return new byte[0]; //temp

        }

        public static byte[] DecryptBlob(byte [] ciphertext, byte[] key, int algCrypt, PaddingMode padding = PaddingMode.Zeros)
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
    }
}