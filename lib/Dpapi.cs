using System;
using System.IO;
using System.Text;
using System.Collections;
using System.Collections.Generic;
using System.Security.Cryptography;


namespace SharpSCCM
{
    public class Dpapi
    {
        public static void Execute(string blob)
        {
            Console.WriteLine("\r\n[*] Action: Describe DPAPI blob");

            // 1. Read in the hex dpapi blob
            // 2. Convert it to bytes
            // 3. Trim the extra header

            //$bytes = for($i=0; $i -lt $bdpass.Length; $i++) {[byte]::Parse($bdpass.Substring($i, 2), [System.Globalization.NumberStyles]::HexNumber); $i++}
            byte[] blobBytes = new byte[blob.Length];
            for (int i = 0; i < blob.Length; i++)
            {
                blobBytes[i] = Byte.Parse(blob.Substring(i, 2), System.Globalization.NumberStyles.HexNumber);
                Console.WriteLine(blobBytes[i]);
                i++;
            }

            // NAA has a header larger than a normal DPAPI blob. Remove the first 4 bytes from the array.
            var offset = 4;
            var dedupedArray = new byte[blob.Length - offset];
            Buffer.BlockCopy(blobBytes, 4, dedupedArray, 0, blobBytes.Length - offset);
            //System.Convert.ToBase64String(dedupedArray);

            if (blobBytes.Length > 0)
            {
                byte[] decBytesRaw = DescribeDPAPIBlob(blobBytes, masterkeys, "blob", unprotect, entropy);
                
                if ((decBytesRaw != null) && (decBytesRaw.Length != 0))
                {
                    if (Helpers.IsUnicode(decBytesRaw))
                    {
                        string data = "";
                        int finalIndex = Array.LastIndexOf(decBytesRaw, (byte)0);
                        if (finalIndex > 1)
                        {
                            byte[] decBytes = new byte[finalIndex + 1];
                            Array.Copy(decBytesRaw, 0, decBytes, finalIndex);
                            data = Encoding.Unicode.GetString(decBytes);
                        }
                        else
                        {
                            data = Encoding.ASCII.GetString(decBytesRaw);
                        }
                        Console.WriteLine("   dec(blob)     : {0}", data);
                    }
                    else
                    {
                        string hexData = BitConverter.ToString(decBytesRaw).Replace("-", " ");
                        Console.WriteLine("   dec(blob)     : {0}", hexData);
                    }
                }
            }
        }

        public static byte[] DescribeDPAPIBlob(byte[] blobBytes, Dictionary<string, string> MasterKeys)
        {
            // Parses a DPAPI blob returning the decrypted plaintext

            var offset = 24; // Set to 24 since we're only working with 'blob' blobType

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