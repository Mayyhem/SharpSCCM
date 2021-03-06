using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace SharpSCCM
{
    public static class Helpers
    {
        public static string ByteArrayToString(byte[] ba)
        {
            return BitConverter.ToString(ba).Replace("-", "");
        }

        public static byte[] Combine(byte[] first, byte[] second)
        {
            // helper to combine two byte arrays
            byte[] ret = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, ret, 0, first.Length);
            Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);

            return ret;
        }
        // Borrowed from SharpDPAPI: 
        public static bool IsUnicode(byte[] bytes)
        {
            // Helper that uses IsTextUnicode() API call to determine if a byte array is likely unicode text
            Interop.IsTextUnicodeFlags flags = Interop.IsTextUnicodeFlags.IS_TEXT_UNICODE_STATISTICS;
            return Interop.IsTextUnicode(bytes, bytes.Length, ref flags);
        }

        public static Dictionary<string, string> ParseMasterKeyCmdLine(string masterkey)
        {
            // Stolen from SharpDPAPI:
            // helper that parses a {GUID}:SHA1 masterkey file
            Dictionary<string, string> masterkeys = new Dictionary<string, string>();

            try
            {
                string[] parts = masterkey.Split(' '); // in case we have multiple keys on one line
                foreach (string part in parts)
                {
                    if (!String.IsNullOrEmpty(part.Trim()))
                    {
                        if (part.StartsWith("{"))
                        {
                            // SharpDPAPI {GUID}:SHA1 format
                            string[] mk = part.Split(':');
                            if (!masterkeys.ContainsKey(mk[0]))
                            {
                                masterkeys.Add(mk[0], mk[1]);
                            }
                        }
                        else if (part.StartsWith("GUID:"))
                        {
                            // Mimikatz dpapi::cache format
                            string[] mk = part.Split(';');
                            string[] guid = mk[0].Split(':');
                            string[] sha1 = mk[1].Split(':');
                            if (!masterkeys.ContainsKey(guid[0]))
                            {
                                masterkeys.Add(guid[1], sha1[1]);
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("[X] Error parsing masterkey file '{0}' : {1}", masterkey, e.Message);
            }

            return masterkeys;
        }

        public static Dictionary<string, string> ParseMasterKeyFile(string filePath)
        {
            // Stolen from SharpDPAPI:
            // helper that parses a {GUID}:SHA1 masterkey file
            Dictionary<string, string> masterkeys = new Dictionary<string, string>();

            if (File.Exists(filePath))
            {
                string[] lines = File.ReadAllLines(filePath);
                try
                {
                    foreach (string line in lines)
                    {
                        string[] parts = line.Split(' '); // in case we have multiple keys on one line
                        foreach (string part in parts)
                        {
                            if (!String.IsNullOrEmpty(part.Trim()))
                            {
                                if (part.StartsWith("{"))
                                {
                                    // SharpDPAPI {GUID}:SHA1 format
                                    string[] mk = part.Split(':');
                                    if (!masterkeys.ContainsKey(mk[0]))
                                    {
                                        masterkeys.Add(mk[0], mk[1]);
                                    }
                                }
                                else if (part.StartsWith("GUID:"))
                                {
                                    // Mimikatz dpapi::cache format
                                    string[] mk = part.Split(';');
                                    string[] guid = mk[0].Split(':');
                                    string[] sha1 = mk[1].Split(':');
                                    if (!masterkeys.ContainsKey(guid[0]))
                                    {
                                        masterkeys.Add(guid[1], sha1[1]);
                                    }
                                }
                            }
                        }
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("[X] Error parsing masterkey file '{0}' : {1}", filePath, e.Message);
                }
            }
            else
            {
                Console.WriteLine("[X] Masterkey file '{0}' doesn't exist!", filePath);
            }
            return masterkeys;
        }

        public static byte[] StringToByteArray(string hex)
        {
            // helper to convert a string hex representation to a byte array
            return Enumerable.Range(0, hex.Length).Where(x => x % 2 == 0).Select(x => Convert.ToByte(hex.Substring(x, 2), 16)).ToArray();
        }
    }
}