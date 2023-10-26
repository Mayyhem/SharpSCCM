using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;

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

        public static bool Contains<T>(this T[] array, T[] candidate)
        {
            if (IsEmptyLocate(array, candidate))
                return false;

            if (candidate.Length > array.Length)
                return false;

            for (int a = 0; a <= array.Length - candidate.Length; a++)
            {
                if (array[a].Equals(candidate[0]))
                {
                    int i = 0;
                    for (; i < candidate.Length; i++)
                    {
                        if (false == array[a + i].Equals(candidate[i]))
                            break;
                    }
                    if (i == candidate.Length)
                        return true;
                }
            }
            return false;
        }

        public static string EscapeBackslashes(string theString)
        {
            if (theString.Contains(@"\"))
            {
                theString = theString.Replace(@"\", @"\\");
            }
            return theString;
        }

        static bool IsEmptyLocate<T>(T[] array, T[] candidate)
        {
            return array == null
                   || candidate == null
                   || array.Length == 0
                   || candidate.Length == 0
                   || candidate.Length > array.Length;
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
            catch (Exception ex)
            {
                Console.WriteLine("[X] Error parsing masterkey file '{0}' : {1}", masterkey, ex.Message);
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
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Error parsing masterkey file '{0}' : {1}", filePath, ex.Message);
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

        public static bool IsHighIntegrity()
        {
            // returns true if the current process is running with adminstrative privs in a high integrity context

            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        public static string GetCurrentUserHexSid()
        {
            WindowsIdentity currentUser = WindowsIdentity.GetCurrent();
            SecurityIdentifier userSid = currentUser.User;
            Console.WriteLine($"[+] Current user: {currentUser.Name}");
            Console.WriteLine($"[+] Active Directory SID for current user: {userSid.Value}");

            byte[] binarySid = new byte[userSid.BinaryLength];
            userSid.GetBinaryForm(binarySid, 0);

            string hexSid = "";
            foreach (byte b in binarySid)
            {
                hexSid += (b.ToString("X2"));
            }
            Console.Write($"[+] Active Directory SID (hex): 0x{hexSid}\n");
            return hexSid;
        }

        public static bool GetSystem()
        {
            // helper to elevate to SYSTEM via token impersonation
            //  used for LSA secret (DPAPI_SYSTEM) retrieval

            if (IsHighIntegrity())
            {
                IntPtr hToken = IntPtr.Zero;

                // Open winlogon's token with TOKEN_DUPLICATE accesss so ca can make a copy of the token with DuplicateToken
                Process[] processes = Process.GetProcessesByName("winlogon");
                IntPtr handle = processes[0].Handle;

                // TOKEN_DUPLICATE = 0x0002
                bool success = Interop.OpenProcessToken(handle, 0x0002, out hToken);
                if (!success)
                {
                    //Console.WriteLine("OpenProcessToken failed!");
                    return false;
                }

                // make a copy of the NT AUTHORITY\SYSTEM token from winlogon
                // 2 == SecurityImpersonation
                IntPtr hDupToken = IntPtr.Zero;
                success = Interop.DuplicateToken(hToken, 2, ref hDupToken);
                if (!success)
                {
                    Interop.CloseHandle(hToken);
                    //Console.WriteLine("DuplicateToken failed!");
                    return false;
                }

                success = Interop.ImpersonateLoggedOnUser(hDupToken);
                if (!success)
                {
                    Interop.CloseHandle(hToken);
                    Interop.CloseHandle(hDupToken);
                    //Console.WriteLine("ImpersonateLoggedOnUser failed!");
                    return false;
                }

                // clean up the handles we created
                Interop.CloseHandle(hToken);
                Interop.CloseHandle(hDupToken);

                string name = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
                if (name != "NT AUTHORITY\\SYSTEM")
                {
                    return false;
                }

                return true;
            }
            else
            {
                return false;
            }
        }

        public static byte[] GetRegKeyValue(string keyPath)
        {
            // takes a given HKLM key path and returns the registry value

            int result = 0;
            IntPtr hKey = IntPtr.Zero;

            // open the specified key with read (0x19) privileges
            //  0x80000002 == HKLM
            result = Interop.RegOpenKeyEx(0x80000002, keyPath, 0, 0x19, ref hKey);
            if (result != 0)
            {
                int error = Marshal.GetLastWin32Error();
                string errorMessage = new Win32Exception((int)error).Message;
                Console.WriteLine("Error opening {0} ({1}) : {2}", keyPath, error, errorMessage);
                return null;
            }

            int cbData = 0;
            result = Interop.RegQueryValueEx(hKey, null, 0, IntPtr.Zero, IntPtr.Zero, ref cbData);
            if (result != 0)
            {
                int error = Marshal.GetLastWin32Error();
                string errorMessage = new Win32Exception((int)error).Message;
                Console.WriteLine("Error enumerating {0} ({1}) : {2}", keyPath, error, errorMessage);
                Interop.RegCloseKey(hKey);
                return null;
            }

            IntPtr dataPtr = Marshal.AllocHGlobal(cbData);
            result = Interop.RegQueryValueEx(hKey, null, 0, IntPtr.Zero, dataPtr, ref cbData);
            if (result != 0)
            {
                int error = Marshal.GetLastWin32Error();
                string errorMessage = new Win32Exception((int)error).Message;
                Console.WriteLine("Error enumerating {0} ({1}) : {2}", keyPath, error, errorMessage);
                Interop.RegCloseKey(hKey);
                return null;
            }
            byte[] data = new byte[cbData];

            Marshal.Copy(dataPtr, data, 0, cbData);
            Interop.RegCloseKey(hKey);

            return data;
        }

        public static void DecompressXMLNodes(System.Xml.XmlNode xmlNode)
        {
            System.Xml.XmlNodeList compressionNodesList = xmlNode.SelectNodes("*[@Compression]");
            if (compressionNodesList != null)
            {
                foreach (System.Xml.XmlNode compressionNode in compressionNodesList)
                {
                    if (compressionNode.Attributes["Compression"].Value == "zlib")
                    {
                        string compressedData = compressionNode.InnerText;
                        byte[] compressedDataBytes = Helpers.StringToByteArray(compressedData);
                        byte[] decompressedBytes;
                        using (MemoryStream outputStream = new MemoryStream())
                        {
                            using (MemoryStream inputStream = new MemoryStream(compressedDataBytes))
                            {
                                using (var decompressionStream = new System.IO.Compression.GZipStream(inputStream, System.IO.Compression.CompressionMode.Decompress))
                                {
                                    decompressionStream.CopyTo(outputStream);
                                }
                            }
                            decompressedBytes = outputStream.ToArray();
                        }
                        string szDecompressedStr = "";

                        //bool isUnicode = Helpers.IsUnicode(decompressedBytes);
                        if (decompressedBytes[0] == 0xFF && decompressedBytes[1] == 0xFE)
                        {
                            byte[] decompressedXMLBytes = new byte[decompressedBytes.Length - 2];
                            Array.Copy(decompressedBytes, 2, decompressedXMLBytes, 0, decompressedBytes.Length - 2);
                            szDecompressedStr = System.Text.Encoding.Unicode.GetString(decompressedXMLBytes);
                        }
                        // Update node content
                        if (szDecompressedStr.Length > 0)
                        {
                            // remove "\r", "\n", "\t", etc.
                            string szCleanedXmlStr = new string(szDecompressedStr.Where(c => !char.IsControl(c)).ToArray());
                            compressionNode.InnerXml = szCleanedXmlStr;
                            // Recursive decompress
                            foreach (System.Xml.XmlNode childNode in compressionNode.ChildNodes)
                            {
                                Helpers.DecompressXMLNodes(childNode);
                            }
                        }
                    }
                }
            }
        }

        public static bool DecryptDESSecret(string szEncData, out string szDecData)
        {
            bool bSuccess = false;
            int iEncBytesSize;
            byte[] abyEncBytes;
            szDecData = "";
            try
            {
                // Convert string to byte array
                Interop.CryptStringToBinaryW(szEncData, szEncData.Length, Interop.CryptStringToBinaryFlags.Hex, null, out iEncBytesSize, IntPtr.Zero, IntPtr.Zero);
                abyEncBytes = new byte[iEncBytesSize];
                Interop.CryptStringToBinaryW(szEncData, szEncData.Length, Interop.CryptStringToBinaryFlags.Hex, abyEncBytes, out iEncBytesSize, IntPtr.Zero, IntPtr.Zero);

                // This would also work, but the interop might be safer
                //byte[] abyEncBytes = Helper.StringToByteArray(szEncData);
            }
            catch (Exception)
            {
                // catch exception
                return false;
            }


            IntPtr pGarbledPtr = Marshal.AllocHGlobal(iEncBytesSize);
            byte[] abyDecData;
            try
            {
                // Copy the memory buffer to pGarbledPtr and marshal
                Marshal.Copy(abyEncBytes, 0, pGarbledPtr, abyEncBytes.Length);
                DESEncGarbledData garbledData = Marshal.PtrToStructure<DESEncGarbledData>(pGarbledPtr);

                // Workaround to solve marshalling of unknown size array
                // iSizeOfGarbledData= iSizeOfGarbledData - sizeOf(GarbledData.dwVersion) - sizeOf(GarbledData.key) - sizeOf(GarbledData.THeaderInfo)
                int iPDataOffset = 4 + 40 + 20;
                byte[] pDataArray = new byte[iEncBytesSize - iPDataOffset];
                Array.Copy(abyEncBytes, iPDataOffset, pDataArray, 0, pDataArray.Length);
                garbledData.pData = pDataArray;

                // decrypt
                bool decryptSucc = Crypto.DecryptDESBuffer(garbledData.key, garbledData.header, garbledData.pData, out abyDecData);
                if (decryptSucc)
                {
                    szDecData = System.Text.Encoding.Unicode.GetString(abyDecData).Trim();
                    bSuccess = true;
                }
            }
            finally
            {
                // Free the allocated memory
                Marshal.FreeHGlobal(pGarbledPtr);
            }
            return bSuccess;
        }
    }
}
