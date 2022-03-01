using System;
using System.Linq;
using System.Management;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

// Configuration Manager SDK
using Microsoft.ConfigurationManagement.Messaging.Framework;
using Microsoft.ConfigurationManagement.Messaging.Messages;
using Microsoft.ConfigurationManagement.Messaging.Sender.Http;



namespace SharpSCCM
{
    public class Management
    {

        static void GetClasses(ManagementScope scope)
        {
            string query = "SELECT * FROM meta_class";
            Console.WriteLine($"[+] Executing WQL query: {query}");
            ObjectQuery objQuery = new ObjectQuery(query);
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, objQuery);
            var classes = new List<string>();
            foreach (ManagementClass wmiClass in searcher.Get())
            {
                classes.Add(wmiClass["__CLASS"].ToString());
            }
            classes.Sort();
            Console.WriteLine(String.Join("\n", classes.ToArray()));
        }
    }
}