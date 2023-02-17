using System;
using System.Management;
using Microsoft.ConfigurationManagement.Messaging.Framework;

namespace SharpSCCM
{
    public class ClientWmi
    {
        public static (string, string) GetCurrentManagementPointAndSiteCode()
        {
            string currentManagementPoint = "";
            string siteCode = "";

            Console.WriteLine("[+] Querying the local WMI repository for the current management point and site code");
            ManagementScope wmiConnection = MgmtUtil.NewWmiConnection("127.0.0.1");
            if (wmiConnection.IsConnected)
            {
                string query = MgmtUtil.BuildClassInstanceQueryString(wmiConnection, "SMS_Authority", false, new[] { "CurrentManagementPoint", "Name" });
                ManagementObjectCollection classInstances = MgmtUtil.GetClassInstances(wmiConnection, "SMS_Authority", query);
                if (classInstances != null)
                {
                    foreach (ManagementObject queryObj in classInstances)
                    {
                        foreach (PropertyData prop in queryObj.Properties)
                        {
                            if (prop.Name == "CurrentManagementPoint")
                            {
                                currentManagementPoint = prop.Value.ToString();
                                if (!string.IsNullOrEmpty(currentManagementPoint))
                                {
                                    Console.WriteLine(value: $"[+] Current management point: {currentManagementPoint}");
                                }
                                else
                                {
                                    Console.WriteLine("[!] Could not find the current management point");
                                }
                            }
                            else if (prop.Name == "Name")
                            {
                                siteCode = prop.Value.ToString().Substring(4, 3);
                                if (!string.IsNullOrEmpty(siteCode))
                                {
                                    Console.WriteLine($"[+] Site code: {siteCode}");
                                }
                                else
                                {
                                    Console.WriteLine("[!] Could not find the current site code");
                                }
                            }
                        }
                    }
                }
                else
                {
                    Console.WriteLine("[!] Could not query SMS_Authority for the current management point and site code");
                }
            }
            return (currentManagementPoint, siteCode);
        }

        public static SmsClientId GetSmsId()
        {
            ManagementScope wmiConnection = MgmtUtil.NewWmiConnection("127.0.0.1");
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(wmiConnection, new ObjectQuery("SELECT * FROM CCM_Client"));
            string smsId = null;
            foreach (ManagementObject instance in searcher.Get())
            {
                smsId = instance["ClientId"].ToString();
            }
            Console.WriteLine($"[+] Obtained SmsId from local host: {smsId}");
            return new SmsClientId(smsId);
        }
    }
}