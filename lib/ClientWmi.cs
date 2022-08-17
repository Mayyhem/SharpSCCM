using System;
using System.Management;
using Microsoft.ConfigurationManagement.Messaging.Framework;

namespace SharpSCCM
{
    static class ClientWmi
    {
        public static (string, string) GetCurrentManagementPointAndSiteCode()
        {
            string currentManagementPoint = "";
            string siteCode = "";

            ManagementScope wmiConnection = MgmtUtil.NewWmiConnection("localhost");
            string query = MgmtUtil.BuildClassInstanceQueryString(wmiConnection, "SMS_Authority", false, new[] { "CurrentManagementPoint", "Name" });
            ManagementObjectCollection classInstances = MgmtUtil.GetClassInstanceCollection(wmiConnection, "SMS_Authority", query);
            foreach (ManagementObject queryObj in classInstances)
            {
                foreach (PropertyData prop in queryObj.Properties)
                {
                    if (prop.Name == "CurrentManagementPoint")
                    {
                        currentManagementPoint = prop.Value.ToString();
                    }
                    else if (prop.Name == "Name")
                    {
                        siteCode = prop.Value.ToString().Substring(4, 3);
                    }
                }
            }
            return (currentManagementPoint, siteCode);
        }

        public static SmsClientId GetSmsId()
        {
            ManagementScope wmiConnection = MgmtUtil.NewWmiConnection("localhost");
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(wmiConnection, new ObjectQuery("SELECT * FROM CCM_Client"));
            string SmsId = null;
            foreach (ManagementObject instance in searcher.Get())
            {
                SmsId = instance["ClientId"].ToString();
            }
            Console.WriteLine($"[+] Obtained SmsId from local host: {SmsId}");
            return new SmsClientId(SmsId);
        }
    }
}