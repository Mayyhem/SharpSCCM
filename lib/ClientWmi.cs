using System;
using System.Management;
using Microsoft.ConfigurationManagement.Messaging.Framework;

namespace SharpSCCM
{
    static class ClientWmi
    {
        public static SmsClientId GetSmsId()
        {
            ManagementScope sccmConnection = MgmtUtil.NewSccmConnection("\\\\localhost\\root\\ccm");
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(sccmConnection, new ObjectQuery("SELECT * FROM CCM_Client"));
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