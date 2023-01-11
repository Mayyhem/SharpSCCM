using System;
using System.Management;

namespace SharpSCCM
{
    public class Cleanup
    {
        public static void RemoveApplication(ManagementScope scope, string applicationName)
        {
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, new ObjectQuery($"SELECT * FROM SMS_Application WHERE LocalizedDisplayName='{applicationName}'"));
            ManagementObjectCollection applications = searcher.Get();
            if (applications.Count > 0)
            {
                Console.WriteLine($"[+] Found {applications.Count} applications named {applicationName}");
                foreach (ManagementObject application in applications)
                {
                    application.InvokeMethod("SetIsExpired", new object[] { "True" });
                    application.Delete();
                }
                Console.WriteLine($"[+] Deleted all applications named {applicationName}");
                Console.WriteLine($"[+] Querying for applications named {applicationName}");
                string whereCondition = "LocalizedDisplayName='" + applicationName + "'";
                MgmtUtil.GetClassInstances(scope, "SMS_Application", false, null, whereCondition);
            }
            else
            {
                Console.WriteLine($"[+] Found {applications.Count} applications named {applicationName}");
            }
        }

        public static void RemoveCollection(ManagementScope scope, string collection)
        {
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, new ObjectQuery($"SELECT * FROM SMS_Collection WHERE Name='{collection}'"));
            ManagementObjectCollection collections = searcher.Get();
            if (collections.Count > 0)
            {
                Console.WriteLine($"[+] Found {collections.Count} collections named {collection}");
                foreach (ManagementObject collectionObj in collections)
                {
                    collectionObj.Delete();
                }
                Console.WriteLine($"[+] Deleted all collections named {collection}");
                Console.WriteLine($"[+] Querying for collections named {collection}");
                string whereCondition = "Name='" + collection + "'";
                MgmtUtil.GetClassInstances(scope, "SMS_Collection", false, null, whereCondition);
            }
            else
            {
                Console.WriteLine($"[+] Found {collections.Count} collections named {collection}");
            }
        }

        public static void RemoveDeployment(ManagementScope scope, string application, string collection)
        {
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, new ObjectQuery($"SELECT * FROM SMS_ApplicationAssignment WHERE ApplicationName='{application}' AND CollectionName='{collection}'"));
            ManagementObjectCollection deployments = searcher.Get();
            if (deployments.Count > 0)
            {
                Console.WriteLine($"[+] Found deployment of {application} to {collection}");
                foreach (ManagementObject deployment in deployments)
                {
                    deployment.Delete();
                    Console.WriteLine($"[+] Deleted deployment of {application} to {collection}");
                }
                Console.WriteLine($"[+] Querying for deployments of {application} to {collection}");
                string whereCondition = "ApplicationName='" + application + "' AND CollectionName='" + collection + "'";
                MgmtUtil.GetClassInstances(scope, "SMS_ApplicationAssignment", false, null, whereCondition);
            }
            else
            {
                Console.WriteLine($"[+] Found {deployments.Count} deployments of {application} to {collection}");
            }
        }

        public static void RemoveDevice(ManagementScope scope, string guid)
        {
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, new ObjectQuery($"SELECT * FROM SMS_R_SYSTEM WHERE SMSUniqueIdentifier='{guid}'"));
            ManagementObjectCollection devices = searcher.Get();
            if (devices.Count > 0)
            {
                foreach (ManagementObject device in devices)
                {
                    device.Delete();
                    Console.WriteLine($"[+] Deleted device with SMSUniqueIdentifier {guid}");
                }
            }
            else
            {
                Console.WriteLine($"[+] Found {devices.Count} devices with SMSUniqueIdentifier {guid}");
            }
        }
    }
}