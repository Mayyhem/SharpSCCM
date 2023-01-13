using System;
using System.Collections;
using System.Collections.ObjectModel;
using System.Management;
using System.Threading;
using System.Xml.Linq;

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
                    try
                    {
                        application.InvokeMethod("SetIsExpired", new object[] { "True" });
                        application.Delete();
                        Console.WriteLine($"[+] Deleted all applications named {applicationName}");
                        Console.WriteLine($"[+] Querying for applications named {applicationName}");
                        string whereCondition = "LocalizedDisplayName='" + applicationName + "'";
                        ManagementObjectCollection notDeletedApplications = MgmtUtil.GetClassInstances(scope, "SMS_Application", null, false, null, whereCondition);
                        if (notDeletedApplications.Count > 0 )
                        {
                            Console.WriteLine($"[!] An application named {applicationName} was found");
                        }
                        else
                        {
                            Console.WriteLine($"[+] No remaining applications named {applicationName} were found");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[!] An exception occurred while attempting to remove the application: {ex.Message}");
                        Console.WriteLine("[!] Is your account assigned the correct security role?");
                    }
                }
            }
            else
            {
                Console.WriteLine($"[+] Found 0 applications named {applicationName}, or you do not have permission to query them");
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
                    try
                    {
                        collectionObj.Delete();
                        Console.WriteLine($"[+] Deleted all collections named {collection}");
                        Console.WriteLine($"[+] Querying for collections named {collection}");
                        string whereCondition = "Name='" + collection + "'";
                        ManagementObjectCollection notDeletedCollections = MgmtUtil.GetClassInstances(scope, "SMS_Collection", null, false, null, whereCondition);
                        if (notDeletedCollections.Count > 0)
                        {
                            Console.WriteLine($"[!] A collection named {collection} was found");
                        }
                        else
                        {
                            Console.WriteLine($"[+] No remaining collections named {collection} were found");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[!] An exception occurred while attempting to remove the collection: {ex.Message}");
                        Console.WriteLine("[!] Is your account assigned the correct security role?");
                    }
                }
            }
            else
            {
                Console.WriteLine($"[+] Found 0 collections named {collection}, or you do not have permission to query them");
            }
        }

        public static void RemoveCollectionMember(ManagementScope scope, string collectionName, string collectionType, string deviceName = null, string userName = null, string resourceId = null)
        {
            // Use the provided collection type or set to device/user depending on which was provided
            collectionType = !string.IsNullOrEmpty(deviceName) ? "device" : !string.IsNullOrEmpty(userName) ? "user" : collectionType;

            // Make sure the specified collection exists
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, new ObjectQuery($"SELECT * FROM SMS_Collection WHERE Name='{collectionName}'"));
            ManagementObjectCollection collections = searcher.Get();
            if (collections.Count > 0)
            {
                // Check if the resource is a member of the collection
                ManagementObjectCollection collectionMembers = MgmtPointWmi.GetCollectionMember(scope, collectionName, printOutput: false);
                if (collectionMembers.Count > 0)
                {
                    bool matchesFound = false;
                    string whereCondition = string.Empty;
                    foreach (ManagementObject collectionMember in collectionMembers)
                    {
                        if (!string.IsNullOrEmpty(deviceName) && (string)collectionMember.GetPropertyValue("Name") == deviceName)
                        {
                            Console.WriteLine($"[+] Found a device named {deviceName} in the collection");
                            matchesFound = true;
                            try
                            {
                                collectionMember.Delete();
                                Console.WriteLine($"[+] Deleted {deviceName} from {collectionName}");
                                whereCondition = $"Name='{deviceName}'";
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"[!] An exception occurred while attempting to remove the collection member: {ex.Message}");
                                Console.WriteLine("[!] Is your account assigned the correct security role?");
                            }
                        }
                        else if (!string.IsNullOrEmpty(userName) && collectionMember.GetPropertyValue("Name").ToString().Contains(userName))
                        {
                            Console.WriteLine($"[+] Found a user named {collectionMember.GetPropertyValue("Name")} in the collection");
                            matchesFound = true;
                            try
                            {
                                collectionMember.Delete();
                                Console.WriteLine($"[+] Deleted {userName} from {collectionName}");
                                whereCondition = $"Name LIKE '%{userName}%'";
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"[!] An exception occurred while attempting to remove the collection member: {ex.Message}");
                                Console.WriteLine("[!] Is your account assigned the correct security role?");
                            }
                        }
                        else if (!string.IsNullOrEmpty(resourceId) && (uint)collectionMember.GetPropertyValue("ResourceID") == Convert.ToUInt32(resourceId))
                        {
                            Console.WriteLine($"[+] Found a resource with ID {resourceId} in the collection");
                            matchesFound = true;
                            try
                            {
                                collectionMember.Delete();
                                Console.WriteLine($"[+] Deleted {resourceId} from {collectionName}");
                                whereCondition = $"ResourceID='{resourceId}'";
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"[!] An exception occurred while attempting to remove the collection member: {ex.Message}");
                                Console.WriteLine("[!] Is your account assigned the correct security role?");
                            }
                        }
                    }
                    if (!matchesFound)
                    {
                        Console.WriteLine(value: $"[+] No collection members with the specified name were found");
                    }
                    else
                    {
                        Console.WriteLine($"[+] Querying for deleted resource in {collectionName}");
                        ManagementObjectCollection notDeletedCollectionMembers = MgmtUtil.GetClassInstances(scope, "SMS_CollectionMember_a", null, false, null, whereCondition);
                        if (notDeletedCollectionMembers.Count > 0)
                        {
                            Console.WriteLine($"[!] A collection member with the specified name was found");
                        }
                        else
                        {
                            Console.WriteLine($"[+] No remaining collection members named {deviceName} were found");
                        }
                    }
                }
            }
            else
            {
                Console.WriteLine($"[+] Found 0 collections named {collectionName}");
            }
        }

        public static void RemoveDeployment(ManagementScope scope, string assignmentName)
        {
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, new ObjectQuery($"SELECT * FROM SMS_ApplicationAssignment WHERE AssignmentName='{assignmentName}'"));
            ManagementObjectCollection deployments = searcher.Get();
            if (deployments.Count > 0)
            {
                Console.WriteLine($"[+] Found deployment named {assignmentName}");
                foreach (ManagementObject deployment in deployments)
                {
                    try
                    {
                        deployment.Delete();
                        Console.WriteLine($"[+] Deleted deployment named {assignmentName}");
                        Console.WriteLine($"[+] Querying for deployments of {assignmentName}");
                        string whereCondition = $"AssignmentName='{assignmentName}'";
                        ManagementObjectCollection notDeletedDeployments = MgmtUtil.GetClassInstances(scope, "SMS_ApplicationAssignment", null, false, null, whereCondition);
                        if (notDeletedDeployments.Count > 0)
                        {
                            Console.WriteLine($"[!] A deployment named {assignmentName} was found");
                        }
                        else
                        {
                            Console.WriteLine($"[+] No remaining deployments named {assignmentName} were found");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[!] An exception occurred while attempting to remove the deployment: {ex.Message}");
                        Console.WriteLine("[!] Is your account assigned the correct security role?");
                    }
                }
            }
            else
            {
                Console.WriteLine($"[+] Found 0 deployments named {assignmentName}, or you do not have permission to query them");
            }
        }

        public static void RemoveDeviceFromCollection(ManagementScope scope, string deviceName, string collectionName)
        {
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, new ObjectQuery($"SELECT * FROM SMS_Collection WHERE Name='{collectionName}'"));
            ManagementObjectCollection collections = searcher.Get();
            if (collections.Count > 0)
            {
                foreach (ManagementObject collection in collections)
                {
                    ManagementObjectSearcher collectionSearcher = new ManagementObjectSearcher(scope, new ObjectQuery($"SELECT * FROM SMS_CollectionMember_a"));
                    ManagementObjectCollection collectionMembers = collectionSearcher.Get();
                    if (collectionMembers.Count > 0)
                    {
                        foreach (ManagementObject collectionMember in collectionMembers)
                        {
                            if (collectionMember.GetPropertyValue("CollectionID") == collection.GetPropertyValue("CollectionID") && (string)collectionMember.GetPropertyValue("Name") == deviceName)
                            {
                                Console.WriteLine($"[+] Found member of {collectionName} named {deviceName}");
                                try
                                {
                                    collectionMember.Delete();
                                    Console.WriteLine($"[+] Deleted {deviceName} from {collectionName}");
                                    Console.WriteLine($"[+] Querying for {deviceName} in {collectionName}");
                                    string whereCondition = $"Name='{deviceName}'";
                                    ManagementObjectCollection notDeletedCollectionMembers = MgmtUtil.GetClassInstances(scope, "SMS_CollectionMember_a", null, false, null, whereCondition);
                                    if (notDeletedCollectionMembers.Count > 0)
                                    {
                                        Console.WriteLine($"[!] A collection member named {deviceName} was found");
                                    }
                                    else
                                    {
                                        Console.WriteLine($"[+] No remaining collection memberss named {deviceName} were found");
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Console.WriteLine($"[!] An exception occurred while attempting to remove the collection member: {ex.Message}");
                                    Console.WriteLine("[!] Is your account assigned the correct security role?");
                                }
                            }
                            else
                            {
                                Console.WriteLine($"[+] Found 0 members of {collectionName} named {deviceName}, or you do not have permission to query them");
                            }
                        }
                    }
                    else
                    {
                        Console.WriteLine($"[+] Found 0 members of {collectionName}, or you do not have permission to query them");
                    }
                }
            }
            else
            {
                Console.WriteLine($"[+] Found 0 collections named {collectionName}");
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
                    try
                    {
                        device.Delete();
                        Console.WriteLine($"[+] Deleted device with SMSUniqueIdentifier {guid}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[!] An exception occurred while attempting to remove the device: {ex.Message}");
                        Console.WriteLine("[!] Is your account assigned the correct security role?");
                    }
                }
            }
            else
            {
                Console.WriteLine($"[+] Found 0 devices with SMSUniqueIdentifier {guid}, or you do not have permission to query them");
            }
        }
    }
}