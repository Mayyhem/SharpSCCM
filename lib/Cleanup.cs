using System;
using System.Linq;
using System.Management;
using System.Threading;

namespace SharpSCCM
{
    public class Cleanup
    {
        public static void RemoveApplication(ManagementScope wmiConnection, string applicationName)
        {
            string whereCondition = $"LocalizedDisplayName='{applicationName}'";
            ManagementObjectCollection applications = MgmtUtil.GetClassInstances(wmiConnection, "SMS_Application", whereCondition: whereCondition);
            if (applications.Count == 1)
            {
                Console.WriteLine($"[+] Found the {applicationName} application");
                ManagementObject application = applications.OfType<ManagementObject>().First();
                try
                {
                    application.InvokeMethod("SetIsExpired", new object[] { "True" });
                    application.Delete();
                    Console.WriteLine($"[+] Deleted the {applicationName} application");
                    Console.WriteLine($"[+] Querying for applications named {applicationName}");
                    ManagementObjectCollection notDeletedApplications = MgmtUtil.GetClassInstances(wmiConnection, "SMS_Application", whereCondition: whereCondition);
                    if (notDeletedApplications.Count > 0 )
                    {
                        Console.WriteLine($"[!] A remaining application named {applicationName} was found");
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
            else if (applications.Count == 0)
            {
                Console.WriteLine($"[+] Found 0 applications named {applicationName}, or you do not have permission to query them");
            }
            else
            {
                Console.WriteLine($"[!] Found {applications.Count} applications named {applicationName}");
            }
        }

        public static void RemoveCollection(ManagementScope wmiConnection, string collectionName, string collectionId)
        {
            ManagementObject collection = SmsProviderWmi.GetCollection(wmiConnection, collectionName, collectionId);
            if (collection != null)
            {
                try
                {
                    collection.Delete();
                    Console.WriteLine($"[+] Deleted the {collection["Name"]} collection ({collection["CollectionID"]})");
                    Console.WriteLine($"[+] Querying for the {collection["Name"]} collection ({collection["CollectionID"]})");
                    ManagementObject notDeletedCollection = SmsProviderWmi.GetCollection(wmiConnection, collectionName, collectionId);
                    if (notDeletedCollection != null)
                    {
                        Console.WriteLine($"[!] A remaining {collection["Name"]} collection ({collection["CollectionID"]}) was found");
                    }
                    else
                    {
                        Console.WriteLine($"[+] No remaining collections named {collection["Name"]} with CollectionID {collection["CollectionID"]} were found");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] An exception occurred while attempting to remove the collection: {ex.Message}");
                    Console.WriteLine("[!] Is your account assigned the correct security role?");
                    Console.WriteLine("[!] This may occur if the collection is referenced by another collection");
                }
            }
        }

        public static void RemoveCollectionMember(ManagementScope wmiConnection, string collectionName = null, string collectionType = null, string collectionId = null, string deviceName = null, string userName = null, string resourceId = null, int waitTime = 15)
        {
            // Use the provided collection type or set to device/user depending on which was provided
            collectionType = !string.IsNullOrEmpty(deviceName) ? "device" : !string.IsNullOrEmpty(userName) ? "user" : collectionType;

            // Check whether the specified collection exists
            ManagementObject collection = SmsProviderWmi.GetCollection(wmiConnection, collectionName, collectionId, true);
            if (collection != null)
            {
                // Check whether the specified resource is a member of the collection
                ManagementObjectCollection existingMembers = SmsProviderWmi.GetCollectionMembers(wmiConnection, collectionName, collectionId, printOutput: false);
                if (existingMembers.Count > 0)
                {
                    bool resourceIsExistingMember = false;
                    foreach (ManagementObject existingMember in existingMembers)
                    {
                        if (!string.IsNullOrEmpty(deviceName) && (string)existingMember.GetPropertyValue("Name") == deviceName)
                        {
                            Console.WriteLine($"[+] Found a device named {deviceName} in the collection");
                            resourceIsExistingMember = true;
                        }
                        else if (!string.IsNullOrEmpty(userName) && existingMember.GetPropertyValue("Name").ToString().Contains(userName))
                        {
                            Console.WriteLine($"[+] Found a user named {existingMember.GetPropertyValue("Name")} in the collection");
                            resourceIsExistingMember = true;
                        }
                        else if (!string.IsNullOrEmpty(resourceId) && (uint)existingMember.GetPropertyValue("ResourceID") == Convert.ToUInt32(resourceId))
                        {
                            Console.WriteLine($"[+] Found resource with ID {resourceId} in the collection");
                            resourceIsExistingMember = true;
                        }
                    }
                    if (!resourceIsExistingMember)
                    {
                        Console.WriteLine("[!] Found 0 matching resources in the specified collection");
                        return;
                    }
                }

                // Check whether the specified resource exists
                ManagementObject matchingResource = SmsProviderWmi.GetDeviceOrUser(wmiConnection, deviceName, resourceId, userName, true);
                if (matchingResource != null)
                {
                    string newCollectionName = $"{collectionType}_{Guid.NewGuid()}";
                    ManagementObject collectionToExclude = SmsProviderWmi.NewCollection(wmiConnection, collectionType, newCollectionName);
                    if (collectionToExclude != null)
                    {
                        SmsProviderWmi.NewCollectionMember(wmiConnection, newCollectionName, collectionType, collectionId, deviceName, userName, resourceId);
                        ManagementObject newCollectionRule = new ManagementClass(wmiConnection, new ManagementPath("SMS_CollectionRuleExcludeCollection"), null).CreateInstance();
                        newCollectionRule["ExcludeCollectionID"] = collectionToExclude["CollectionID"];
                        newCollectionRule["RuleName"] = $"{newCollectionName}";
                        ManagementBaseObject addMembershipRuleParams = collection.GetMethodParameters("AddMembershipRule");
                        addMembershipRuleParams.SetPropertyValue("collectionRule", newCollectionRule);
                        if ((uint)collection.Properties[propertyName: "CollectionType"].Value == 1 && collectionType == "device")
                        {
                            Console.WriteLine("[!] Can't add a device to a user collection");
                        }
                        else if ((uint)collection.Properties["CollectionType"].Value == 2 && collectionType == "user")
                        {
                            Console.WriteLine("[!] Can't add a user to a device collection");

                        }
                        else
                        {
                            try
                            {
                                collection.InvokeMethod("AddMembershipRule", addMembershipRuleParams, null);
                                Console.WriteLine($"[+] Added rule to exclude resource from {(!string.IsNullOrEmpty(collectionName) ? collectionName : collectionId)}");
                                Console.WriteLine($"[+] Waiting {waitTime}s for collection to populate");
                                Thread.Sleep(waitTime * 1000);
                                ManagementObjectCollection collectionMembers = SmsProviderWmi.GetCollectionMembers(wmiConnection, collectionName, collectionId, printOutput: true);
                            }
                            catch (ManagementException ex)
                            {
                                Console.WriteLine($"[!] An exception occurred while attempting to commit the changes: {ex.Message}");
                                Console.WriteLine("[!] Is your account assigned the correct security role?");
                            }
                        }
                    }
                }
                else
                {
                    Console.WriteLine($"[!] Could not find the specified device or user");
                }
            }
        }

        public static void RemoveCollectionRule(ManagementScope wmiConnection, string collectionId, string queryId)
        {
            bool foundMatchingRule = false;
            // Check whether the specified collection exists
            ManagementObjectCollection collections = MgmtUtil.GetClassInstances(wmiConnection, "SMS_Collection", $"SELECT * FROM SMS_Collection WHERE CollectionID='{collectionId}'");
            if (collections.Count == 1)
            {
                foreach (ManagementObject collection in collections)
                {
                    // Fetch CollectionRules lazy property
                    collection.Get();
                    ManagementBaseObject[] collectionRules = (ManagementBaseObject[])collection["CollectionRules"];
                    foreach (ManagementBaseObject collectionRule in collectionRules)
                    {
                        if (collectionRule.Properties.Cast<PropertyData>().Any(property => property.Name == "QueryID"))
                        {
                            if ((uint)collectionRule["QueryID"] == Convert.ToUInt32(queryId))
                            {
                                foundMatchingRule = true;
                                Console.WriteLine($"[+] Found matching rule for CollectionID {collectionId}");
                                Console.WriteLine($"-----------------------------------");
                                Console.WriteLine("CollectionRule");
                                Console.WriteLine($"-----------------------------------");
                                foreach (PropertyData property in collectionRule.Properties)
                                {
                                    Console.WriteLine($"{property.Name}: {property.Value}");
                                }
                                Console.WriteLine($"-----------------------------------");
                                try
                                {
                                    collection.InvokeMethod("DeleteMembershipRule", new object[] { collectionRule });
                                    Console.WriteLine($"[+] Successfully removed collection rule");
                                }
                                catch (Exception ex)
                                {
                                    Console.WriteLine($"[!] An exception occurred while attempting to remove the collection rule: {ex.Message}");
                                    Console.WriteLine("[!] Is your account assigned the correct security role?");
                                }
                            }
                        }
                    }
                }
                if (!foundMatchingRule)
                { 
                    Console.WriteLine("[+] Found 0 matching collection membership rules");
                }
            }
            else if (collections.Count > 1)
            {
                Console.WriteLine($"[!] Found {collections.Count} instances of the specified collectionID {collectionId}");
            }
            else
            {
                Console.WriteLine($"[+] Found 0 collections named {collectionId}");
            }
        }

        public static void RemoveDeployment(ManagementScope wmiConnection, string assignmentName)
        {
            ManagementObjectCollection deployments = MgmtUtil.GetClassInstances(wmiConnection, "SMS_ApplicationAssignment", whereCondition: $"AssignmentName='{assignmentName}'");
            if (deployments.Count == 1)
            {
                Console.WriteLine($"[+] Found the {assignmentName} deployment");
                ManagementObject deployment = deployments.OfType<ManagementObject>().First();
                try
                {
                    deployment.Delete();
                    Console.WriteLine($"[+] Deleted the {assignmentName} deployment");
                    Console.WriteLine($"[+] Querying for deployments of {assignmentName}");
                    string whereCondition = $"AssignmentName='{assignmentName}'";
                    ManagementObjectCollection notDeletedDeployments = MgmtUtil.GetClassInstances(wmiConnection, "SMS_ApplicationAssignment", null, false, null, whereCondition);
                    if (notDeletedDeployments.Count > 0)
                    {
                        Console.WriteLine($"[!] A remaining deployment named {assignmentName} was found");
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
            else if (deployments.Count == 0)
            {
                Console.WriteLine($"[+] Found 0 deployments named {assignmentName}, or you do not have permission to query them");
            }
            else
            {
                Console.WriteLine($"[+] Found {deployments.Count} deployments named {assignmentName}");
            }
        }

        public static void RemoveDeviceFromCollection(ManagementScope wmiConnection, string deviceName, string collectionName)
        {
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(wmiConnection, new ObjectQuery($"SELECT * FROM SMS_Collection WHERE Name='{collectionName}'"));
            ManagementObjectCollection collections = searcher.Get();
            if (collections.Count > 0)
            {
                foreach (ManagementObject collection in collections)
                {
                    ManagementObjectSearcher collectionSearcher = new ManagementObjectSearcher(wmiConnection, new ObjectQuery($"SELECT * FROM SMS_CollectionMember_a"));
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
                                    ManagementObjectCollection notDeletedCollectionMembers = MgmtUtil.GetClassInstances(wmiConnection, "SMS_CollectionMember_a", null, false, null, whereCondition);
                                    if (notDeletedCollectionMembers.Count > 0)
                                    {
                                        Console.WriteLine($"[!] A remaining collection member named {deviceName} was found");
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

        public static void RemoveDevice(ManagementScope wmiConnection, string guid)
        {
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(wmiConnection, new ObjectQuery($"SELECT * FROM SMS_R_SYSTEM WHERE SMSUniqueIdentifier='{guid}'"));
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