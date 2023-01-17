using System;
using System.Collections;
using System.Collections.Generic;
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

        public static void RemoveCollectionMember(ManagementScope scope, string collectionName = null, string collectionType = null, string collectionId = null, string deviceName = null, string userName = null, string resourceId = null, int waitTime = 15)
        {
            // Use the provided collection type or set to device/user depending on which was provided
            collectionType = !string.IsNullOrEmpty(deviceName) ? "device" : !string.IsNullOrEmpty(userName) ? "user" : collectionType;

            // Make sure the specified collection exists
            ManagementObjectCollection collections = MgmtPointWmi.GetCollection(scope, collectionName, collectionId);
            if (collections.Count == 1)
            {
                // Make sure the specified resource is a member of the collection
                ManagementObjectCollection existingMembers = MgmtPointWmi.GetCollectionMember(scope, collectionName, collectionId, printOutput: false);
                if (existingMembers.Count > 0)
                {
                    foreach (ManagementObject existingMember in existingMembers)
                    {
                        if (!string.IsNullOrEmpty(deviceName) && (string)existingMember.GetPropertyValue("Name") == deviceName)
                        {
                            Console.WriteLine($"[+] Found a device named {deviceName} in the collection");
                        }
                        else if (!string.IsNullOrEmpty(userName) && existingMember.GetPropertyValue("Name").ToString().Contains(userName))
                        {
                            Console.WriteLine($"[+] Found a user named {existingMember.GetPropertyValue("Name")} in the collection");
                        }
                        else if (!string.IsNullOrEmpty(resourceId) && (uint)existingMember.GetPropertyValue("ResourceID") == Convert.ToUInt32(resourceId))
                        {
                            Console.WriteLine($"[+] Found resource with ID {resourceId} in the collection");
                        }
                    }
                }

                // Make sure the specified resource exists
                string membershipQuery = null;
                ManagementObjectCollection matchingResources = null;
                if (!string.IsNullOrEmpty(resourceId))
                {
                    membershipQuery = $"SELECT * FROM SMS_R_{(collectionType == "device" ? "System" : "User")} WHERE ResourceID='{resourceId}'";
                    matchingResources = MgmtUtil.GetClassInstances(scope, $"SMS_R_{(collectionType == "device" ? "System" : "User")}", membershipQuery);

                }
                else if (!string.IsNullOrEmpty(deviceName))
                {
                    membershipQuery = $"SELECT * FROM SMS_R_System WHERE Name='{deviceName}'";
                    matchingResources = MgmtUtil.GetClassInstances(scope, "SMS_R_System", membershipQuery);
                }
                else if (!string.IsNullOrEmpty(userName))
                {
                    membershipQuery = $"SELECT * FROM SMS_R_User WHERE UniqueUserName='{userName}'";
                    matchingResources = MgmtUtil.GetClassInstances(scope, "SMS_R_User", membershipQuery);
                }
                if (matchingResources.Count > 1)
                {
                    Console.WriteLine("[!] Found more than one instance of the specified resource");
                    Console.WriteLine("[!] Try using its ResourceID instead (-r)");
                }
                else if (matchingResources.Count > 0)
                {
                    Console.WriteLine("[+] Verified resource exists");
                    string newCollectionName = $"{collectionType}_{Guid.NewGuid()}";
                    ManagementObject collectionToExclude = MgmtPointWmi.NewCollection(scope, collectionType, newCollectionName);
                    if (collectionToExclude != null)
                    {
                        MgmtPointWmi.NewCollectionMember(scope, newCollectionName, collectionType, collectionId, deviceName, userName, resourceId);
                        ManagementObject newCollectionRule = new ManagementClass(scope, new ManagementPath("SMS_CollectionRuleExcludeCollection"), null).CreateInstance();
                        newCollectionRule["ExcludeCollectionID"] = collectionToExclude["CollectionID"];
                        newCollectionRule["RuleName"] = $"{newCollectionName}";
                        foreach (ManagementObject collection in collections)
                        {
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
                                    ManagementObjectCollection collectionMembers = MgmtPointWmi.GetCollectionMember(scope, collectionName, collectionId);
                                }
                                catch (ManagementException ex)
                                {
                                    Console.WriteLine($"[!] An exception occurred while attempting to commit the changes: {ex.Message}");
                                    Console.WriteLine("[!] Is your account assigned the correct security role?");
                                }
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

        public static void RemoveCollectionRule(ManagementScope scope, string collectionId, string queryId)
        {
            bool foundMatchingRule = false;
            // Make sure the specified collection exists
            ManagementObjectCollection collections = MgmtUtil.GetClassInstances(scope, "SMS_Collection", $"SELECT * FROM SMS_Collection WHERE CollectionID='{collectionId}'");
            if (collections.Count == 1)
            {
                foreach (ManagementObject collection in collections)
                {
                    // Fetch CollectionRules lazy property
                    collection.Get();
                    ManagementBaseObject[] collectionRules = (ManagementBaseObject[])collection["CollectionRules"];
                    foreach (ManagementBaseObject collectionRule in collectionRules)
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
                if (!foundMatchingRule)
                { 
                    Console.WriteLine("[+] Found 0 matching collection membership rules");
                }
            }
            else if (collections.Count > 1)
            {
                Console.WriteLine($"[!] Found more than one instance of the specified collection");
            }
            else
            {
                Console.WriteLine($"[+] Found 0 collections named {collectionId}");
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