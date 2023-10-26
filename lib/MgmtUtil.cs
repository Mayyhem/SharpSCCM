using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;

namespace SharpSCCM
{
    public class MgmtUtil
    {
        public static string BuildClassInstanceQueryString(ManagementScope wmiConnection, string wmiClass, bool count = false, string[] properties = null, string whereCondition = null, string orderByColumn = null, bool verbose = false)
        {
            string propString;
            if (verbose || count || properties == null)
            {
                propString = "*";
            }
            else
            {
                string[] keyPropertyNames = GetKeyPropertyNames(wmiConnection, wmiClass);
                if (keyPropertyNames.Length > 0)
                {
                    properties = keyPropertyNames.Union(properties).ToArray();
                    propString = string.Join(",", properties);
                }
                else
                {
                    return null;
                }
            }

            string whereClause = "";
            if (!string.IsNullOrEmpty(whereCondition))
            {
                whereClause = $"WHERE {whereCondition}";
            }

            string orderByClause = "";
            if (!string.IsNullOrEmpty(orderByColumn))
            {
                orderByClause = $"ORDER BY {orderByColumn}";
            }

            string query;
            if (count)
            {
                query = $"SELECT COUNT({propString}) FROM {wmiClass} {whereClause}";
            }
            else
            {
                query = $"SELECT {propString} FROM {wmiClass} {whereClause} {orderByClause}";
            }
            return query;
        }

        public static ManagementObjectCollection GetClassInstances(ManagementScope wmiConnection, string wmiClass, string query = null, bool count = false, string[] properties = null, string whereCondition = null, string orderByColumn = null, bool dryRun = false, bool verbose = false, bool getLazyProps = true, bool printOutput = false)
        {
            ManagementObjectCollection classInstances = null;
            if (wmiConnection.IsConnected)
            {
                // Build query string if not provided
                query = string.IsNullOrEmpty(query) ? BuildClassInstanceQueryString(wmiConnection, wmiClass, count, properties, whereCondition, orderByColumn, verbose) : query;
                if (dryRun)
                {
                    Console.WriteLine($"[+] WQL query: {query}");
                }
                else
                {
                    if (printOutput) Console.WriteLine($"[+] Executing WQL query: {query}");
                    ObjectQuery objQuery = new ObjectQuery(query);
                    ManagementObjectSearcher searcher = new ManagementObjectSearcher(wmiConnection, objQuery);
                    try
                    {
                        classInstances = searcher.Get();
                        if (printOutput)
                        {
                            if (classInstances.Count > 0)
                            {
                                PrintClassInstances(wmiClass, classInstances, count, properties, verbose, getLazyProps);
                            }
                            else
                            {
                                Console.WriteLine($"[+] No instances of {wmiClass} meeting the specified criteria were found, or you do not have permission to query them");
                            }
                        }
                    }
                    catch (ManagementException ex)
                    {
                        Console.WriteLine($"[!] An exception occurred while querying for WMI data: {ex.Message}");
                        if (ex.Message == "Unexpected error ")
                        {
                            Console.WriteLine("[!] Does your account have the correct permissions?");
                        }
                    }
                }
            }
            return classInstances;
        }

        public static string[] GetKeyPropertyNames(ManagementScope wmiConnection, string className)
        {
            try
            {
                using (ManagementClass managementClass = new ManagementClass(wmiConnection, new ManagementPath(className), new ObjectGetOptions()))
                {
                    return managementClass.Properties
                        .Cast<PropertyData>()
                        .Where(
                            property => property.Qualifiers
                                .Cast<QualifierData>()
                                .Any(qualifier => string.Equals(qualifier.Name, "Key", StringComparison.OrdinalIgnoreCase))
                        )
                        .Select(property => property.Name)
                        .ToArray();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] An exception occurred getting properties for {className}: {ex.Message}");
                return new string[0];
            }
        }

        public static ManagementScope NewWmiConnection(string server = null, string wmiNamespace = null, string siteCode = null)
        {
            string path = "";
            ConnectionOptions connection = new ConnectionOptions();
            // local connection
            if (server == "127.0.0.1")
            {
                if (string.IsNullOrEmpty(wmiNamespace))
                {
                    wmiNamespace = "root\\CCM";
                }
                path = $"\\\\{server}\\{wmiNamespace}";
            }
            // server is provided
            else if (!string.IsNullOrEmpty(server))
            {
                // but sidecode is not provided
                if (string.IsNullOrEmpty(siteCode))
                {
                    (_, siteCode) = ClientWmi.GetCurrentManagementPointAndSiteCode();
                    // siteCode should now be populated
                    if (!string.IsNullOrEmpty(siteCode))
                    {
                        Console.WriteLine($"[+] Using WMI provider: {server}");
                    }
                }
                // server and sitecode should now be populated unless there are errors querying the local WMI repository
                if (!string.IsNullOrEmpty(server) && !string.IsNullOrEmpty(siteCode))
                {
                    if (string.IsNullOrEmpty(wmiNamespace))
                    {
                        path = $"\\\\{server}\\root\\SMS\\site_{siteCode}";
                    }
                    else
                    {
                        path = $"\\\\{server}\\{wmiNamespace}";
                    }
                }
            }
            else
            // server not provided
            {
                // but sitecode is provided
                if (!string.IsNullOrEmpty(siteCode))
                { 
                    (server, _) = ClientWmi.GetCurrentManagementPointAndSiteCode();
                    // server should now be populated
                    if (!string.IsNullOrEmpty(server))
                    {
                        Console.WriteLine($"[+] Using provided site code: {siteCode}");
                    }
                }
                // server and sitecode not provided
                else
                {
                    (server, siteCode) = ClientWmi.GetCurrentManagementPointAndSiteCode();
                }
                // server and sitecode should now be populated unless there are errors querying the local WMI repository
                if (!string.IsNullOrEmpty(server) && !string.IsNullOrEmpty(siteCode))
                {
                    if (string.IsNullOrEmpty(wmiNamespace))
                    {
                        path = $"\\\\{server}\\root\\SMS\\site_{siteCode}";
                    }
                    else
                    {
                        path = $"\\\\{server}\\{wmiNamespace}";
                    }
                }
            }
            ManagementScope wmiConnection = null;
            try
            {
                if (!string.IsNullOrEmpty(path))
                {
                    wmiConnection = new ManagementScope(path, connection);
                    Console.WriteLine($"[+] Connecting to {wmiConnection.Path}");
                    wmiConnection.Connect();
                }
            }
            catch (UnauthorizedAccessException ex)
            {
                Console.WriteLine($"[!] Access to the WMI provider was not authorized: {ex.Message.Trim()}");
            }
            catch (ManagementException ex)
            {
                Console.WriteLine($"[!] Could not connect to {path}: " + ex.Message);
                if (path == "\\\\127.0.0.1\\root\\CCM" && ex.Message == "Invalid namespace ")
                {
                    Console.WriteLine(
                        "[!] The SCCM client may not be installed on this machine\n" +
                        "[!] Try specifying an SMS Provider (-sms) and site code (-sc)"
                        );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An unhandled exception of type {ex.GetType()} occurred: {ex.Message}");
            }
            return wmiConnection;
        }

        public static void PrintClasses(ManagementScope wmiConnection)
        {
            string query = "SELECT * FROM meta_class";
            Console.WriteLine($"[+] Executing WQL query: {query}");
            ObjectQuery objQuery = new ObjectQuery(query);
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(wmiConnection, objQuery);
            var classes = new List<string>();
            foreach (ManagementClass wmiClass in searcher.Get())
            {
                classes.Add(wmiClass["__CLASS"].ToString());
            }
            classes.Sort();
            Console.WriteLine(String.Join("\n", classes.ToArray()));
            //string jsonString = JsonSerializer.Serialize(classes);
            //Console.WriteLine(jsonString);
        }

        public static void PrintClassInstances(string wmiClass, ManagementObjectCollection classInstances, bool count = false, string[] properties = null, bool verbose = false, bool getLazyProps = true)
        {
            if (classInstances != null)
            {
                if (!string.IsNullOrEmpty(wmiClass))
                {
                    Console.WriteLine("-----------------------------------");
                    Console.WriteLine(wmiClass);
                }
                Console.WriteLine("-----------------------------------");
                foreach (ManagementObject queryObj in classInstances)
                {
                    // Get lazy properties unless we're just counting instances or we explicitly don't want lazy props
                    if (!count && getLazyProps)
                    {
                        try
                        {
                            queryObj.Get();
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"An unhandled exception of type {ex.GetType().ToString()} occurred: {ex.Message}");
                        }
                    }
                    foreach (PropertyData prop in queryObj.Properties)
                    {
                        // Print default properties if none specified, named properties if specified, or all properties if verbose
                        if (properties == null || properties.Length == 0 || properties.Contains(prop.Name) || count || verbose)
                        {
                            if (prop.IsArray)
                            {
                                // Test to see if we can display property values as strings, otherwise bail. Byte[] (e.g., Device.ObjectGUID) breaks things, Object[] (e.g., Collection.CollectionRules, Collection.RefreshSchedule) breaks things
                                if (prop.Value is String[])
                                {
                                    String[] nestedValues = (String[])(prop.Value);
                                    Console.WriteLine($"{prop.Name}: {string.Join(", ", nestedValues)}");
                                }
                                else if (prop.Value is int[])
                                {
                                    int[] nestedValues = (int[])(prop.Value);
                                    string[] nestedValueStrings = nestedValues.Select(x => x.ToString()).ToArray();
                                    Console.WriteLine($"{prop.Name}: {string.Join(", ", nestedValueStrings)}");
                                }
                                else if (prop.Value == null)
                                {
                                    Console.WriteLine($"{prop.Name}: Empty");
                                }
                                else
                                {
                                    string canConvertToString = prop.Value as string;
                                    if (canConvertToString != null)
                                    {
                                        Console.WriteLine($"{prop.Name}: {canConvertToString}");
                                    }
                                    else
                                    {
                                        Console.WriteLine($"{prop.Name}: Can't display {prop.Type.ToString()} as a String");
                                    }
                                }
                            }
                            else
                            {
                                Console.WriteLine("{0}: {1}", prop.Name, prop.Value);
                            }
                        }
                    }
                    Console.WriteLine("-----------------------------------");
                }
            }
        }

        public static void PrintClassProperties(ManagementObject classInstance, bool showValue = false)
        {
            Console.WriteLine("-----------------------------------");
            Console.WriteLine(classInstance.ClassPath);
            Console.WriteLine("-----------------------------------");
            foreach (PropertyData property in classInstance.Properties)
            {
                if (!showValue)
                {
                    Console.WriteLine($"{property.Name} ({property.Type})");
                }
                else
                {
                    Console.WriteLine($"{property.Name} ({property.Type}): {property.Value}");
                }
            }
            Console.WriteLine("-----------------------------------");
        }

        public static void PrintObjectProperties(ManagementBaseObject managementBaseObject, bool showValue = false)
        {
            foreach (PropertyData property in managementBaseObject.Properties)
            {
                Console.WriteLine($"{property.Name}: {property.Value}");
            }
            Console.WriteLine("-----------------------------------");
        }
    }
}