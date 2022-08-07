using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;

namespace SharpSCCM
{
    public class MgmtUtil
    {
        public static void GetClasses(ManagementScope scope)
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

        public static void GetClassInstances(ManagementScope scope, string wmiClass, bool count = false, string[] properties = null, string whereCondition = null, string orderByColumn = null, bool dryRun = false, bool verbose = false, bool getLazyProps = true)
        {
            try
            {
                string query = "";
                string propString = "";
                string whereClause = "";
                string orderByClause = "";

                if (verbose || count || properties == null)
                {
                    propString = "*";
                }
                else
                {
                    string[] keyPropertyNames = GetKeyPropertyNames(scope, wmiClass);
                    properties = keyPropertyNames.Union(properties).ToArray();
                    propString = string.Join(",", properties);
                }
                if (!string.IsNullOrEmpty(whereCondition))
                {
                    whereClause = $"WHERE {whereCondition}";
                }
                if (!string.IsNullOrEmpty(orderByColumn))
                {
                    orderByClause = $"ORDER BY {orderByColumn}";
                }
                if (count)
                {
                    query = $"SELECT COUNT({propString}) FROM {wmiClass} {whereClause}";
                }
                else
                {
                    query = $"SELECT {propString} FROM {wmiClass} {whereClause} {orderByClause}";
                }

                if (dryRun)
                {
                    Console.WriteLine($"[+] WQL query: {query}");
                }
                else
                {
                    Console.WriteLine($"[+] Executing WQL query: {query}\n");
                    ObjectQuery objQuery = new ObjectQuery(query);
                    ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, objQuery);
                    Console.WriteLine("-----------------------------------");
                    Console.WriteLine(wmiClass);
                    Console.WriteLine("-----------------------------------");
                    foreach (ManagementObject queryObj in searcher.Get())
                    {
                        // Get lazy properties unless we're just counting instances or we explicitly don't want lazy props
                        if (!count && getLazyProps)
                        {
                            queryObj.Get();
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
            catch (ManagementException err)
            {
                Console.WriteLine("An error occurred while querying for WMI data: " + err.Message);
            }
        }

        public static void GetClassProperties(ManagementObject classInstance, bool showValue = false)
        {
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
        }

        public static string[] GetKeyPropertyNames(ManagementScope sccmConnection, string className)
        {
            using (ManagementClass managementClass = new ManagementClass(sccmConnection, new ManagementPath(className), new ObjectGetOptions()))
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

        public static void InvokeQuery(ManagementScope scope, string query)
        {
            try
            {
                ObjectQuery objQuery = new ObjectQuery(query);
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, objQuery);
                Console.WriteLine("-----------------------------------");
                Console.WriteLine(objQuery);
                Console.WriteLine("-----------------------------------");
                foreach (ManagementObject queryObj in searcher.Get())
                {
                    foreach (PropertyData prop in queryObj.Properties)
                    {
                        Console.WriteLine("{0}: {1}", prop.Name, prop.Value);
                    }
                    Console.WriteLine("-----------------------------------");
                }
            }
            catch (ManagementException err)
            {
                Console.WriteLine("An error occurred while querying for WMI data: " + err.Message);
            }
        }

        public static ManagementScope NewSccmConnection(string path)
        {
            ConnectionOptions connection = new ConnectionOptions();
            ManagementScope sccmConnection = new ManagementScope(path, connection);
            try
            {
                Console.WriteLine($"[+] Connecting to {sccmConnection.Path}");
                sccmConnection.Connect();
            }
            catch (System.UnauthorizedAccessException unauthorizedErr)
            {
                Console.WriteLine("[!] Access to WMI was not authorized (user name or password might be incorrect): " + unauthorizedErr.Message);
            }
            catch (Exception e)
            {
                Console.WriteLine("[!] Error connecting to WMI: " + e.Message);
            }
            return sccmConnection;
        }
    }
}