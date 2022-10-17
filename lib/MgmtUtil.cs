using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
//using System.Text.Json;

namespace SharpSCCM
{
    public class MgmtUtil
    {
        public static string BuildClassInstanceQueryString(ManagementScope scope, string wmiClass, bool count = false, string[] properties = null, string whereCondition = null, string orderByColumn = null, bool verbose = false)
        {
            string propString;
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

        public static ManagementObjectCollection GetClassInstanceCollection(ManagementScope scope, string wmiClass, string query)
        {
            ManagementObjectCollection classInstances = null;
            try
            {
                Console.WriteLine($"[+] Executing WQL query: {query}");
                ObjectQuery objQuery = new ObjectQuery(query);
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, objQuery);
                classInstances = searcher.Get();
                
            }
            catch (ManagementException error)
            {
                Console.WriteLine("An error occurred while querying for WMI data: " + error.Message);
            }
            catch(Exception error)
            {
                Console.WriteLine($"An unhandled exception of type {error.GetType()} occurred: {error.Message}");
            }
            return classInstances;
        }

        public static void GetClassInstances(ManagementScope scope, string wmiClass, bool count = false, string[] properties = null, string whereCondition = null, string orderByColumn = null, bool dryRun = false, bool verbose = false, bool getLazyProps = true)
        {
            string query = BuildClassInstanceQueryString(scope, wmiClass, count, properties, whereCondition, orderByColumn, verbose);
            if (dryRun)
            {
                Console.WriteLine($"[+] WQL query: {query}");
            }
            else
            {
                ManagementObjectCollection classInstanceCollection = GetClassInstanceCollection(scope, wmiClass, query);
                PrintClassInstances(scope, wmiClass, query, classInstanceCollection, count, properties, verbose, getLazyProps);
            }
        }

        public static string[] GetKeyPropertyNames(ManagementScope wmiConnection, string className)
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
            catch (ManagementException error)
            {
                Console.WriteLine("An error occurred while querying for WMI data: " + error.Message);
            }
            catch (Exception error)
            {
                Console.WriteLine($"An unhandled exception of type {error.GetType()} occurred: {error.Message}");
            }
        }

        public static ManagementScope NewWmiConnection(string server = null, string wmiNamespace = null, string siteCode = null)
        {
            string path = "";
            ConnectionOptions connection = new ConnectionOptions();
            if (server == "localhost")
            {
                if (string.IsNullOrEmpty(wmiNamespace))
                {
                    wmiNamespace = "root\\ccm";
                }
                path = $"\\\\{server}\\{wmiNamespace}";
            }
            else if (!string.IsNullOrEmpty(server) && !string.IsNullOrEmpty(siteCode))
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
            else
            {
                (server, siteCode) = ClientWmi.GetCurrentManagementPointAndSiteCode();
                if (string.IsNullOrEmpty(wmiNamespace))
                {
                    path = $"\\\\{server}\\root\\SMS\\site_{siteCode}";
                }
                else
                {
                    path = $"\\\\{server}\\{wmiNamespace}";
                }
                
            }
            ManagementScope wmiConnection = new ManagementScope(path, connection);
            try
            {
                Console.WriteLine($"[+] Connecting to {wmiConnection.Path}");
                wmiConnection.Connect();
            }
            catch (UnauthorizedAccessException error)
            {
                Console.WriteLine("[!] Access to WMI was not authorized (user name or password might be incorrect): " + error.Message);
            }
            catch (ManagementException error)
            {
                Console.WriteLine("[!] Access to WMI was not authorized (user name or password might be incorrect): " + error.Message);
            }
            catch (Exception error)
            {
                Console.WriteLine($"An unhandled exception of type {error.GetType()} occurred: {error.Message}");
            }
            return wmiConnection;
        }

        public static void PrintClasses(ManagementScope scope)
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
            //string jsonString = JsonSerializer.Serialize(classes);
            //Console.WriteLine(jsonString);
        }

        public static void PrintClassInstances(ManagementScope scope, string wmiClass, string query, ManagementObjectCollection classInstanceCollection, bool count = false, string[] properties = null, bool verbose = false, bool getLazyProps = true)
        {
            Console.WriteLine("-----------------------------------");
            Console.WriteLine(wmiClass);
            Console.WriteLine("-----------------------------------");
            foreach (ManagementObject queryObj in classInstanceCollection)
            {
                // Get lazy properties unless we're just counting instances or we explicitly don't want lazy props
                if (!count && getLazyProps)
                {
                    try
                    {
                        queryObj.Get();
                    }
                    catch (Exception error)
                    {
                        Console.WriteLine($"An unhandled exception of type {error.GetType().ToString()} occurred: {error.Message}");
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

        public static void PrintClassProperties(ManagementObject classInstance, bool showValue = false)
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
    }
}