using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Management;
using System.Net;

namespace SharpSCCM.UnitTests
{
    [TestClass]
    public class SmsProviderWmiTests
    {
        public TestContext TestContext { get; set; }

        [TestMethod]
        public void GenerateCCR_DoesStuff()
        {
            Assert.Inconclusive();
        }

        [TestMethod]
        public void GetCollectionMember_PrintsCollectionMembers()
        {
            Assert.Inconclusive();
        }

        [TestMethod]
        public void GetSitePushMethod_Prints_SMS_SCI_SCProperty_Contents()
        {
            Assert.Inconclusive();
        }

        [TestMethod]
        public void GetSitePushMethod_PrintsClientPushAccounts()
        {
            Assert.Inconclusive();
        }

        [TestMethod]
        public void Exec_DoesStuff()
        {
            Assert.Inconclusive();
        }

        [TestMethod]
        public void InvokeUpdate_CallsInitiateClientOperation()
        {
            Assert.Inconclusive();
        }

        [TestMethod]
        public void NewApplication_PrintsNewApplicationNameIn_SMS_Application()
        {
            Assert.Inconclusive();
        }

        [TestMethod]
        public void NewApplication_PrintsNewCollectionNameIn_SMS_Collection()
        {
            Assert.Inconclusive();
        }

        [TestMethod]
        public void NewCollectionMember_Device_PrintsDeviceNameInCollectionMembers()
        {
            string collectionName = "NewCollectionMember_Device_UnitTest";
            string deviceName = Dns.GetHostName();

            ManagementScope wmiConnection = MgmtUtil.NewWmiConnection();
            TestContext.WriteLine($"Device name is {deviceName}");
            SmsProviderWmi.NewCollection(wmiConnection, "device", collectionName);
            var stringWriter = new StringWriter();
            Console.SetOut(stringWriter);
            SmsProviderWmi.NewCollectionMember(wmiConnection, collectionName, null, deviceName);
            StringAssert.Contains(stringWriter.ToString(), $"Name: {deviceName.ToUpper()}");
            TestContext.WriteLine(stringWriter.ToString());
            Cleanup.RemoveCollection(wmiConnection, collectionName, null);
        }

        [TestMethod]
        public void NewDeployment_PrintsNewDeploymentNameIn_SMS_ApplicationAssignment()
        {
            Assert.Inconclusive();
        }
    }
}
