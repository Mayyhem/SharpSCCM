using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Management;
using System.Net;
using System.Resources;

namespace SharpSCCM.UnitTests
{
    [TestClass]
    public class MgmtPointWmiTests
    {
        public TestContext TestContext { get; set; }

        [TestMethod]
        public void AddDeviceToCollection_PrintsDeviceNameInCollectionMembers()
        {
            string collectionName = "AddDeviceToCollection_UnitTest";
            string deviceName = Dns.GetHostName();
            
            ManagementScope wmiConnection = MgmtUtil.NewWmiConnection();
            TestContext.WriteLine($"Device name is {deviceName}");
            MgmtPointWmi.NewCollection(wmiConnection, "device", collectionName);
            var stringWriter = new StringWriter();
            Console.SetOut(stringWriter);
            MgmtPointWmi.AddDeviceToCollection(wmiConnection, deviceName, collectionName);
            StringAssert.Contains(stringWriter.ToString(), $"Name: {deviceName.ToUpper()}");
            TestContext.WriteLine(stringWriter.ToString());
            Cleanup.RemoveCollection(wmiConnection, collectionName);
        }

        [TestMethod]
        public void AddUserToCollection_PrintsUserNameInCollectionMembers()
        {
            /*
            string collectionName = "AddUserToCollection_UnitTest";
            string domainName = Environment.UserDomainName;
            string userName = Environment.UserName;
            string fullUserName = $"{domainName}\\{userName}";
            
            ManagementScope wmiConnection = MgmtUtil.NewWmiConnection();
            TestContext.WriteLine($"User name is {fullUserName}");
            MgmtPointWmi.NewCollection(wmiConnection, "user", collectionName);
            var stringWriter = new StringWriter();
            Console.SetOut(stringWriter);
            MgmtPointWmi.AddUserToCollection(wmiConnection, fullUserName, collectionName);
            StringAssert.Contains(stringWriter.ToString(), $"Name: {fullUserName.ToUpper()}");
            TestContext.WriteLine(stringWriter.ToString());
            //Cleanup.RemoveCollection(wmiConnection, CollectionName);
            */
            Assert.Inconclusive();
        }

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
        public void NewDeployment_PrintsNewDeploymentNameIn_SMS_ApplicationAssignment()
        {
            Assert.Inconclusive();
        }
    }
}
