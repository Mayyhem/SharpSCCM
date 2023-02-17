using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Management;

namespace SharpSCCM.UnitTests
{
    [TestClass]
    public class MgmtUtilTests
    {
        [TestMethod]
        public void BuildClassInstanceQueryString_Success_ReturnsString()
        {
            ManagementScope wmiConnection = MgmtUtil.NewWmiConnection("localhost");
            string query = MgmtUtil.BuildClassInstanceQueryString(wmiConnection, "SMS_Authority");
            Assert.IsInstanceOfType(query, typeof(string));
            Assert.IsNotNull(query, "query != null");
            StringAssert.StartsWith(query, "SELECT");
        }

        [TestMethod]
        public void GetClassInstances_Success_ReturnsManagementObjectCollection()
        {
            ManagementScope wmiConnection = MgmtUtil.NewWmiConnection("localhost");
            string query = MgmtUtil.BuildClassInstanceQueryString(wmiConnection, "SMS_Authority");
            ManagementObjectCollection classInstanceCollection = MgmtUtil.GetClassInstances(wmiConnection, "SMS_Authority", query, printOutput: true);
            Assert.IsInstanceOfType(classInstanceCollection, typeof(ManagementObjectCollection));
            Assert.IsNotNull(classInstanceCollection, "classInstanceCollection != null");
        }

        [TestMethod]
        public void GetClassInstances_DryRun_PrintsQuery()
        {

            ManagementScope wmiConnection = MgmtUtil.NewWmiConnection("localhost");
            string query = MgmtUtil.BuildClassInstanceQueryString(wmiConnection, "SMS_Authority");
            var stringWriter = new StringWriter();
            Console.SetOut(stringWriter);
            MgmtUtil.GetClassInstances(wmiConnection, "SMS_Authority", null, false, null, null, null, true, printOutput: true);
            string expectedOutput = $"[+] WQL query: {query}";
            Assert.AreEqual(expectedOutput.Trim(), stringWriter.ToString().Trim());
        }

        [TestMethod]
        public void GetClassInstances_NotDryRun_PrintsClasses()
        {
            ManagementScope wmiConnection = MgmtUtil.NewWmiConnection("localhost");
            var stringWriter = new StringWriter();
            Console.SetOut(stringWriter);
            MgmtUtil.GetClassInstances(wmiConnection, "SMS_Authority", printOutput: true);
            StringAssert.Contains( stringWriter.ToString(), "CurrentManagementPoint");
        }

        [TestMethod]
        public void GetKeyPropertyNames_Success_ReturnsStringArray()
        {
            ManagementScope wmiConnection = MgmtUtil.NewWmiConnection("localhost");
            string[] keyProperties = MgmtUtil.GetKeyPropertyNames(wmiConnection, "SMS_Authority");
            Assert.IsInstanceOfType(keyProperties, typeof(string[]));
            StringAssert.Contains(keyProperties[0], "Name");
        }
    }
}