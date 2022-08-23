using Microsoft.ConfigurationManagement.Messaging.Framework;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SharpSCCM.UnitTests
{
    [TestClass]
    public class ClientWmiTests
    {
        [TestMethod]
        public void GetCurrentManagementPointAndSiteCode_Success_ReturnsStrings()
        {
            (string currentManagementPoint, string siteCode) = ClientWmi.GetCurrentManagementPointAndSiteCode();
            Assert.IsInstanceOfType(currentManagementPoint, typeof(string));
            Assert.IsNotNull(currentManagementPoint, "currentManagementPoint != null");
            Assert.IsInstanceOfType(siteCode, typeof(string));
            Assert.IsNotNull(siteCode, "siteCode != null");
            int siteCodeLength = 3;
            Assert.AreEqual(siteCodeLength, siteCode.Length);
        }

        [TestMethod]
        public void GetSmsId_Success_ReturnsSmsClientId()
        {
            SmsClientId smsId = ClientWmi.GetSmsId();
            Assert.IsInstanceOfType(smsId, typeof(SmsClientId));
            Assert.IsNotNull(smsId, "smsId != null");
            StringAssert.Contains(smsId.ToString(), "GUID");
        }
    }
}