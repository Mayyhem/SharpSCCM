using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Xml;

namespace SharpSCCM.UnitTests
{
    [TestClass]
    public class HelpersTests
    {
        [TestMethod]
        public void DecompressXMLNodes_NestedXmlDeclaration_ExpandsWithoutDeclaration()
        {
            string nestedXml = "<?xml version=\"1.0\" encoding=\"utf-16\"?><Inner><Value>test</Value></Inner>";
            byte[] nestedXmlBytes = Encoding.Unicode.GetPreamble().Concat(Encoding.Unicode.GetBytes(nestedXml)).ToArray();
            byte[] compressedBytes;

            using (MemoryStream output = new MemoryStream())
            {
                using (GZipStream compressor = new GZipStream(output, CompressionMode.Compress, true))
                {
                    compressor.Write(nestedXmlBytes, 0, nestedXmlBytes.Length);
                }
                compressedBytes = output.ToArray();
            }

            XmlDocument document = new XmlDocument();
            string compressedHex = BitConverter.ToString(compressedBytes).Replace("-", string.Empty);
            document.LoadXml($"<Root><Policy Compression=\"zlib\">{compressedHex}</Policy></Root>");

            Helpers.DecompressXMLNodes(document.DocumentElement);

            Assert.AreEqual("test", document.SelectSingleNode("/Root/Policy/Inner/Value").InnerText);
            Assert.IsFalse(document.OuterXml.Contains("<?xml"));
        }
    }
}
