using System;
using System.Linq;
using System.Text;
using Mastercard.Developer.ClientEncryption.Core.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Mastercard.Developer.ClientEncryption.Tests.Utils
{
    [TestClass]
    public class EncodingUtilsTest
    {
        [TestMethod]
        public void TestHexEncode()
        {
            Assert.AreEqual("00", EncodingUtils.HexEncode(new byte[1]));
            Assert.AreEqual("736f6d652064617461", EncodingUtils.HexEncode(Encoding.ASCII.GetBytes("some data")));
            Assert.AreEqual("", EncodingUtils.HexEncode(Encoding.ASCII.GetBytes("")));
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void TestHexEncode_ShouldThrowArgumentNullException_WhenNullValue()
        {
            EncodingUtils.HexEncode(null);
        }

        [TestMethod]
        public void TestHexDecode()
        {
            Assert.IsTrue(new byte[1].SequenceEqual(EncodingUtils.HexDecode("00")));
            Assert.IsTrue(Encoding.ASCII.GetBytes("some data").SequenceEqual(EncodingUtils.HexDecode("736f6d652064617461")));
            Assert.IsTrue(Encoding.ASCII.GetBytes("some data").SequenceEqual(EncodingUtils.HexDecode("736F6D652064617461")));
            Assert.IsTrue(Encoding.ASCII.GetBytes("").SequenceEqual(EncodingUtils.HexDecode("")));
        }

        [TestMethod]
        [ExpectedException(typeof(FormatException))]
        public void TestHexDecode_ShouldThrowFormatException_WhenNotAnHexValue()
        {
            EncodingUtils.HexDecode("not an hex string!");
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void TestHexDecode_ShouldThrowArgumentNullException_WhenNullValue()
        {
            EncodingUtils.HexDecode(null);
        }
    }
}
