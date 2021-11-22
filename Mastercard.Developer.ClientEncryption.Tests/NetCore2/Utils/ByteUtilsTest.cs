using System;
using Mastercard.Developer.ClientEncryption.Core.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Mastercard.Developer.ClientEncryption.Tests.NetCore.Utils
{
    [TestClass]
    public class ByteUtilsTest
    {
        [TestMethod]
        public void TestByteCountWithRemainder()
        {
            // GIVEN
            const int bitLength = 33;

            // WHEN
            int byteCount = ByteUtils.ByteCount(bitLength);

            // THEN
            Assert.AreEqual(5, byteCount);
        }

        [TestMethod]
        public void TestByteCountWithoutRemainder()
        {
            // GIVEN
            const int bitLength = 64;

            // WHEN
            int byteCount = ByteUtils.ByteCount(bitLength);

            // THEN
            Assert.AreEqual(8, byteCount);
        }
    }
}
