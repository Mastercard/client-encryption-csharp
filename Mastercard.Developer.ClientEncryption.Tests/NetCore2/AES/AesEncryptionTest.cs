using System;
using Mastercard.Developer.ClientEncryption.Core.Encryption.AES;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Mastercard.Developer.ClientEncryption.Tests.NetCore.AES
{
    [TestClass]
    public class AesEncryptionTest
    {
        [TestMethod]
        public void TestGenerateIV()
        {
            // WHEN
            byte[] iv = AesEncryption.GenerateIV();

            // THEN
            Assert.AreEqual(12, iv.Length);
        }

        [TestMethod]
        public void TestGenerateCek()
        {
            // WHEN
            byte[] cek = AesEncryption.GenerateCek(256);

            // THEN
            Assert.AreEqual(32, cek.Length);
        }
    }
}
