using System;
using System.IO;
using Mastercard.Developer.ClientEncryption.Core.Encryption;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Mastercard.Developer.ClientEncryption.Tests.Encryption
{
    [TestClass]
    public class EncryptionExceptionTest
    {
        [TestMethod]
        public void TestConstructor1()
        {
            try
            {
                throw new EncryptionException("Something happened!", new IOException());
            }
            catch (Exception e)
            {
                Assert.AreEqual("Something happened!", e.Message);
                Assert.IsTrue(e.InnerException is IOException);
            }
        }

        [TestMethod]
        public void TestConstructor2()
        {
            try
            {
                throw new EncryptionException("Something happened!");
            }
            catch (Exception e)
            {
                Assert.AreEqual("Something happened!", e.Message);
                Assert.IsNull(e.InnerException);
            }
        }
    }
}