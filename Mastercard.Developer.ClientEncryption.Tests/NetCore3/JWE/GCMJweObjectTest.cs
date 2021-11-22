using System;
using Mastercard.Developer.ClientEncryption.Core.Encryption.JWE;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Mastercard.Developer.ClientEncryption.Tests.NetCore.Test;

namespace Mastercard.Developer.ClientEncryption.Tests.NetCore.Encryption.JWE
{
    [TestClass]
    public class GCMJweObjectTest
    {
        [TestMethod]
        public void TestDecrypt_ShouldReturnDecryptedPayload_WhenPayloadIsGcmEncrypted()
        {
            // GIVEN
            JweObject jweObject = TestUtils.GetTestGcmJweObject();

            // WHEN
            string decryptedPayload = jweObject.Decrypt(TestUtils.GetTestJweConfigBuilder().Build());

            // THEN
            Assert.AreEqual("{\"foo\":\"bar\"}", decryptedPayload);
        }
    }
}
