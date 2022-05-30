using Mastercard.Developer.ClientEncryption.Core.Encryption.JWE;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Mastercard.Developer.ClientEncryption.Tests.NetCore.Test;

namespace Mastercard.Developer.ClientEncryption.Tests.NetCore.Encryption.JWE
{
    [TestClass]
    public class CbcJweObjectTest
    {
        [TestMethod]
        public void TestDecrypt_ShouldReturnDecryptedPayload_WhenPayloadIsCbcEncrypted()
        {
            // GIVEN
            JweObject jweObject = TestUtils.GetTestCbcJweObject();

            // WHEN
            string decryptedPayload = jweObject.Decrypt(TestUtils.GetTestJweConfigBuilder().Build());

            // THEN
            Assert.AreEqual("bar", decryptedPayload);
        }
    }
}
