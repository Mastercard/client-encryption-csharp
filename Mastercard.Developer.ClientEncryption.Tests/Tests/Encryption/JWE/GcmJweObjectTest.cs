using Mastercard.Developer.ClientEncryption.Core.Encryption;
using Mastercard.Developer.ClientEncryption.Core.Encryption.JWE;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Mastercard.Developer.ClientEncryption.Tests.NetCore.Test;

namespace Mastercard.Developer.ClientEncryption.Tests.NetCore.Encryption.JWE
{
    [TestClass]
    public class GcmJweObjectTest
    {
        [TestMethod]
#if !NETCOREAPP3_1 && !NET5_0_OR_GREATER
        [ExpectedException(typeof(EncryptionException), "AES/GCM/NoPadding is unsupported on .NET Standard < 2.1")]
#endif
        public void TestDecrypt_ShouldReturnDecryptedPayload_WhenPayloadIs256GcmEncrypted()
        {
            // GIVEN
            JweObject jweObject = TestUtils.GetTest256GcmJweObject();

            // WHEN
            string decryptedPayload = jweObject.Decrypt(TestUtils.GetTestJweConfigBuilder().Build());

            // THEN
            Assert.AreEqual("{\"foo\":\"bar\"}", decryptedPayload);
        }

        public void TestDecrypt_ShouldReturnDecryptedPayload_WhenPayloadIs192GcmEncrypted()
        {
            // GIVEN
            JweObject jweObject = TestUtils.GetTest192GcmJweObject();

            // WHEN
            string decryptedPayload = jweObject.Decrypt(TestUtils.GetTestJweConfigBuilder().Build());

            // THEN
            Assert.AreEqual("{\"foo\":\"bar\"}", decryptedPayload);
        }

        public void TestDecrypt_ShouldReturnDecryptedPayload_WhenPayloadIs128GcmEncrypted()
        {
            // GIVEN
            JweObject jweObject = TestUtils.GetTest128GcmJweObject();

            // WHEN
            string decryptedPayload = jweObject.Decrypt(TestUtils.GetTestJweConfigBuilder().Build());

            // THEN
            Assert.AreEqual("{\"foo\":\"bar\"}", decryptedPayload);
        }
    }
}
