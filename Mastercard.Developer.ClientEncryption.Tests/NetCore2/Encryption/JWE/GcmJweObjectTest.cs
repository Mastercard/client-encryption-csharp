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
