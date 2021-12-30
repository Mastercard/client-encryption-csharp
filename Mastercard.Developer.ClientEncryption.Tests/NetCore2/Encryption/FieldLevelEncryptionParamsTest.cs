using System;
using Mastercard.Developer.ClientEncryption.Core.Encryption;
using Mastercard.Developer.ClientEncryption.Tests.NetCore.Test;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Mastercard.Developer.ClientEncryption.Tests.NetCore.Encryption
{
    [TestClass]
    public class FieldLevelEncryptionParamsTest
    {
        [TestMethod]
        public void TestGenerate_Nominal()
        {
            // GIVEN
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder().Build();

            // WHEN
            var parameters = FieldLevelEncryptionParams.Generate(config);

            // THEN
            Assert.IsNotNull(parameters.IvValue);
            Assert.IsNotNull(parameters.GetIvBytes());
            Assert.IsNotNull(parameters.EncryptedKeyValue);
            Assert.IsNotNull(parameters.GetSecretKeyBytes());
            Assert.AreEqual("SHA256", parameters.OaepPaddingDigestAlgorithmValue);
        }

        [TestMethod]
        [ExpectedException(typeof(EncryptionException))]
        public void TestGetIvBytes_ShouldThrowEncryptionException_WhenFailsToDecodeIV()
        {
            try
            {
                // GIVEN
                var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder().Build();
                var parameters = new FieldLevelEncryptionParams(config, "INVALID VALUE", null);

                // WHEN
                var ivBytes = parameters.GetIvBytes();
                Assert.Fail($"Unexpected {ivBytes}");
            }
            catch (Exception e)
            {
                // THEN
                Assert.AreEqual("Failed to decode the provided IV value!", e.Message);
                throw;
            }
        }

        [TestMethod]
        [ExpectedException(typeof(EncryptionException))]
        public void TestGetSecretKeyBytes_ShouldThrowEncryptionException_WhenFailsToReadEncryptedKey()
        {
            try
            {
                // GIVEN
                var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder().Build();
                var parameters = new FieldLevelEncryptionParams(config, null, "INVALID VALUE");

                // WHEN
                var secretKeyBytes = parameters.GetSecretKeyBytes();
                Assert.Fail($"Unexpected {secretKeyBytes}");
            }
            catch (Exception e)
            {
                // THEN
                Assert.AreEqual("Failed to decode and unwrap the provided secret key value!", e.Message);
                throw;
            }
        }
    }
}
