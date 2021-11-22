using System;
using Mastercard.Developer.ClientEncryption.Core.Encryption;
using Mastercard.Developer.ClientEncryption.Tests.NetCore.Test;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Mastercard.Developer.ClientEncryption.Tests.NetCore.Encryption
{
    [TestClass]
    public class JweConfigBuilderTest
    {
        [TestMethod]
        public void TestBuild_Nominal()
        {
            var config = JweConfigBuilder.AJweConfigBuilder()
                .WithEncryptionPath("$.payload", "$.encryptedPayload")
                .WithEncryptionCertificate(TestUtils.GetTestEncryptionCertificate())
                .WithEncryptionKeyFingerprint("F806B26BC4870E26986C70B6590AF87BAF4C2B56BB50622C51B12212DAFF2810")
                .WithDecryptionPath("$.encryptedPayload", "$.payload")
                .WithDecryptionKey(TestUtils.GetTestDecryptionKey())
                .WithOaepPaddingDigestAlgorithm("SHA-512")
                .WithEncryptedValueFieldName("encryptedValue")
                .Build();

            Assert.IsNotNull(config);
            Assert.AreEqual(1, config.EncryptionPaths.Count);
            Assert.IsNotNull(config.EncryptionCertificate);
            Assert.AreEqual("F806B26BC4870E26986C70B6590AF87BAF4C2B56BB50622C51B12212DAFF2810", config.EncryptionKeyFingerprint);
            Assert.AreEqual(1, config.DecryptionPaths.Count);
            Assert.IsNotNull(config.DecryptionKey);
            Assert.AreEqual("SHA-512", config.OaepPaddingDigestAlgorithm);
            Assert.AreEqual("encryptedValue", config.EncryptedValueFieldName);
        }

        [TestMethod]
        public void TestBuild_ResultShouldBeAssignableToGenericEncryptionConfig()
        {
            EncryptionConfig config = TestUtils.GetTestJweConfigBuilder().Build();
            Assert.IsNotNull(config);
        }

        [TestMethod]
        public void TestBuild_ResultShouldHaveJWESchemeSet()
        {
            EncryptionConfig config = TestUtils.GetTestJweConfigBuilder().Build();
            Assert.AreEqual(EncryptionConfig.EncryptionScheme.Jwe, config.Scheme);
        }

        [TestMethod]
        public void TestBuild_ShouldComputeCertificateKeyFingerprints_WhenFingerprintsNotSet()
        {
            EncryptionConfig config = TestUtils.GetTestJweConfigBuilder().Build();
            Assert.AreEqual("761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79", config.EncryptionKeyFingerprint);
        }

        [TestMethod]
        [ExpectedException(typeof(EncryptionException))]
        public void TestBuild_ShouldThrowEncryptionException_WhenInvalidEncryptionCertficate()
        {
            TestUtils.GetTestJweConfigBuilder()
                .WithEncryptionCertificate(TestUtils.GetTestInvalidEncryptionCertificate())
                .Build();
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestBuild_ShouldThrowArgumentException_WhenMissingDecryptionKey()
        {
            try
            {
                JweConfigBuilder.AJweConfigBuilder().Build();
            }
            catch (Exception e)
            {
                Assert.AreEqual("You must include at least an encryption certificate or a decryption key", e.Message);
                throw;
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestBuild_ShouldThrowArgumentException_WhenNotDefiniteDecryptionPath()
        {
            try
            {
                JweConfigBuilder.AJweConfigBuilder()
                    .WithDecryptionPath("$.encryptedPayloads[*]", "$.payload")
                    .WithDecryptionKey(TestUtils.GetTestDecryptionKey())
                    .Build();
            }
            catch (Exception e)
            {
                Assert.AreEqual("JSON paths for decryption must point to a single item!", e.Message);
                throw;
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestBuild_ShouldThrowArgumentException_WhenNotDefiniteEncryptionPath()
        {
            try
            {
                JweConfigBuilder.AJweConfigBuilder()
                    .WithEncryptionPath("$.payloads[*]", "$.encryptedPayload")
                    .WithEncryptionCertificate(TestUtils.GetTestEncryptionCertificate())
                    .Build();
            }
            catch (Exception e)
            {
                Assert.AreEqual("JSON paths for encryption must point to a single item!", e.Message);
                throw;
            }
        }
    }
}
