using System;
using System.Collections.Generic;
using System.Linq;
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
            var config = JweConfigBuilder.AJweEncryptionConfig()
                .WithEncryptionPath("$.payload", "$.encryptedPayload")
                .WithEncryptionCertificate(TestUtils.GetTestEncryptionCertificate())
                .WithDecryptionPath("$.encryptedPayload", "$.payload")
                .WithDecryptionKey(TestUtils.GetTestDecryptionKey())
                .WithEncryptedValueFieldName("encryptedValue")
                .Build();

            Assert.IsNotNull(config);
            Assert.AreEqual(1, config.EncryptionPaths.Count);
            Assert.IsNotNull(config.EncryptionCertificate);
            Assert.AreEqual(1, config.DecryptionPaths.Count);
            Assert.IsNotNull(config.DecryptionKey);
            Assert.AreEqual("encryptedValue", config.EncryptedValueFieldName);
            Assert.AreEqual(EncryptionConfig.EncryptionScheme.Jwe, config.Scheme);
        }

        [TestMethod]
        public void TestBuild_ResultShouldBeAssignableToGenericEncryptionConfig()
        {
            EncryptionConfig config = TestUtils.GetTestJweConfigBuilder().Build();
            Assert.IsNotNull(config);
        }

        [TestMethod]
        public void TestBuild_ShouldComputeCertificateKeyFingerprint_WhenFingerprintNotSet()
        {
            EncryptionConfig config = TestUtils.GetTestJweConfigBuilder().Build();
            Assert.AreEqual("761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79", config.EncryptionKeyFingerprint);
        }

        [TestMethod]
        [ExpectedException(typeof(EncryptionException))]
        public void TestBuild_ShouldThrowEncryptionException_WhenInvalidEncryptionCertificate()
        {
            TestUtils.GetTestJweConfigBuilder()
                .WithEncryptionCertificate(TestUtils.GetTestInvalidEncryptionCertificate() )
                .Build();
        }

        [TestMethod]
        public void TestBuild_ShouldFallbackToDefaults()
        {
            // WHEN
            var config = JweConfigBuilder.AJweEncryptionConfig()
                .WithEncryptionCertificate(TestUtils.GetTestEncryptionCertificate())
                .Build();

            // THEN
            var expectedDecryptionPaths = new Dictionary<string, string> {{"$.encryptedData", "$"}};
            var expectedEncryptionPaths = new Dictionary<string, string> {{ "$", "$" }};
            Assert.AreEqual(expectedDecryptionPaths.Count, config.DecryptionPaths.Count);
            Assert.AreEqual(expectedEncryptionPaths.Count, config.EncryptionPaths.Count);
            Assert.AreEqual(0, expectedDecryptionPaths.Except(config.DecryptionPaths).Count());
            Assert.AreEqual(0, expectedDecryptionPaths.Except(config.DecryptionPaths).Count());
            Assert.AreEqual("encryptedData", config.EncryptedValueFieldName);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestBuild_ShouldThrowArgumentException_WhenMissingDecryptionKey()
        {
            try
            {
                JweConfigBuilder.AJweEncryptionConfig().Build();
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
                JweConfigBuilder.AJweEncryptionConfig()
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
                JweConfigBuilder.AJweEncryptionConfig()
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
