using System;
using Mastercard.Developer.ClientEncryption.Core.Encryption;
using Mastercard.Developer.ClientEncryption.Tests.NetCore.Test;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using static Mastercard.Developer.ClientEncryption.Core.Encryption.FieldLevelEncryptionConfig;

namespace Mastercard.Developer.ClientEncryption.Tests.NetCore.Encryption
{
    [TestClass]
    public class FieldLevelEncryptionConfigBuilderTest
    {
        [TestMethod]
        public void TestBuild_Nominal()
        {
            var config = FieldLevelEncryptionConfigBuilder.AFieldLevelEncryptionConfig()
                .WithEncryptionPath("$.payload", "$.encryptedPayload")
                .WithEncryptionCertificate(TestUtils.GetTestEncryptionCertificate())
                .WithEncryptionCertificateFingerprint("97A2FFE9F0D48960EF31E87FCD7A55BF7843FB4A9EEEF01BDB6032AD6FEF146B")
                .WithEncryptionKeyFingerprint("F806B26BC4870E26986C70B6590AF87BAF4C2B56BB50622C51B12212DAFF2810")
                .WithEncryptionCertificateFingerprintFieldName("publicCertificateFingerprint")
                .WithEncryptionCertificateFingerprintHeaderName("x-public-certificate-fingerprint")
                .WithEncryptionKeyFingerprintFieldName("publicKeyFingerprint")
                .WithEncryptionKeyFingerprintHeaderName("x-public-key-fingerprint")
                .WithDecryptionPath("$.encryptedPayload", "$.payload")
                .WithDecryptionKey(TestUtils.GetTestDecryptionKey())
                .WithOaepPaddingDigestAlgorithm("SHA-512")
                .WithOaepPaddingDigestAlgorithmFieldName("oaepPaddingDigestAlgorithm")
                .WithOaepPaddingDigestAlgorithmHeaderName("x-oaep-padding-digest-algorithm")
                .WithEncryptedValueFieldName("encryptedValue")
                .WithEncryptedKeyFieldName("encryptedKey")
                .WithEncryptedKeyHeaderName("x-encrypted-key")
                .WithIvFieldName("iv")
                .WithIvHeaderName("x-iv")
                .WithValueEncoding(FieldValueEncoding.Base64)
                .Build();
            Assert.IsNotNull(config);
            Assert.AreEqual(1, config.EncryptionPaths.Count);
            Assert.IsNotNull(config.EncryptionCertificate);
            Assert.AreEqual("97A2FFE9F0D48960EF31E87FCD7A55BF7843FB4A9EEEF01BDB6032AD6FEF146B", config.EncryptionCertificateFingerprint);
            Assert.AreEqual("F806B26BC4870E26986C70B6590AF87BAF4C2B56BB50622C51B12212DAFF2810", config.EncryptionKeyFingerprint);
            Assert.AreEqual("publicCertificateFingerprint", config.EncryptionCertificateFingerprintFieldName);
            Assert.AreEqual("x-public-certificate-fingerprint", config.EncryptionCertificateFingerprintHeaderName);
            Assert.AreEqual("publicKeyFingerprint", config.EncryptionKeyFingerprintFieldName);
            Assert.AreEqual("x-public-key-fingerprint", config.EncryptionKeyFingerprintHeaderName);
            Assert.AreEqual(1, config.DecryptionPaths.Count);
            Assert.IsNotNull(config.DecryptionKey);
            Assert.AreEqual("SHA-512", config.OaepPaddingDigestAlgorithm);
            Assert.AreEqual("encryptedValue", config.EncryptedValueFieldName);
            Assert.AreEqual("encryptedKey", config.EncryptedKeyFieldName);
            Assert.AreEqual("x-encrypted-key", config.EncryptedKeyHeaderName);
            Assert.AreEqual("iv", config.IvFieldName);
            Assert.AreEqual("x-iv", config.IvHeaderName);
            Assert.AreEqual("oaepPaddingDigestAlgorithm", config.OaepPaddingDigestAlgorithmFieldName);
            Assert.AreEqual("x-oaep-padding-digest-algorithm", config.OaepPaddingDigestAlgorithmHeaderName);
            Assert.AreEqual(FieldValueEncoding.Base64, config.ValueEncoding);
        }

        [TestMethod]
        public void TestBuild_ShouldComputeCertificateAndKeyFingerprints_WhenFingerprintsNotSetInConfig()
        {
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithEncryptionCertificateFingerprint(null)
                .WithEncryptionKeyFingerprint(null)
                .WithEncryptionCertificate(TestUtils.GetTestEncryptionCertificate())
                .WithDecryptionKey(TestUtils.GetTestDecryptionKey())
                .Build();

            Assert.AreEqual("761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79", config.EncryptionKeyFingerprint);
            Assert.AreEqual("80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279", config.EncryptionCertificateFingerprint);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestBuild_ShouldThrowArgumentException_WhenNotDefiniteDecryptionPath()
        {
            try
            {
                FieldLevelEncryptionConfigBuilder.AFieldLevelEncryptionConfig()
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
        public void TestBuild_ShouldThrowArgumentException_WhenMissingDecryptionKey()
        {
            try
            {
                FieldLevelEncryptionConfigBuilder.AFieldLevelEncryptionConfig()
                    .WithDecryptionPath("$.encryptedPayload", "$.payload")
                    .WithOaepPaddingDigestAlgorithm("SHA-512")
                    .WithEncryptedValueFieldName("encryptedValue")
                    .WithEncryptedKeyFieldName("encryptedKey")
                    .WithIvFieldName("iv")
                    .WithValueEncoding(FieldValueEncoding.Hex)
                    .Build();
            }
            catch (Exception e)
            {
                Assert.AreEqual("Can't decrypt without decryption key!", e.Message);
                throw;
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestBuild_ShouldThrowArgumentException_WhenNotDefiniteEncryptionPath()
        {
            try
            {
                FieldLevelEncryptionConfigBuilder.AFieldLevelEncryptionConfig()
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

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestBuild_ShouldThrowArgumentException_WhenMissingEncryptionCertificate()
        {
            try
            {
                FieldLevelEncryptionConfigBuilder.AFieldLevelEncryptionConfig()
                    .WithEncryptionPath("$.payload", "$.encryptedPayload")
                    .WithOaepPaddingDigestAlgorithm("SHA-512")
                    .WithEncryptedValueFieldName("encryptedValue")
                    .WithEncryptedKeyFieldName("encryptedKey")
                    .WithIvFieldName("iv")
                    .WithValueEncoding(FieldValueEncoding.Hex)
                    .Build();
            }
            catch (Exception e)
            {
                Assert.AreEqual("Can't encrypt without encryption key!", e.Message);
                throw;
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestBuild_ShouldThrowArgumentException_WhenMissingOaepPaddingDigestAlgorithm()
        {
            try
            {
                FieldLevelEncryptionConfigBuilder.AFieldLevelEncryptionConfig()
                    .WithEncryptedValueFieldName("encryptedValue")
                    .WithEncryptedKeyFieldName("encryptedKey")
                    .WithIvFieldName("iv")
                    .WithValueEncoding(FieldValueEncoding.Hex)
                    .Build();
            }
            catch (Exception e)
            {
                Assert.AreEqual("The digest algorithm for OAEP cannot be null!", e.Message);
                throw;
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestBuild_ShouldThrowArgumentException_WhenUnsupportedOaepPaddingDigestAlgorithm()
        {
            try
            {
                FieldLevelEncryptionConfigBuilder.AFieldLevelEncryptionConfig()
                    .WithOaepPaddingDigestAlgorithm("SHA-720")
                    .Build();
            }
            catch (Exception e)
            {
                Assert.AreEqual("Unsupported OAEP digest algorithm: SHA-720!", e.Message);
                throw;
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestBuild_ShouldThrowArgumentException_WhenMissingEncryptedValueFieldName()
        {
            try
            {
                FieldLevelEncryptionConfigBuilder.AFieldLevelEncryptionConfig()
                    .WithOaepPaddingDigestAlgorithm("SHA-512")
                    .WithEncryptedKeyFieldName("encryptedKey")
                    .WithIvFieldName("iv")
                    .WithValueEncoding(FieldValueEncoding.Hex)
                    .Build();
            }
            catch (Exception e)
            {
                Assert.AreEqual("Encrypted value field name cannot be null!", e.Message);
                throw;
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestBuild_ShouldThrowArgumentException_WhenMissingBothEncryptedKeyFieldNameAndHeaderName()
        {
            try
            {
                FieldLevelEncryptionConfigBuilder.AFieldLevelEncryptionConfig()
                    .WithOaepPaddingDigestAlgorithm("SHA-512")
                    .WithEncryptedValueFieldName("encryptedValue")
                    .WithIvFieldName("iv")
                    .WithValueEncoding(FieldValueEncoding.Hex)
                    .Build();
            }
            catch (Exception e)
            {
                Assert.AreEqual("At least one of encrypted key field name or encrypted key header name must be set!", e.Message);
                throw;
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestBuild_ShouldThrowArgumentException_WhenMissingBothIvFieldNameAndHeaderName()
        {
            try
            {
                FieldLevelEncryptionConfigBuilder.AFieldLevelEncryptionConfig()
                    .WithOaepPaddingDigestAlgorithm("SHA-512")
                    .WithEncryptedValueFieldName("encryptedValue")
                    .WithEncryptedKeyFieldName("encryptedKey")
                    .WithValueEncoding(FieldValueEncoding.Hex)
                    .Build();
            }
            catch (Exception e)
            {
                Assert.AreEqual("At least one of IV field name or IV header name must be set!", e.Message);
                throw;
            }
        }
        
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestBuild_ShouldThrowArgumentException_WhenEncryptedKeyAndIvHeaderNamesNotBothSetOrUnset()
        {
            try
            {
                FieldLevelEncryptionConfigBuilder.AFieldLevelEncryptionConfig()
                    .WithOaepPaddingDigestAlgorithm("SHA-512")
                    .WithEncryptedValueFieldName("encryptedValue")
                    .WithEncryptedKeyHeaderName("x-encrypted-key")
                    .WithEncryptedKeyFieldName("encryptedKey")
                    .WithIvFieldName("iv")
                    .WithValueEncoding(FieldValueEncoding.Hex)
                    .Build();
            }
            catch (Exception e)
            {
                Assert.AreEqual("IV header name and encrypted key header name must be both set or both unset!", e.Message);
                throw;
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestBuild_ShouldThrowArgumentException_WhenEncryptedKeyAndIvFieldNamesNotBothSetOrUnset()
        {
            try
            {
                FieldLevelEncryptionConfigBuilder.AFieldLevelEncryptionConfig()
                    .WithOaepPaddingDigestAlgorithm("SHA-512")
                    .WithEncryptedValueFieldName("encryptedValue")
                    .WithEncryptedKeyFieldName("encryptedKey")
                    .WithEncryptedKeyHeaderName("x-encrypted-key")
                    .WithIvHeaderName("x-iv")
                    .WithValueEncoding(FieldValueEncoding.Hex)
                    .Build();
            }
            catch (Exception e)
            {
                Assert.AreEqual("IV field name and encrypted key field name must be both set or both unset!", e.Message);
                throw;
            }
        }
    }
}
