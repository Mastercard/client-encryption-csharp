using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Mastercard.Developer.ClientEncryption.Core.Encryption;
using Mastercard.Developer.ClientEncryption.Core.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json.Linq;
// ReSharper disable once InconsistentNaming

namespace Mastercard.Developer.ClientEncryption.Tests.Test
{
    internal static class TestUtils
    {
        internal static X509Certificate2 GetTestEncryptionCertificate()
        {
            return EncryptionUtils.LoadEncryptionCertificate("./_Resources/test_certificate.pem");
        }

        internal static X509Certificate2 GetTestInvalidEncryptionCertificate()
        {
            return new X509Certificate2(); // No key
        }

        internal static RSA GetTestDecryptionKey()
        {
            return EncryptionUtils.LoadDecryptionKey("./_Resources/test_key_pkcs8.der");
        }

        internal static FieldLevelEncryptionConfigBuilder GetTestFieldLevelEncryptionConfigBuilder()
        {
            return FieldLevelEncryptionConfigBuilder.AFieldLevelEncryptionConfig()
                .WithEncryptionCertificate(GetTestEncryptionCertificate())
                .WithDecryptionKey(GetTestDecryptionKey())
                .WithOaepPaddingDigestAlgorithm("SHA-256")
                .WithEncryptedValueFieldName("encryptedValue")
                .WithEncryptedKeyFieldName("encryptedKey")
                .WithIvFieldName("iv")
                .WithOaepPaddingDigestAlgorithmFieldName("oaepHashingAlgorithm")
                .WithEncryptionCertificateFingerprintFieldName("encryptionCertificateFingerprint")
                .WithEncryptionCertificateFingerprint("80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279")
                .WithEncryptionKeyFingerprintFieldName("encryptionKeyFingerprint")
                .WithEncryptionKeyFingerprint("761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79")
                .WithValueEncoding(FieldLevelEncryptionConfig.FieldValueEncoding.Hex);
        }

        internal static void AssertDecryptedPayloadEquals(string expectedPayload, string encryptedPayload, FieldLevelEncryptionConfig config)
        {
            var payloadString = FieldLevelEncryption.DecryptPayload(encryptedPayload, config);
            AssertPayloadEquals(expectedPayload, payloadString);
        }

        internal static void AssertPayloadEquals(string expectedPayload, string payload)
        {
            var expectedPayloadObject = JObject.Parse(expectedPayload);
            var payloadObject = JObject.Parse(payload);
            Assert.AreEqual(expectedPayloadObject.ToString(), payloadObject.ToString());
        }
    }
}
