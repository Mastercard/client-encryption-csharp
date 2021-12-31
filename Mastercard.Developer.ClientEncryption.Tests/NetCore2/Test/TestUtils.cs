using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Mastercard.Developer.ClientEncryption.Core.Encryption;
using Mastercard.Developer.ClientEncryption.Core.Encryption.JWE;
using Mastercard.Developer.ClientEncryption.Core.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json.Linq;
// ReSharper disable once InconsistentNaming

namespace Mastercard.Developer.ClientEncryption.Tests.NetCore.Test
{
    internal static class TestUtils
    {
        internal static X509Certificate2 GetTestEncryptionCertificate()
        {
            return EncryptionUtils.LoadEncryptionCertificate("./_Resources/Certificates/test_certificate-2048.pem");
        }

        internal static X509Certificate2 GetTestInvalidEncryptionCertificate() => new X509Certificate2(); // No key

        internal static RSA GetTestDecryptionKey()
        {
            return EncryptionUtils.LoadDecryptionKey("./_Resources/Keys/Pkcs8/test_key_pkcs8-2048.der");
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
            var expectedPayloadToken = JToken.Parse(expectedPayload);
            var payloadToken = JToken.Parse(payload);
            Assert.AreEqual(expectedPayloadToken.ToString(), payloadToken.ToString());
        }

        internal static JweConfigBuilder GetTestJweConfigBuilder()
        {
            return JweConfigBuilder.AJweEncryptionConfig()
                .WithEncryptionCertificate(TestUtils.GetTestEncryptionCertificate())
                .WithDecryptionKey(TestUtils.GetTestDecryptionKey());
        }

        internal static JweObject GetTestCbcJweObject()
        {
            return JweObject.Parse("eyJraWQiOiI3NjFiMDAzYzFlYWRlM2E1NDkwZTUwMDBkMzc4ODdiYWE1ZTZlYzBlMjI2YzA3NzA2ZTU5OTQ1MWZjMDMyYTc5IiwiY3R5IjoiYXBwbGljYXRpb25cL2pzb24iLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.5bsamlChk0HR3Nqg2UPJ2Fw4Y0MvC2pwWzNv84jYGkOXyqp1iwQSgETGaplIa7JyLg1ZWOqwNHEx3N7gsN4nzwAnVgz0eta6SsoQUE9YQ-5jek0COslUkoqIQjlQYJnYur7pqttDibj87fcw13G2agle5fL99j1QgFPjNPYqH88DMv481XGFa8O3VfJhW93m73KD2gvE5GasOPOkFK9wjKXc9lMGSgSArp3Awbc_oS2Cho_SbsvuEQwkhnQc2JKT3IaSWu8yK7edNGwD6OZJLhMJzWJlY30dUt2Eqe1r6kMT0IDRl7jHJnVIr2Qpe56CyeZ9V0aC5RH1mI5dYk4kHg.yI0CS3NdBrz9CCW2jwBSDw.6zr2pOSmAGdlJG0gbH53Eg.UFgf3-P9UjgMocEu7QA_vQ");
        }

        internal static JweObject GetTestGcmJweObject()
        {
            return JweObject.Parse("eyJraWQiOiI3NjFiMDAzYzFlYWRlM2E1NDkwZTUwMDBkMzc4ODdiYWE1ZTZlYzBlMjI2YzA3NzA2ZTU5OTQ1MWZjMDMyYTc5IiwiY3R5IjoiYXBwbGljYXRpb25cL2pzb24iLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.8c6vxeZOUBS8A9SXYUSrRnfl1ht9xxciB7TAEv84etZhQQ2civQKso-htpa2DWFBSUm-UYlxb6XtXNXZxuWu-A0WXjwi1K5ZAACc8KUoYnqPldEtC9Q2bhbQgc_qZF_GxeKrOZfuXc9oi45xfVysF_db4RZ6VkLvY2YpPeDGEMX_nLEjzqKaDz_2m0Ae_nknr0p_Nu0m5UJgMzZGR4Sk1DJWa9x-WJLEyo4w_nRDThOjHJshOHaOU6qR5rdEAZr_dwqnTHrjX9Qm9N9gflPGMaJNVa4mvpsjz6LJzjaW3nJ2yCoirbaeJyCrful6cCiwMWMaDMuiBDPKa2ovVTy0Sw.w0Nkjxl0T9HHNu4R.suRZaYu6Ui05Z3-vsw.akknMr3Dl4L0VVTGPUszcA");
        }
    }
}
