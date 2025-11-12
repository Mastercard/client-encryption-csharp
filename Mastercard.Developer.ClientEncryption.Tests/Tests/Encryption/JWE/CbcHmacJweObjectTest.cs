using System;
using Mastercard.Developer.ClientEncryption.Core.Encryption;
using Mastercard.Developer.ClientEncryption.Core.Encryption.JWE;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Mastercard.Developer.ClientEncryption.Tests.NetCore.Test;

namespace Mastercard.Developer.ClientEncryption.Tests.NetCore.Encryption.JWE
{
    [TestClass]
    public class CbcHmacJweObjectTest
    {
        [TestMethod]
        public void TestDecrypt_ShouldWorkWithoutHmacVerification_WhenHmacDisabledByDefault()
        {
            // GIVEN - Default config without HMAC enabled
            JweObject jweObject = TestUtils.GetTestCbcJweObject();
            var config = TestUtils.GetTestJweConfigBuilder().Build();

            // WHEN
            string decryptedPayload = jweObject.Decrypt(config);

            // THEN
            Assert.AreEqual("bar", decryptedPayload);
            Assert.IsFalse(config.EnableCbcHmacVerification, "HMAC verification should be disabled by default");
        }

        [TestMethod]
        public void TestDecrypt_ShouldWorkWithoutHmacVerification_WhenExplicitlyDisabled()
        {
            // GIVEN
            JweObject jweObject = TestUtils.GetTestCbcJweObject();
            var config = TestUtils.GetTestJweConfigBuilder()
                .WithCbcHmacVerification(false)
                .Build();

            // WHEN
            string decryptedPayload = jweObject.Decrypt(config);

            // THEN
            Assert.AreEqual("bar", decryptedPayload);
            Assert.IsFalse(config.EnableCbcHmacVerification);
        }

        [TestMethod]
        public void TestEncryptDecrypt_A128CBC_HS256_WithHmacEnabled()
        {
            // GIVEN
            var config = TestUtils.GetTestJweConfigBuilder()
                .WithCbcHmacVerification(true)
                .Build();

            var header = new JweHeader("RSA-OAEP-256", "A128CBC-HS256", config.EncryptionKeyFingerprint, "application/json");

            string payload = "{\"test\":\"data\"}";

            // WHEN - Encrypt with HMAC
            string encrypted = JweObject.Encrypt(config, payload, header);
            
            // THEN - Decrypt with HMAC verification
            var jweObject = JweObject.Parse(encrypted);
            string decrypted = jweObject.Decrypt(config);

            Assert.AreEqual(payload, decrypted);
            Assert.IsTrue(config.EnableCbcHmacVerification);
        }

        [TestMethod]
        public void TestEncryptDecrypt_A192CBC_HS384_WithHmacEnabled()
        {
            // GIVEN
            var config = TestUtils.GetTestJweConfigBuilder()
                .WithCbcHmacVerification(true)
                .Build();

            var header = new JweHeader("RSA-OAEP-256", "A192CBC-HS384", config.EncryptionKeyFingerprint, "application/json");

            string payload = "{\"accountNumber\":\"1234567890\"}";

            // WHEN - Encrypt with HMAC
            string encrypted = JweObject.Encrypt(config, payload, header);
            
            // THEN - Decrypt with HMAC verification
            var jweObject = JweObject.Parse(encrypted);
            string decrypted = jweObject.Decrypt(config);

            Assert.AreEqual(payload, decrypted);
        }

        [TestMethod]
        public void TestEncryptDecrypt_A256CBC_HS512_WithHmacEnabled()
        {
            // GIVEN
            var config = TestUtils.GetTestJweConfigBuilder()
                .WithCbcHmacVerification(true)
                .Build();

            var header = new JweHeader("RSA-OAEP-256", "A256CBC-HS512", config.EncryptionKeyFingerprint, "application/json");

            string payload = "{\"sensitiveData\":\"secret\"}";

            // WHEN - Encrypt with HMAC
            string encrypted = JweObject.Encrypt(config, payload, header);
            
            // THEN - Decrypt with HMAC verification
            var jweObject = JweObject.Parse(encrypted);
            string decrypted = jweObject.Decrypt(config);

            Assert.AreEqual(payload, decrypted);
        }

        [TestMethod]
        public void TestEncryptDecrypt_WithHmacDisabled_ShouldStillWork()
        {
            // GIVEN - HMAC explicitly disabled
            var config = TestUtils.GetTestJweConfigBuilder()
                .WithCbcHmacVerification(false)
                .Build();

            var header = new JweHeader("RSA-OAEP-256", "A128CBC-HS256", config.EncryptionKeyFingerprint, null);

            string payload = "{\"test\":\"backward-compatible\"}";

            // WHEN
            string encrypted = JweObject.Encrypt(config, payload, header);
            var jweObject = JweObject.Parse(encrypted);
            string decrypted = jweObject.Decrypt(config);

            // THEN
            Assert.AreEqual(payload, decrypted);
        }

        [TestMethod]
        public void TestDecrypt_ShouldThrowException_WhenHmacVerificationFailsDueToCiphertextTampering()
        {
            // GIVEN - Encrypt with HMAC enabled
            var config = TestUtils.GetTestJweConfigBuilder()
                .WithCbcHmacVerification(true)
                .Build();

            var header = new JweHeader("RSA-OAEP-256", "A128CBC-HS256", config.EncryptionKeyFingerprint, null);

            string payload = "{\"test\":\"data\"}";
            string encrypted = JweObject.Encrypt(config, payload, header);

            // Tamper with the ciphertext
            var parts = encrypted.Split('.');
            // Corrupt one character in the ciphertext (part 3)
            var tamperedCiphertext = parts[3].Substring(0, parts[3].Length - 1) + "X";
            var tamperedJwe = $"{parts[0]}.{parts[1]}.{parts[2]}.{tamperedCiphertext}.{parts[4]}";

            var jweObject = JweObject.Parse(tamperedJwe);

            // WHEN/THEN - Should throw exception due to HMAC verification failure
            try
            {
                jweObject.Decrypt(config);
                Assert.Fail("Expected EncryptionException to be thrown");
            }
            catch (EncryptionException ex)
            {
                Assert.IsTrue(ex.Message.Contains("HMAC verification failed"), 
                    $"Expected HMAC verification failure, but got: {ex.Message}");
            }
        }

        [TestMethod]
        [ExpectedException(typeof(EncryptionException), "HMAC verification failed")]
        public void TestDecrypt_ShouldThrowException_WhenHmacVerificationFailsDueToAuthTagTampering()
        {
            // GIVEN - Encrypt with HMAC enabled
            var config = TestUtils.GetTestJweConfigBuilder()
                .WithCbcHmacVerification(true)
                .Build();

            var header = new JweHeader("RSA-OAEP-256", "A256CBC-HS512", config.EncryptionKeyFingerprint, null);

            string payload = "{\"test\":\"data\"}";
            string encrypted = JweObject.Encrypt(config, payload, header);

            // Tamper with the authentication tag
            var parts = encrypted.Split('.');
            // Corrupt one character in the auth tag (part 4)
            var tamperedAuthTag = parts[4].Substring(0, parts[4].Length - 1) + "Y";
            var tamperedJwe = $"{parts[0]}.{parts[1]}.{parts[2]}.{parts[3]}.{tamperedAuthTag}";

            var jweObject = JweObject.Parse(tamperedJwe);

            // WHEN/THEN - Should throw exception due to HMAC verification failure
            jweObject.Decrypt(config);
        }

        [TestMethod]
        public void TestDecrypt_ShouldNotThrowHmacException_WhenHmacDisabledAndCiphertextTampered()
        {
            // GIVEN - Encrypt with HMAC disabled
            var config = TestUtils.GetTestJweConfigBuilder()
                .WithCbcHmacVerification(false)
                .Build();

            var header = new JweHeader("RSA-OAEP-256", "A128CBC-HS256", config.EncryptionKeyFingerprint, null);

            string payload = "{\"test\":\"data\"}";
            string encrypted = JweObject.Encrypt(config, payload, header);

            // Tamper with the ciphertext
            var parts = encrypted.Split('.');
            var tamperedCiphertext = parts[3].Substring(0, parts[3].Length - 1) + "X";
            var tamperedJwe = $"{parts[0]}.{parts[1]}.{parts[2]}.{tamperedCiphertext}.{parts[4]}";

            var jweObject = JweObject.Parse(tamperedJwe);

            // WHEN/THEN - Should not throw HMAC exception (but will fail with padding/decryption error)
            bool caughtException = false;
            try
            {
                jweObject.Decrypt(config);
            }
            catch (Exception ex)
            {
                caughtException = true;
                // Should NOT be HMAC verification failure (but could be padding or other crypto exception)
                Assert.IsFalse(ex.Message.Contains("HMAC verification failed"),
                    "Should not fail due to HMAC when HMAC is disabled. Got: " + ex.Message);
            }
            
            // Tampering should cause some kind of failure (padding, decryption, etc.) but not HMAC
            Assert.IsTrue(caughtException, "Expected some exception due to tampering");
        }

        [TestMethod]
        public void TestConfigBuilder_ShouldDefaultToHmacDisabled()
        {
            // GIVEN/WHEN
            var config = TestUtils.GetTestJweConfigBuilder().Build();

            // THEN
            Assert.IsFalse(config.EnableCbcHmacVerification,
                "HMAC verification should be disabled by default for backward compatibility");
        }

        [TestMethod]
        public void TestConfigBuilder_WithCbcHmacVerification_ShouldEnableHmac()
        {
            // GIVEN/WHEN
            var config = TestUtils.GetTestJweConfigBuilder()
                .WithCbcHmacVerification()
                .Build();

            // THEN
            Assert.IsTrue(config.EnableCbcHmacVerification);
        }

        [TestMethod]
        public void TestConfigBuilder_WithCbcHmacVerificationTrue_ShouldEnableHmac()
        {
            // GIVEN/WHEN
            var config = TestUtils.GetTestJweConfigBuilder()
                .WithCbcHmacVerification(true)
                .Build();

            // THEN
            Assert.IsTrue(config.EnableCbcHmacVerification);
        }

        [TestMethod]
        public void TestConfigBuilder_WithCbcHmacVerificationFalse_ShouldDisableHmac()
        {
            // GIVEN/WHEN
            var config = TestUtils.GetTestJweConfigBuilder()
                .WithCbcHmacVerification(false)
                .Build();

            // THEN
            Assert.IsFalse(config.EnableCbcHmacVerification);
        }

        [TestMethod]
        public void TestEncrypt_MultipleTimes_WithHmacEnabled_ShouldProduceDifferentCiphertext()
        {
            // GIVEN
            var config = TestUtils.GetTestJweConfigBuilder()
                .WithCbcHmacVerification(true)
                .Build();

            var header = new JweHeader("RSA-OAEP-256", "A128CBC-HS256", config.EncryptionKeyFingerprint, null);

            string payload = "{\"test\":\"data\"}";

            // WHEN - Encrypt the same payload twice
            string encrypted1 = JweObject.Encrypt(config, payload, header);
            string encrypted2 = JweObject.Encrypt(config, payload, header);

            // THEN - Should be different due to random IV
            Assert.AreNotEqual(encrypted1, encrypted2, 
                "Multiple encryptions should produce different ciphertext due to random IV");

            // But both should decrypt to the same value
            var jweObject1 = JweObject.Parse(encrypted1);
            var jweObject2 = JweObject.Parse(encrypted2);
            
            Assert.AreEqual(payload, jweObject1.Decrypt(config));
            Assert.AreEqual(payload, jweObject2.Decrypt(config));
        }
    }
}
