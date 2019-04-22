using System;
using System.Linq;
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

        [TestMethod]
        public void TestWrapUnwrapSecretKey_ShouldReturnTheOriginalKey()
        {
            // GIVEN
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder().Build();
            var originalKeyBytes = Convert.FromBase64String("mZzmzoURXI3Vk0vdsPkcFw==");

            // WHEN
            var wrappedKeyBytes = FieldLevelEncryptionParams.WrapSecretKey(config, originalKeyBytes);
            var unwrappedKeyBytes = FieldLevelEncryptionParams.UnwrapSecretKey(config, wrappedKeyBytes, config.OaepPaddingDigestAlgorithm);

            // THEN
            Assert.IsTrue(originalKeyBytes.SequenceEqual(unwrappedKeyBytes));
        }

        [TestMethod]
        public void TestUnwrapSecretKey_InteroperabilityTest_OaepSha256()
        {
            // GIVEN
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithOaepPaddingDigestAlgorithm("SHA-256")
                .Build();
            const string wrappedKey = "ZLB838BRWW2/BtdFFAWBRYShw/gBxXSwItpxEZ9zaSVEDHo7n+SyVYU7mayd+9vHkR8OdpqwpXM68t0VOrWI8LD8A2pRaYx8ICyhVFya4OeiWlde05Rhsk+TNwwREPbiw1RgjT8aedRJJYbAZdLb9XEI415Kb/UliHyvsdHMb6vKyYIjUHB/pSGAAmgds56IhIJGfvnBLPZfSHmGgiBT8WXLRuuf1v48aIadH9S0FfoyVGTaLYr+2eznSTAFC0ZBnzebM3mQI5NGQNviTnEJ0y+uZaLE/mthiKgkv1ZybyDPx2xJK2n05sNzfIWKmnI/SOb65RZLlo1Q+N868l2m9g==";
            var wrappedKeyBytes = Convert.FromBase64String(wrappedKey);

            // WHEN
            var unwrappedKeyBytes = FieldLevelEncryptionParams.UnwrapSecretKey(config, wrappedKeyBytes, config.OaepPaddingDigestAlgorithm);

            // THEN
            var expectedKeyBytes = Convert.FromBase64String("mZzmzoURXI3Vk0vdsPkcFw==");
            Assert.IsTrue(expectedKeyBytes.SequenceEqual(unwrappedKeyBytes));
        }

        [TestMethod]
        public void TestUnwrapSecretKey_InteroperabilityTest_OaepSha512()
        {
            // GIVEN
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithOaepPaddingDigestAlgorithm("SHA-512")
                .Build();
            const string wrappedKey = "RuruMYP5rG6VP5vS4kVznIrSOjUzXyOhtD7bYlVqwniWTvxxZC73UDluwDhpLwX5QJCsCe8TcwGiQRX1u+yWpBveHDRmDa03hrc3JRJALEKPyN5tnt5w7aI4dLRnLuNoXbYoTSc4V47Z3gaaK6q2rEjydx2sQ/SyVmeUJN7NgxkhtHTyVWTymEM1ythL+AaaQ5AaXedhpWKhG06XYZIX4KV7T9cHEn+See6RVGGB2RUPHBJjrxJo5JoVSfnWN0gkTMyuwbmVaTWfsowbvh8GFibFT7h3uXyI3b79NiauyB7scXp9WidGues3MrTx4dKZrSbs3uHxzPKmCDZimuKfwg==";
            var wrappedKeyBytes = Convert.FromBase64String(wrappedKey);

            // WHEN
            var unwrappedKeyBytes = FieldLevelEncryptionParams.UnwrapSecretKey(config, wrappedKeyBytes, config.OaepPaddingDigestAlgorithm);

            // THEN
            var expectedKeyBytes = Convert.FromBase64String("mZzmzoURXI3Vk0vdsPkcFw==");
            Assert.IsTrue(expectedKeyBytes.SequenceEqual(unwrappedKeyBytes));
        }
    }
}
