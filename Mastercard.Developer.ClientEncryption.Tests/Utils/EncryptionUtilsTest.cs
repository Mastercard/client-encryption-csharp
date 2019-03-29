using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Mastercard.Developer.ClientEncryption.Core.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Mastercard.Developer.ClientEncryption.Tests.Utils
{
    [TestClass]
    public class EncryptionUtilsTest
    {
        [TestMethod]
        public void TestLoadEncryptionCertificate_ShouldSupportDer()
        {
            // GIVEN
            const string certificatePath = "./_Resources/test_certificate.der";

            // WHEN
            var certificate = EncryptionUtils.LoadEncryptionCertificate(certificatePath);

            // THEN
            Assert.IsNotNull(certificate);
            Assert.IsNotNull(certificate.GetPublicKey());
            Assert.AreEqual("X509", certificate.GetFormat());
        }

        [TestMethod]
        public void TestLoadEncryptionCertificate_ShouldSupportPem()
        {
            // GIVEN
            const string certificatePath = "./_Resources/test_certificate.pem";

            // WHEN
            var certificate = EncryptionUtils.LoadEncryptionCertificate(certificatePath);

            // THEN
            Assert.IsNotNull(certificate);
            Assert.IsNotNull(certificate.GetPublicKey());
            Assert.AreEqual("X509", certificate.GetFormat());
        }

        [TestMethod]
        public void TestLoadDecryptionKey_ShouldSupportPkcs8Der()
        {
            // GIVEN
            const string keyPath = "./_Resources/test_key_pkcs8.der";

            // WHEN
            var privateKey = EncryptionUtils.LoadDecryptionKey(keyPath);

            // THEN
            Assert.IsNotNull(privateKey);
            Assert.AreEqual(2048, privateKey.KeySize);
            Assert.AreEqual("RSA", privateKey.KeyExchangeAlgorithm);
        }

        [TestMethod]
        public void TestLoadDecryptionKey_ShouldSupportPkcs8Base64Pem()
        {
            // GIVEN
            const string keyPath = "./_Resources/test_key_pkcs8.pem";

            // WHEN
            var privateKey = EncryptionUtils.LoadDecryptionKey(keyPath);

            // THEN
            Assert.IsNotNull(privateKey);
            Assert.AreEqual(2048, privateKey.KeySize);
            Assert.AreEqual("RSA", privateKey.KeyExchangeAlgorithm);
        }

        [TestMethod]
        public void TestLoadDecryptionKey_ShouldSupportPkcs1Base64Pem_Nominal()
        {
            // GIVEN
            const string keyPath = "./_Resources/test_key_pkcs1.pem";

            // WHEN
            var privateKey = EncryptionUtils.LoadDecryptionKey(keyPath);

            // THEN
            Assert.IsNotNull(privateKey);
            Assert.AreEqual(2048, privateKey.KeySize);
            Assert.AreEqual("RSA", privateKey.KeyExchangeAlgorithm);
        }

        [TestMethod]
        public void TestLoadDecryptionKey_ShouldSupportPkcs1Base64Pem_1024bits()
        {
            // GIVEN
            const string keyPath = "./_Resources/test_key_pkcs1-1024.pem";

            // WHEN
            var privateKey = EncryptionUtils.LoadDecryptionKey(keyPath);

            // THEN
            Assert.IsNotNull(privateKey);
            Assert.AreEqual(1024, privateKey.KeySize);
            Assert.AreEqual("RSA", privateKey.KeyExchangeAlgorithm);
        }

        [TestMethod]
        public void TestLoadDecryptionKey_ShouldSupportPkcs1Base64Pem_4096bits()
        {
            // GIVEN
            const string keyPath = "./_Resources/test_key_pkcs1-4096.pem";

            // WHEN
            var privateKey = EncryptionUtils.LoadDecryptionKey(keyPath);

            // THEN
            Assert.IsNotNull(privateKey);
            Assert.AreEqual(4096, privateKey.KeySize);
            Assert.AreEqual("RSA", privateKey.KeyExchangeAlgorithm);
        }

        [TestMethod]
        public void TestLoadDecryptionKey_ShouldSupportPkcs12()
        {
            // GIVEN
            const string keyContainerPath = "./_Resources/test_key.p12";
            const string keyAlias = "mykeyalias";
            const string keyPassword = "Password1";

            // WHEN
            const X509KeyStorageFlags flags = X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable; // https://github.com/dotnet/corefx/issues/14745
            var privateKey = EncryptionUtils.LoadDecryptionKey(keyContainerPath, keyAlias, keyPassword, flags);

            // THEN
            Assert.AreEqual(2048, privateKey.KeySize);
            Assert.AreEqual("RSA", privateKey.KeyExchangeAlgorithm);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))] // THEN
        public void TestLoadDecryptionKey_ShouldThrowArgumentException_WhenInvalidKey()
        {
            // GIVEN
            const string keyPath = "./_Resources/test_invalid_key.der";

            // WHEN
            EncryptionUtils.LoadDecryptionKey(keyPath);
        }

        [TestMethod]
        [ExpectedException(typeof(FileNotFoundException))] // THEN
        public void TestLoadDecryptionKey_ShouldThrowFileNotFoundException_WhenKeyFileDoesNotExist()
        {
            // GIVEN
            const string keyPath = "./_Resources/some_file";

            // WHEN
            EncryptionUtils.LoadDecryptionKey(keyPath);
        }
    }
}
