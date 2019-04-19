using System;
using Mastercard.Developer.ClientEncryption.Core.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Mastercard.Developer.ClientEncryption.Tests.Utils
{
    [TestClass]
    public class RsaKeyUtilsTest
    {
        [TestMethod]
        public void TestReadPrivateKeyFile_ShouldSupportPkcs8Pem512bits()
        {
            // GIVEN
            const string keyPath = "./_Resources/Keys/Pkcs8/test_key_pkcs8-512.pem";

            // WHEN
            var rsa = RsaKeyUtils.ReadPrivateKeyFile(keyPath);

            // THEN
            Assert.AreEqual("RSA", rsa.KeyExchangeAlgorithm);
            Assert.AreEqual(512, rsa.KeySize);
        }

        [TestMethod]
        public void TestReadPrivateKeyFile_ShouldSupportPkcs8Pem1024bits()
        {
            // GIVEN
            const string keyPath = "./_Resources/Keys/Pkcs8/test_key_pkcs8-1024.pem";

            // WHEN
            var rsa = RsaKeyUtils.ReadPrivateKeyFile(keyPath);

            // THEN
            Assert.AreEqual("RSA", rsa.KeyExchangeAlgorithm);
            Assert.AreEqual(1024, rsa.KeySize);
        }

        [TestMethod]
        public void TestReadPrivateKeyFile_ShouldSupportPkcs8Pem2048bits()
        {
            // GIVEN
            const string keyPath = "./_Resources/Keys/Pkcs8/test_key_pkcs8-2048.pem";

            // WHEN
            var rsa = RsaKeyUtils.ReadPrivateKeyFile(keyPath);

            // THEN
            Assert.AreEqual("RSA", rsa.KeyExchangeAlgorithm);
            Assert.AreEqual(2048, rsa.KeySize);
        }

        [TestMethod]
        public void TestReadPrivateKeyFile_ShouldSupportPkcs8Pem4096bits()
        {
            // GIVEN
            const string keyPath = "./_Resources/Keys/Pkcs8/test_key_pkcs8-4096.pem";

            // WHEN
            var rsa = RsaKeyUtils.ReadPrivateKeyFile(keyPath);

            // THEN
            Assert.AreEqual("RSA", rsa.KeyExchangeAlgorithm);
            Assert.AreEqual(4096, rsa.KeySize);
        }

        [TestMethod]
        public void TestReadPrivateKeyFile_ShouldSupportPkcs8Der512bits()
        {
            // GIVEN
            const string keyPath = "./_Resources/Keys/Pkcs8/test_key_pkcs8-512.der";

            // WHEN
            var rsa = RsaKeyUtils.ReadPrivateKeyFile(keyPath);

            // THEN
            Assert.AreEqual("RSA", rsa.KeyExchangeAlgorithm);
            Assert.AreEqual(512, rsa.KeySize);
        }

        [TestMethod]
        public void TestReadPrivateKeyFile_ShouldSupportPkcs8Der1024bits()
        {
            // GIVEN
            const string keyPath = "./_Resources/Keys/Pkcs8/test_key_pkcs8-1024.der";

            // WHEN
            var rsa = RsaKeyUtils.ReadPrivateKeyFile(keyPath);

            // THEN
            Assert.AreEqual("RSA", rsa.KeyExchangeAlgorithm);
            Assert.AreEqual(1024, rsa.KeySize);
        }

        [TestMethod]
        public void TestReadPrivateKeyFile_ShouldSupportPkcs8Der2048bits()
        {
            // GIVEN
            const string keyPath = "./_Resources/Keys/Pkcs8/test_key_pkcs8-2048.der";

            // WHEN
            var rsa = RsaKeyUtils.ReadPrivateKeyFile(keyPath);

            // THEN
            Assert.AreEqual("RSA", rsa.KeyExchangeAlgorithm);
            Assert.AreEqual(2048, rsa.KeySize);
        }

        [TestMethod]
        public void TestReadPrivateKeyFile_ShouldSupportPkcs8Der4096bits()
        {
            // GIVEN
            const string keyPath = "./_Resources/Keys/Pkcs8/test_key_pkcs8-4096.der";

            // WHEN
            var rsa = RsaKeyUtils.ReadPrivateKeyFile(keyPath);

            // THEN
            Assert.AreEqual("RSA", rsa.KeyExchangeAlgorithm);
            Assert.AreEqual(4096, rsa.KeySize);
        }

        [TestMethod]
        public void TestReadPrivateKeyFile_ShouldSupportPkcs1Base64Pem512bits()
        {
            // GIVEN
            const string keyPath = "./_Resources/Keys/Pkcs1/test_key_pkcs1-512.pem";

            // WHEN
            var rsa = RsaKeyUtils.ReadPrivateKeyFile(keyPath);

            // THEN
            Assert.AreEqual("RSA", rsa.KeyExchangeAlgorithm);
            Assert.AreEqual(512, rsa.KeySize);
        }

        [TestMethod]
        public void TestReadPrivateKeyFile_ShouldSupportPkcs1Base64Pem1024bits()
        {
            // GIVEN
            const string keyPath = "./_Resources/Keys/Pkcs1/test_key_pkcs1-1024.pem";

            // WHEN
            var rsa = RsaKeyUtils.ReadPrivateKeyFile(keyPath);

            // THEN
            Assert.AreEqual("RSA", rsa.KeyExchangeAlgorithm);
            Assert.AreEqual(1024, rsa.KeySize);
        }

        [TestMethod]
        public void TestReadPrivateKeyFile_ShouldSupportPkcs1Base64Pem2048bits()
        {
            // GIVEN
            const string keyPath = "./_Resources/Keys/Pkcs1/test_key_pkcs1-2048.pem";

            // WHEN
            var rsa = RsaKeyUtils.ReadPrivateKeyFile(keyPath);

            // THEN
            Assert.AreEqual("RSA", rsa.KeyExchangeAlgorithm);
            Assert.AreEqual(2048, rsa.KeySize);
        }

        [TestMethod]
        public void TestReadPrivateKeyFile_ShouldSupportPkcs1Base64Pem4096bits()
        {
            // GIVEN
            const string keyPath = "./_Resources/Keys/Pkcs1/test_key_pkcs1-4096.pem";

            // WHEN
            var rsa = RsaKeyUtils.ReadPrivateKeyFile(keyPath);

            // THEN
            Assert.AreEqual("RSA", rsa.KeyExchangeAlgorithm);
            Assert.AreEqual(4096, rsa.KeySize);
        }

        [TestMethod]
        public void TestGetEncoded_ShouldSupportPublicKey512bits()
        {
            // GIVEN
            const string certificatePath = "./_Resources/Certificates/test_certificate-512.pem";
            var certificate = EncryptionUtils.LoadEncryptionCertificate(certificatePath);

            // WHEN
            var encodedBytes = RsaKeyUtils.GetEncoded(certificate.PublicKey);

            // THEN
            const string javaGetEncodedKeyValue = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANgkcDW0LBw2whiJld9zMq2fs56NdZcPxaM4kbN5NJKcWMv/120mOUrRlqsxdN0slsqvnyxG+D+weHdEQVFcUn8CAwEAAQ==";
            Assert.AreEqual(javaGetEncodedKeyValue, Convert.ToBase64String(encodedBytes));
        }

        [TestMethod]
        public void TestGetEncoded_ShouldSupportPublicKey1024bits()
        {
            // GIVEN
            const string certificatePath = "./_Resources/Certificates/test_certificate-1024.pem";
            var certificate = EncryptionUtils.LoadEncryptionCertificate(certificatePath);

            // WHEN
            var encodedBytes = RsaKeyUtils.GetEncoded(certificate.PublicKey);

            // THEN
            const string javaGetEncodedKeyValue = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDih8akxCCa30Pv5epkBWt4KzpGaXqeyB/ydbj3Hq7ylvHnJwrb9cJ4MbsKzox2JUbtYg/AVXCaQTDlsXfql6+O51ptKLWWilyzAZb5/okpOx2DlzHe4c/crrDfMnF0UA2sFbmzqSUVpNY7NjE7tquRhYueJTT2RpAGGANMReMhjwIDAQAB";
            Assert.AreEqual(javaGetEncodedKeyValue, Convert.ToBase64String(encodedBytes));
        }

        [TestMethod]
        public void TestGetEncoded_ShouldSupportPublicKey2048bits()
        {
            // GIVEN
            const string certificatePath = "./_Resources/Certificates/test_certificate-2048.pem";
            var certificate = EncryptionUtils.LoadEncryptionCertificate(certificatePath);

            // WHEN
            var encodedBytes = RsaKeyUtils.GetEncoded(certificate.PublicKey);

            // THEN
            const string javaGetEncodedKeyValue = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9Mp6gEFp9E+/1SS5XrUyYKMbE7eU0dyJCfmJPz8YOkOYV7ohqwXQvjlaP/YazZ6bbmYfa2WCraOpW0o2BYijHgQ7z2a2Az87rKdAtCpZSKFW82Ijnsw++lx7EABI3tFF282ZV7LT13n9m4th5Kldukk9euy+TuJqCvPu4xzE/NE+l4LFMr8rfD47EPQkrun5w/TXwkmJrdnG9ejl3BLQO06Ns6Bs516geiYZ7RYxtI8Xnu0ZC0fpqDqjCPZBTORkiFeLocEPRbTgo1H+0xQFNdsMH1/0F1BI+hvdxlbc3+kHZFZFoeBMkR3jC8jDXOXNCMNWb13Tin6HqPReO0KW8wIDAQAB";
            Assert.AreEqual(javaGetEncodedKeyValue, Convert.ToBase64String(encodedBytes));
        }

        [TestMethod]
        public void TestGetEncoded_ShouldSupportPublicKey4096bits()
        {
            // GIVEN
            const string certificatePath = "./_Resources/Certificates/test_certificate-4096.pem";
            var certificate = EncryptionUtils.LoadEncryptionCertificate(certificatePath);

            // WHEN
            var encodedBytes = RsaKeyUtils.GetEncoded(certificate.PublicKey);

            // THEN
            const string javaGetEncodedValue = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAygN/8OUwDKbTIt5zguBP4sBF1GCWpKsV6Nt2llfMNqugd/9xM2BI4WyINNSzQDA69Qp+ce2mAkqxO72l7BhBdGitHDRrU4QAun/ls+ECrWZ5ug9iFZD2dsrLxj08gLRlybwFCUjuLLK5QUjB4HfbgAxkgYfVBgluIgA6G7Lcr9rQr57F53IZ5hM9ppcbNeb9HlW5wHV+tHW/1l9ZcOS5TJPP5ptV3aHneMpVKB8TJIMjSiWZt+6bs1VoCB2jaxaVNC2jkgzInezsqGur+G7Zq5oofcRDKyDt8imXf71i3BcM7d7fOur/r5gB0k6Kc+UGSzQK2oVP54T/0X52+2eKV8NqGF3Lpu5Poy5Nq0rID3L1Db81P7qUrrISuMkLP+uPPbFk4A6ZuczNAbxXARjSwOFhshUHEVKIW7FWeWWCCY5Ti21eWG9Recl5ahA7aHLogTFqyhAqV5h4l7D/icoxr2TAOkllFGLCRZ3ad43ET7gXPttiqu3SPstUFbuqDbmt3Yp4ZuoDA3+KEeSXYPaIn+J9Drm4B6gMTrTh/i0eRdKc9VFYmIgVJGRH4X6KCAO3erhzAUuFRKELJl1g6i0xZnPLICSktG+dBWkiFSqkLIsxPc9K4o9ZEOmhALih8gLEitXIcze7TT4ohhJsuA9T4GVMBRaQiAHo9fK2PF7h+WcCAwEAAQ==";
            Assert.AreEqual(javaGetEncodedValue, Convert.ToBase64String(encodedBytes));
        }
    }
}
