using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Mastercard.Developer.ClientEncryption.Core.Utils
{
    /// <summary>
    /// Utility class for loading certificates and keys.
    /// </summary>
    public static class EncryptionUtils
    {
        /// <summary>
        /// Populate a X509 encryption certificate object with the certificate data at the given file path.
        /// </summary>
        public static X509Certificate2 LoadEncryptionCertificate(string certificatePath)
        {
            if (certificatePath == null) throw new ArgumentNullException(nameof(certificatePath));
            return new X509Certificate2(certificatePath);
        }

        /// <summary>
        /// Load a RSA decryption key from a file (PEM or DER).
        /// </summary>
        public static RSA LoadDecryptionKey(string keyFilePath) => RsaKeyUtils.ReadPrivateKeyFile(keyFilePath);

        /// <summary>
        /// Load a RSA decryption key out of a PKCS#12 container.
        /// </summary>
        public static RSA LoadDecryptionKey(string pkcs12KeyFilePath, string decryptionKeyAlias, string decryptionKeyPassword,
            X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet)
        {
            if (pkcs12KeyFilePath == null) throw new ArgumentNullException(nameof(pkcs12KeyFilePath));
            var certificate = new X509Certificate2(pkcs12KeyFilePath, decryptionKeyPassword, keyStorageFlags);
            return certificate.GetRSAPrivateKey();
        }

        /// <summary>
        /// Load a RSA decryption key from a byte array.
        /// </summary>
        public static RSA LoadDecryptionKey(byte[] key) => RsaKeyUtils.ReadPrivateKey(key);
    }
}
