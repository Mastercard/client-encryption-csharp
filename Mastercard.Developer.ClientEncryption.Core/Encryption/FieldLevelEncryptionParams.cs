using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Mastercard.Developer.ClientEncryption.Core.Utils;
#pragma warning disable 1591 // "Missing XML comment for publicly visible type or member."

namespace Mastercard.Developer.ClientEncryption.Core.Encryption
{
    /// <summary>
    /// Encryption parameters for computing field level encryption/decryption.
    /// </summary>
    public class FieldLevelEncryptionParams : EncryptionParams
    {
        private const int SymmetricKeySize = 128;

        /// <summary>
        /// Initialization vector value.
        /// </summary>
        public string IvValue { get; private set; }

        /// <summary>
        /// Encrypted key value.
        /// </summary>
        public string EncryptedKeyValue { get; private set; }

        /// <summary>
        /// Digest algorithm to be used for the RSA OAEP padding. Example: "SHA-512".
        /// </summary>
        public string OaepPaddingDigestAlgorithmValue { get; private set; }

        private FieldLevelEncryptionConfig Config { get; set; }
        private byte[] SecretKeyBytes { get; set; }
        private byte[] IvBytes { get; set; }

        private FieldLevelEncryptionParams() {}

        public FieldLevelEncryptionParams(FieldLevelEncryptionConfig config, string ivValue, string encryptedKeyValue, string oaepPaddingDigestAlgorithmValue = null)
        {
            IvValue = ivValue;
            EncryptedKeyValue = encryptedKeyValue;
            OaepPaddingDigestAlgorithmValue = oaepPaddingDigestAlgorithmValue;
            Config = config;
        }

        /// <summary>
        /// Generate encryption parameters.
        /// </summary>
        /// <exception cref="EncryptionException"/>
        public static FieldLevelEncryptionParams Generate(FieldLevelEncryptionConfig config)
        {
            // Generate a random IV
            var ivBytes = GenerateIv();
            var ivValue = EncodingUtils.EncodeBytes(ivBytes, config.ValueEncoding);

            // Generate an AES secret key
            var secretKeyBytes = GenerateSecretKey();

            // Encrypt the secret key
            var encryptedSecretKeyBytes = WrapSecretKey(config, secretKeyBytes);
            var encryptedKeyValue = EncodingUtils.EncodeBytes(encryptedSecretKeyBytes, config.ValueEncoding);

            // Compute the OAEP padding digest algorithm
            var oaepPaddingDigestAlgorithmValue = config.OaepPaddingDigestAlgorithm.Replace("-", string.Empty);

            return new FieldLevelEncryptionParams
            {
                IvValue = ivValue,
                EncryptedKeyValue = encryptedKeyValue,
                OaepPaddingDigestAlgorithmValue = oaepPaddingDigestAlgorithmValue,
                Config = config,
                SecretKeyBytes = secretKeyBytes,
                IvBytes = ivBytes
            };
        }

        private static byte[] GenerateIv()
        {
            using (var aes = Aes.Create())
            {
                if (aes == null)
                {
                    throw new EncryptionException("Failed to generate IV, AES instance is null!");
                }

                aes.GenerateIV();
                return aes.IV;
            }
        }

        private static byte[] GenerateSecretKey()
        {
            using (var aes = Aes.Create())
            {
                if (aes == null)
                {
                    throw new EncryptionException("Failed to generate secret key, AES instance is null!");
                }

                aes.KeySize = SymmetricKeySize;
                aes.GenerateKey();
                return aes.Key;
            }
        }

        internal byte[] GetSecretKeyBytes()
        {
            try
            {
                if (SecretKeyBytes != null)
                {
                    return SecretKeyBytes;
                }
                // Decrypt the AES secret key
                var encryptedSecretKeyBytes = EncodingUtils.DecodeValue(EncryptedKeyValue, Config.ValueEncoding);
                SecretKeyBytes = UnwrapSecretKey(Config, encryptedSecretKeyBytes, OaepPaddingDigestAlgorithmValue);
                return SecretKeyBytes;
            }
            catch (Exception e)
            {
                throw new EncryptionException("Failed to decode and unwrap the provided secret key value!", e);
            }
        }

        internal byte[] GetIvBytes()
        {
            try
            {
                if (IvBytes != null)
                {
                    return IvBytes;
                }
                // Decode the IV
                IvBytes = EncodingUtils.DecodeValue(IvValue, Config.ValueEncoding);
                return IvBytes;
            }
            catch (Exception e)
            {
                throw new EncryptionException("Failed to decode the provided IV value!", e);
            }
        }
    }
}
