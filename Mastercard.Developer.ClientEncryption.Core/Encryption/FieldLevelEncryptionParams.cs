using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Mastercard.Developer.ClientEncryption.Core.Utils;
using static Mastercard.Developer.ClientEncryption.Core.Encryption.FieldLevelEncryptionConfig;

namespace Mastercard.Developer.ClientEncryption.Core.Encryption
{
    /// <summary>
    /// Encryption parameters for computing field level encryption/decryption.
    /// </summary>
    public class FieldLevelEncryptionParams
    {
        private const int SymmetricKeySize = 128;

        public string IvValue { get; private set; }
        public string EncryptedKeyValue { get; private set; }
        public string OaepPaddingDigestAlgorithmValue { get; private set; }
        public string EncryptionCertificateFingerprintValue { get; private set; }
        public string EncryptionKeyFingerprintValue { get; private set; }
        private FieldLevelEncryptionConfig Config { get; set; }
        private byte[] SecretKeyBytes { get; set; }
        private byte[] IvBytes { get; set; }

        private FieldLevelEncryptionParams() {}

        public FieldLevelEncryptionParams(FieldLevelEncryptionConfig config, string ivValue, string encryptedKeyValue,
                                          string oaepPaddingDigestAlgorithmValue = null, string encryptionCertificateFingerprintValue = null,
                                          string encryptionKeyFingerprintValue = null)
        {
            IvValue = ivValue;
            EncryptedKeyValue = encryptedKeyValue;
            OaepPaddingDigestAlgorithmValue = oaepPaddingDigestAlgorithmValue;
            EncryptionCertificateFingerprintValue = encryptionCertificateFingerprintValue;
            EncryptionKeyFingerprintValue = encryptionKeyFingerprintValue;
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

            // Compute fingerprints and OAEP padding digest algorithm
            var encryptionCertificateFingerprint = GetOrComputeEncryptionCertificateFingerprint(config);
            var encryptionKeyFingerprint = GetOrComputeEncryptionKeyFingerprint(config);
            var oaepPaddingDigestAlgorithmValue = config.OaepPaddingDigestAlgorithm.Replace("-", string.Empty);

            return new FieldLevelEncryptionParams
            {
                IvValue = ivValue,
                EncryptedKeyValue = encryptedKeyValue,
                OaepPaddingDigestAlgorithmValue = oaepPaddingDigestAlgorithmValue,
                EncryptionCertificateFingerprintValue = encryptionCertificateFingerprint,
                EncryptionKeyFingerprintValue = encryptionKeyFingerprint,
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

        internal static byte[] WrapSecretKey(FieldLevelEncryptionConfig config, byte[] keyBytes)
        {
            try
            {
                var publicEncryptionKey = config.EncryptionCertificate.GetRSAPublicKey();
                return publicEncryptionKey.Encrypt(keyBytes,
                    "SHA-256".Equals(config.OaepPaddingDigestAlgorithm)
                        ? RSAEncryptionPadding.OaepSHA256
                        : RSAEncryptionPadding.OaepSHA512);
            }
            catch (Exception e)
            {
                throw new EncryptionException("Failed to wrap secret key!", e);
            }
        }

        internal static byte[] UnwrapSecretKey(FieldLevelEncryptionConfig config, byte[] keyBytes, string oaepDigestAlgorithm)
        {
            try
            {
                if (!oaepDigestAlgorithm.Contains("-")) {
                    oaepDigestAlgorithm = oaepDigestAlgorithm.Replace("SHA", "SHA-");
                }

                var decryptionKey = config.DecryptionKey;
                return decryptionKey.Decrypt(keyBytes, 
                    "SHA-256".Equals(oaepDigestAlgorithm) 
                        ? RSAEncryptionPadding.OaepSHA256 
                        : RSAEncryptionPadding.OaepSHA512);
            }
            catch (Exception e)
            {
                throw new EncryptionException("Failed to unwrap secret key!", e);
            }
        }

        private static string GetOrComputeEncryptionCertificateFingerprint(FieldLevelEncryptionConfig config)
        {
            try
            {
                var providedCertificateFingerprintValue = config.EncryptionCertificateFingerprint;
                if (!string.IsNullOrEmpty(providedCertificateFingerprintValue))
                {
                    return providedCertificateFingerprintValue;
                }

                var certificateFingerprintBytes = Sha256Digest(config.EncryptionCertificate.RawData);
                return EncodingUtils.EncodeBytes(certificateFingerprintBytes, FieldValueEncoding.Hex);
            }
            catch (Exception e)
            {
                throw new EncryptionException("Failed to compute encryption certificate fingerprint!", e);
            }
        }

        private static string GetOrComputeEncryptionKeyFingerprint(FieldLevelEncryptionConfig config)
        {
            try
            {
                var providedKeyFingerprintValue = config.EncryptionKeyFingerprint;
                if (!string.IsNullOrEmpty(providedKeyFingerprintValue))
                {
                    return providedKeyFingerprintValue;
                }

                var encodedKey = RsaKeyUtils.GetEncoded(config.EncryptionCertificate.PublicKey);
                var keyFingerprintBytes = Sha256Digest(encodedKey);
                return EncodingUtils.EncodeBytes(keyFingerprintBytes, FieldValueEncoding.Hex);
            }
            catch (Exception e)
            {
                throw new EncryptionException("Failed to compute encryption key fingerprint!", e);
            }
        }

        private static byte[] Sha256Digest(byte[] inputBytes)
        {
            var sha256 = SHA256.Create();
            return sha256.ComputeHash(inputBytes);
        }
    }
}
