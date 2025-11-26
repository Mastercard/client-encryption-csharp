using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Mastercard.Developer.ClientEncryption.Core.Encryption
{
    /// <summary>
    /// A builder class for <see cref="JweConfig"/>.
    /// </summary>
    public class JweConfigBuilder : EncryptionConfigBuilder
    {
        private JweConfigBuilder() {  }

        /// <summary>
        /// Get an instance of the builder.
        /// </summary>
        public static JweConfigBuilder AJweEncryptionConfig() => new JweConfigBuilder();

        /// <summary>
        /// See: <see cref="EncryptionConfig.EncryptionCertificate"/>
        /// </summary>
        public JweConfigBuilder WithEncryptionCertificate(X509Certificate2 encryptionCertificate)
        {
            _encryptionCertificate = encryptionCertificate;
            return this;
        }

        /// <summary>
        /// See: <see cref="EncryptionConfig.EncryptionCertificate"/>
        /// </summary>
        public JweConfigBuilder WithEncryptionKeyFingerprint(string encryptionKeyFingerprint)
        {
            _encryptionKeyFingerprint = encryptionKeyFingerprint;
            return this;
        }

        /// <summary>
        /// See: <see cref="EncryptionConfig.DecryptionKey"/>
        /// </summary>
        public JweConfigBuilder WithDecryptionKey(RSA decryptionKey)
        {
            _decryptionKey = decryptionKey;
            return this;
        }

        /// <summary>
        /// See: <see cref="EncryptionConfig.EncryptionPaths"/>
        /// </summary>
        public JweConfigBuilder WithEncryptionPath(string jsonPathIn, string jsonPathOut)
        {
            _encryptionPaths.Add(jsonPathIn, jsonPathOut);
            return this;
        }

        /// <summary>
        /// See: <see cref="EncryptionConfig.DecryptionPaths"/>
        /// </summary>
        public JweConfigBuilder WithDecryptionPath(string jsonPathIn, string jsonPathOut)
        {
            _decryptionPaths.Add(jsonPathIn, jsonPathOut);
            return this;
        }

        /// <summary>
        /// See: <see cref="EncryptionConfig.EncryptedValueFieldName"/>
        /// </summary>
        public JweConfigBuilder WithEncryptedValueFieldName(string encryptedValueFieldName)
        {
            _encryptedValueFieldName = encryptedValueFieldName;
            return this;
        }

        private bool _enableCbcHmacVerification = false;

        /// <summary>
        /// Enable HMAC verification for CBC mode encryption algorithms (A128CBC-HS256, A192CBC-HS384, A256CBC-HS512).
        /// When enabled, HMAC authentication tags will be verified during decryption and generated during encryption.
        /// Default is false for backward compatibility.
        /// </summary>
        public JweConfigBuilder WithCbcHmacVerification(bool enable = true)
        {
            _enableCbcHmacVerification = enable;
            return this;
        }

        /// <summary>
        /// Build a <see cref="JweConfig"/>
        /// </summary>
        public JweConfig Build()
        {
            CheckParameterValues();
            ComputeEncryptionKeyFingerprintWhenNeeded();
            CheckJsonPathParameterValues();

            return new JweConfig
            {
                EncryptionCertificate = _encryptionCertificate,
                EncryptionKeyFingerprint = _encryptionKeyFingerprint,
                DecryptionKey = _decryptionKey,
                EncryptionPaths = _encryptionPaths.Count == 0 ? new Dictionary<string, string> { { "$", "$" } } : _encryptionPaths,
                DecryptionPaths = _decryptionPaths.Count == 0 ? new Dictionary<string, string> { { "$.encryptedData", "$" } } : _decryptionPaths,
                EncryptedValueFieldName = _encryptedValueFieldName ?? "encryptedData",
                Scheme = EncryptionConfig.EncryptionScheme.Jwe,
                EnableCbcHmacVerification = _enableCbcHmacVerification
            };
        }

        private void CheckParameterValues()
        {
            if (_decryptionKey == null && _encryptionCertificate == null)
            {
                throw new ArgumentException("You must include at least an encryption certificate or a decryption key");
            }
        }
    }
}
