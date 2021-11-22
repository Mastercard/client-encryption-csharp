﻿using System;
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
        public static JweConfigBuilder AJweConfigBuilder()
        {
            return new JweConfigBuilder();
        }

        /// <summary>
        /// See: <see cref="EncryptionConfig.EncryptionCertificate"/>
        /// </summary>
        public JweConfigBuilder WithEncryptionCertificate(X509Certificate2 encryptionCertificate)
        {
            _encryptionCertificate = encryptionCertificate;
            return this;
        }

        /// <summary>
        /// See: <see cref="EncryptionConfig.EncryptionKeyFingerprint"/>
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
        /// See: <see cref="EncryptionConfig.OaepPaddingDigestAlgorithm"/>
        /// </summary>
        public JweConfigBuilder WithOaepPaddingDigestAlgorithm(string oaepPaddingDigestAlgorithm)
        {
            _oaepPaddingDigestAlgorithm = oaepPaddingDigestAlgorithm;
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
                Scheme = EncryptionConfig.EncryptionScheme.Jwe,
                EncryptionKeyFingerprint = _encryptionKeyFingerprint,
                DecryptionKey = _decryptionKey,
                EncryptionPaths = _encryptionPaths,
                DecryptionPaths = _decryptionPaths,
                EncryptionCertificate = _encryptionCertificate,
                OaepPaddingDigestAlgorithm = _oaepPaddingDigestAlgorithm,
                EncryptedValueFieldName = _encryptedValueFieldName
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
