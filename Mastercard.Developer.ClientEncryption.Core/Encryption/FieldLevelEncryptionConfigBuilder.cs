using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Mastercard.Developer.ClientEncryption.Core.Utils;
using static Mastercard.Developer.ClientEncryption.Core.Encryption.FieldLevelEncryptionConfig;

namespace Mastercard.Developer.ClientEncryption.Core.Encryption
{
    /// <summary>
    /// A builder class for <see cref="FieldLevelEncryptionConfig"/>.
    /// </summary>
    public class FieldLevelEncryptionConfigBuilder : EncryptionConfigBuilder
    {
        private string _encryptionCertificateFingerprint;
        private string _ivFieldName;
        private string _ivHeaderName;
        private string _oaepPaddingDigestAlgorithmFieldName;
        private string _oaepPaddingDigestAlgorithmHeaderName;
        private string _encryptedKeyFieldName;
        private string _encryptedKeyHeaderName;
        private string _encryptionCertificateFingerprintFieldName;
        private string _encryptionCertificateFingerprintHeaderName;
        private string _encryptionKeyFingerprintFieldName;
        private string _encryptionKeyFingerprintHeaderName;
        private FieldValueEncoding _valueEncoding;

        private FieldLevelEncryptionConfigBuilder() {}

        /// <summary>
        /// Get an instance of the builder.
        /// </summary>
        public static FieldLevelEncryptionConfigBuilder AFieldLevelEncryptionConfig() => new FieldLevelEncryptionConfigBuilder();

        /// <summary>
        /// See: <see cref="EncryptionConfig.EncryptionCertificate"/>
        /// </summary>
        public FieldLevelEncryptionConfigBuilder WithEncryptionCertificate(X509Certificate2 encryptionCertificate)
        {
            _encryptionCertificate = encryptionCertificate;
            return this;
        }

        /// <summary>
        /// See: <see cref="FieldLevelEncryptionConfig.EncryptionCertificateFingerprint"/>
        /// </summary>
        public FieldLevelEncryptionConfigBuilder WithEncryptionCertificateFingerprint(string encryptionCertificateFingerprint)
        {
            _encryptionCertificateFingerprint = encryptionCertificateFingerprint;
            return this;
        }

        /// <summary>
        /// See: <see cref="EncryptionConfig.EncryptionKeyFingerprint"/>
        /// </summary>
        public FieldLevelEncryptionConfigBuilder WithEncryptionKeyFingerprint(string encryptionKeyFingerprint)
        {
            _encryptionKeyFingerprint = encryptionKeyFingerprint;
            return this;
        }

        /// <summary>
        /// See: <see cref="EncryptionConfig.DecryptionKey"/>
        /// </summary>
        public FieldLevelEncryptionConfigBuilder WithDecryptionKey(RSA decryptionKey)
        {
            _decryptionKey = decryptionKey;
            return this;
        }

        /// <summary>
        /// See: <see cref="EncryptionConfig.EncryptionPaths"/>
        /// </summary>
        public FieldLevelEncryptionConfigBuilder WithEncryptionPath(string jsonPathIn, string jsonPathOut)
        {
            _encryptionPaths.Add(jsonPathIn, jsonPathOut);
            return this;
        }

        /// <summary>
        /// See: <see cref="EncryptionConfig.DecryptionPaths"/>
        /// </summary>
        public FieldLevelEncryptionConfigBuilder WithDecryptionPath(string jsonPathIn, string jsonPathOut)
        {
            _decryptionPaths.Add(jsonPathIn, jsonPathOut);
            return this;
        }

        /// <summary>
        /// See: <see cref="EncryptionConfig.OaepPaddingDigestAlgorithm"/>
        /// </summary>
        public FieldLevelEncryptionConfigBuilder WithOaepPaddingDigestAlgorithm(string oaepPaddingDigestAlgorithm)
        {
            _oaepPaddingDigestAlgorithm = oaepPaddingDigestAlgorithm;
            return this;
        }

        /// <summary>
        /// See: <see cref="FieldLevelEncryptionConfig.IvFieldName"/>
        /// </summary>
        public FieldLevelEncryptionConfigBuilder WithIvFieldName(string ivFieldName)
        {
            _ivFieldName = ivFieldName;
            return this;
        }

        /// <summary>
        /// See: <see cref="FieldLevelEncryptionConfig.OaepPaddingDigestAlgorithmFieldName"/>
        /// </summary>
        public FieldLevelEncryptionConfigBuilder WithOaepPaddingDigestAlgorithmFieldName(string oaepPaddingDigestAlgorithmFieldName)
        {
            _oaepPaddingDigestAlgorithmFieldName = oaepPaddingDigestAlgorithmFieldName;
            return this;
        }

        /// <summary>
        /// See: <see cref="FieldLevelEncryptionConfig.EncryptedKeyFieldName"/>
        /// </summary>
        public FieldLevelEncryptionConfigBuilder WithEncryptedKeyFieldName(string encryptedKeyFieldName)
        {
            _encryptedKeyFieldName = encryptedKeyFieldName;
            return this;
        }

        /// <summary>
        /// See: <see cref="EncryptionConfig.EncryptedValueFieldName"/>
        /// </summary>
        public FieldLevelEncryptionConfigBuilder WithEncryptedValueFieldName(string encryptedValueFieldName)
        {
            _encryptedValueFieldName = encryptedValueFieldName;
            return this;
        }

        /// <summary>
        /// See: <see cref="FieldLevelEncryptionConfig.EncryptionCertificateFingerprintFieldName"/>
        /// </summary>
        public FieldLevelEncryptionConfigBuilder WithEncryptionCertificateFingerprintFieldName(string encryptionCertificateFingerprintFieldName)
        {
            _encryptionCertificateFingerprintFieldName = encryptionCertificateFingerprintFieldName;
            return this;
        }

        /// <summary>
        /// See: <see cref="FieldLevelEncryptionConfig.EncryptionKeyFingerprintFieldName"/>
        /// </summary>
        public FieldLevelEncryptionConfigBuilder WithEncryptionKeyFingerprintFieldName(string encryptionKeyFingerprintFieldName)
        {
            _encryptionKeyFingerprintFieldName = encryptionKeyFingerprintFieldName;
            return this;
        }

        /// <summary>
        /// See: <see cref="FieldLevelEncryptionConfig.ValueEncoding"/>
        /// </summary>
        public FieldLevelEncryptionConfigBuilder WithValueEncoding(FieldValueEncoding valueEncoding)
        {
            _valueEncoding = valueEncoding;
            return this;
        }

        /// <summary>
        /// See: <see cref="FieldLevelEncryptionConfig.IvHeaderName"/>
        /// </summary>
        public FieldLevelEncryptionConfigBuilder WithIvHeaderName(string ivHeaderName)
        {
            _ivHeaderName = ivHeaderName;
            return this;
        }

        /// <summary>
        /// See: <see cref="FieldLevelEncryptionConfig.OaepPaddingDigestAlgorithmHeaderName"/>
        /// </summary>
        public FieldLevelEncryptionConfigBuilder WithOaepPaddingDigestAlgorithmHeaderName(string oaepPaddingDigestAlgorithmHeaderName)
        {
            _oaepPaddingDigestAlgorithmHeaderName = oaepPaddingDigestAlgorithmHeaderName;
            return this;
        }

        /// <summary>
        /// See: <see cref="FieldLevelEncryptionConfig.EncryptedKeyHeaderName"/>
        /// </summary>
        public FieldLevelEncryptionConfigBuilder WithEncryptedKeyHeaderName(string encryptedKeyHeaderName)
        {
            _encryptedKeyHeaderName = encryptedKeyHeaderName;
            return this;
        }

        /// <summary>
        /// See: <see cref="FieldLevelEncryptionConfig.EncryptionCertificateFingerprintHeaderName"/>
        /// </summary>
        public FieldLevelEncryptionConfigBuilder WithEncryptionCertificateFingerprintHeaderName(string encryptionCertificateFingerprintHeaderName)
        {
            _encryptionCertificateFingerprintHeaderName = encryptionCertificateFingerprintHeaderName;
            return this;
        }

        /// <summary>
        /// See: <see cref="FieldLevelEncryptionConfig.EncryptionKeyFingerprintHeaderName"/>
        /// </summary>
        public FieldLevelEncryptionConfigBuilder WithEncryptionKeyFingerprintHeaderName(string encryptionKeyFingerprintHeaderName)
        {
            _encryptionKeyFingerprintHeaderName = encryptionKeyFingerprintHeaderName;
            return this;
        }

        /// <summary>
        /// Build a <see cref="FieldLevelEncryptionConfig"/>
        /// </summary>
        public FieldLevelEncryptionConfig Build()
        {
            CheckJsonPathParameterValues();
            CheckParameterValues();
            CheckParameterConsistency();

            ComputeEncryptionCertificateFingerprintWhenNeeded();
            ComputeEncryptionKeyFingerprintWhenNeeded();

            return new FieldLevelEncryptionConfig
            {
                Scheme = EncryptionConfig.EncryptionScheme.Legacy,
                EncryptionCertificateFingerprintFieldName = _encryptionCertificateFingerprintFieldName,
                EncryptionKeyFingerprintFieldName = _encryptionKeyFingerprintFieldName,
                EncryptionCertificateFingerprint = _encryptionCertificateFingerprint,
                EncryptionKeyFingerprint = _encryptionKeyFingerprint,
                DecryptionKey = _decryptionKey,
                EncryptionPaths = _encryptionPaths,
                EncryptionCertificate = _encryptionCertificate,
                OaepPaddingDigestAlgorithm = _oaepPaddingDigestAlgorithm,
                IvFieldName = _ivFieldName,
                OaepPaddingDigestAlgorithmFieldName = _oaepPaddingDigestAlgorithmFieldName,
                DecryptionPaths = _decryptionPaths,
                EncryptedKeyFieldName = _encryptedKeyFieldName,
                ValueEncoding = _valueEncoding,
                EncryptedValueFieldName = _encryptedValueFieldName,
                IvHeaderName = _ivHeaderName,
                OaepPaddingDigestAlgorithmHeaderName = _oaepPaddingDigestAlgorithmHeaderName,
                EncryptedKeyHeaderName = _encryptedKeyHeaderName,
                EncryptionCertificateFingerprintHeaderName = _encryptionCertificateFingerprintHeaderName,
                EncryptionKeyFingerprintHeaderName = _encryptionKeyFingerprintHeaderName
            };
        }

        private void CheckParameterValues()
        {
            if (_oaepPaddingDigestAlgorithm == null)
            {
                throw new ArgumentException("The digest algorithm for OAEP cannot be null!");
            }

            if (!"SHA-256".Equals(_oaepPaddingDigestAlgorithm)
                    && !"SHA-512".Equals(_oaepPaddingDigestAlgorithm))
            {
                throw new ArgumentException($"Unsupported OAEP digest algorithm: {_oaepPaddingDigestAlgorithm}!");
            }

            if (_ivFieldName == null && _ivHeaderName == null)
            {
                throw new ArgumentException("At least one of IV field name or IV header name must be set!");
            }

            if (_encryptedKeyFieldName == null && _encryptedKeyHeaderName == null)
            {
                throw new ArgumentException("At least one of encrypted key field name or encrypted key header name must be set!");
            }

            if (_encryptedValueFieldName == null)
            {
                throw new ArgumentException("Encrypted value field name cannot be null!");
            }
        }

        private void CheckParameterConsistency()
        {
            if (_decryptionPaths.Count != 0 && _decryptionKey == null)
            {
                throw new ArgumentException("Can't decrypt without decryption key!");
            }

            if (_encryptionPaths.Count != 0 && _encryptionCertificate == null)
            {
                throw new ArgumentException("Can't encrypt without encryption key!");
            }

            if (_ivHeaderName != null && _encryptedKeyHeaderName == null
                    || _ivHeaderName == null && _encryptedKeyHeaderName != null)
            {
                throw new ArgumentException("IV header name and encrypted key header name must be both set or both unset!");
            }

            if (_ivFieldName != null && _encryptedKeyFieldName == null
                    || _ivFieldName == null && _encryptedKeyFieldName != null)
            {
                throw new ArgumentException("IV field name and encrypted key field name must be both set or both unset!");
            }
        }

        private void ComputeEncryptionCertificateFingerprintWhenNeeded()
        {
            try
            {
                if (_encryptionCertificate == null || !string.IsNullOrEmpty(_encryptionCertificateFingerprint))
                {
                    // No encryption certificate set or certificate fingerprint already provided
                    return;
                }
                var certificateFingerprintBytes = Sha256Digest(_encryptionCertificate.RawData);
                _encryptionCertificateFingerprint = EncodingUtils.EncodeBytes(certificateFingerprintBytes, FieldValueEncoding.Hex);
            }
            catch (Exception e)
            {
                throw new EncryptionException("Failed to compute encryption certificate fingerprint!", e);
            }
        }
    }
}
