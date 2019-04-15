using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using static Mastercard.Developer.ClientEncryption.Core.Encryption.FieldLevelEncryptionConfig;
using static Mastercard.Developer.ClientEncryption.Core.Utils.JsonUtils;

namespace Mastercard.Developer.ClientEncryption.Core.Encryption
{
    /// <summary>
    /// A builder class for <see cref="FieldLevelEncryptionConfig"/>.
    /// </summary>
    public class FieldLevelEncryptionConfigBuilder
    {
        private X509Certificate2 _encryptionCertificate;
        private string _encryptionCertificateFingerprint;
        private string _encryptionKeyFingerprint;
        private RSA _decryptionKey;
        private readonly Dictionary<string, string> _encryptionPaths = new Dictionary<string, string>();
        private readonly Dictionary<string, string> _decryptionPaths = new Dictionary<string, string>();
        private string _oaepPaddingDigestAlgorithm;
        private string _ivFieldName;
        private string _ivHeaderName;
        private string _oaepPaddingDigestAlgorithmFieldName;
        private string _oaepPaddingDigestAlgorithmHeaderName;
        private string _encryptedKeyFieldName;
        private string _encryptedKeyHeaderName;
        private string _encryptedValueFieldName;
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
        /// See: <see cref="FieldLevelEncryptionConfig.EncryptionCertificate"/>
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
        /// See: <see cref="FieldLevelEncryptionConfig.EncryptionKeyFingerprint"/>
        /// </summary>
        public FieldLevelEncryptionConfigBuilder WithEncryptionKeyFingerprint(string encryptionKeyFingerprint)
        {
            _encryptionKeyFingerprint = encryptionKeyFingerprint;
            return this;
        }

        /// <summary>
        /// See: <see cref="FieldLevelEncryptionConfig.DecryptionKey"/>
        /// </summary>
        public FieldLevelEncryptionConfigBuilder WithDecryptionKey(RSA decryptionKey)
        {
            _decryptionKey = decryptionKey;
            return this;
        }

        /// <summary>
        /// See: <see cref="FieldLevelEncryptionConfig.EncryptionPaths"/>
        /// </summary>
        public FieldLevelEncryptionConfigBuilder WithEncryptionPath(string jsonPathIn, string jsonPathOut)
        {
            _encryptionPaths.Add(jsonPathIn, jsonPathOut);
            return this;
        }

        /// <summary>
        /// See: <see cref="FieldLevelEncryptionConfig.DecryptionPaths"/>
        /// </summary>
        public FieldLevelEncryptionConfigBuilder WithDecryptionPath(string jsonPathIn, string jsonPathOut)
        {
            _decryptionPaths.Add(jsonPathIn, jsonPathOut);
            return this;
        }

        /// <summary>
        /// See: <see cref="FieldLevelEncryptionConfig.OaepPaddingDigestAlgorithm"/>
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
        /// See: <see cref="FieldLevelEncryptionConfig.EncryptedValueFieldName"/>
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
            
            return new FieldLevelEncryptionConfig
            {
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

        private void CheckJsonPathParameterValues()
        {
            foreach (var key in _decryptionPaths.Keys)
            {
                if (!IsPathDefinite(key) || !IsPathDefinite(_decryptionPaths[key]))
                {
                    throw new ArgumentException("JSON paths for decryption must point to a single item!");
                }
            }

            foreach (var key in _encryptionPaths.Keys)
            {
                if (!IsPathDefinite(key) || !IsPathDefinite(_encryptionPaths[key]))
                {
                    throw new ArgumentException("JSON paths for encryption must point to a single item!");
                }
            }
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
    }
}
