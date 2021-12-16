#pragma warning disable 1591 // "Missing XML comment for publicly visible type or member."

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Mastercard.Developer.ClientEncryption.Core.Utils;

using static Mastercard.Developer.ClientEncryption.Core.Utils.JsonUtils;

namespace Mastercard.Developer.ClientEncryption.Core.Encryption
{
    /// <summary>
    /// A base class for configuration builders.
    /// </summary>
    public abstract class EncryptionConfigBuilder
    {
        protected internal X509Certificate2 _encryptionCertificate;
        protected internal string _encryptionKeyFingerprint;
        protected internal RSA _decryptionKey;
        protected internal readonly Dictionary<string, string> _encryptionPaths = new Dictionary<string, string>();
        protected internal readonly Dictionary<string, string> _decryptionPaths = new Dictionary<string, string>();
        protected internal string _encryptedValueFieldName;
        protected internal string _oaepPaddingDigestAlgorithm;

        protected internal void CheckJsonPathParameterValues()
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

        protected internal void ComputeEncryptionKeyFingerprintWhenNeeded()
        {
            try
            {
                if (_encryptionCertificate == null || !string.IsNullOrEmpty(_encryptionKeyFingerprint))
                {
                    // No encryption certificate set or certificate fingerprint already provided
                    return;
                }
                var encodedKey = RsaKeyUtils.GetEncoded(_encryptionCertificate.PublicKey);
                var keyFingerprintBytes = Sha256Digest(encodedKey);
                _encryptionKeyFingerprint = EncodingUtils.HexEncode(keyFingerprintBytes);
            }
            catch (Exception e)
            {
                throw new EncryptionException("Failed to compute encryption key fingerprint!", e);
            }
        }

        protected internal static byte[] Sha256Digest(byte[] inputBytes)
        {
            var sha256 = SHA256.Create();
            return sha256.ComputeHash(inputBytes);
        }
    }
}
