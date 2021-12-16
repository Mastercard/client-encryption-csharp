#pragma warning disable 1591 // "Missing XML comment for publicly visible type or member."

namespace Mastercard.Developer.ClientEncryption.Core.Encryption
{
    /// <summary>
    /// A POCO for storing the encryption/decryption configuration.
    /// </summary>
    public class FieldLevelEncryptionConfig : EncryptionConfig
    {
        /// <summary>
        /// The different ways of encoding the field and header values.
        /// </summary>
        public enum FieldValueEncoding
        {
            Base64,
            Hex
        }

        internal FieldLevelEncryptionConfig() {}

        /// <summary>
        /// The SHA-256 hex-encoded digest of the certificate used for encryption (optional, the digest will be
        /// automatically computed if this field is null or empty).
        /// Example: "4d9d7540be320429ffc8e6506f054525816e2d0e95a85247d5b58be713f28be0"
        /// </summary>
        public string EncryptionCertificateFingerprint { get; internal set; }

        /// <summary>
        /// The name of the payload field where to write/read the digest algorithm used for
        /// the RSA OAEP padding (optional, the field won't be set if the name is null or empty).
        /// </summary>
        public string OaepPaddingDigestAlgorithmFieldName { get; internal set; }

        /// <summary>
        /// The name of the HTTP header where to write/read the digest algorithm used for
        /// the RSA OAEP padding (optional, the header won't be set if the name is null or empty).
        /// </summary>
        public string OaepPaddingDigestAlgorithmHeaderName { get; internal set; }

        /// <summary>
        /// The name of the payload field where to write/read the initialization vector value.
        /// </summary>
        public string IvFieldName { get; internal set; }

        /// <summary>
        /// The name of the header where to write/read the initialization vector value.
        /// </summary>
        public string IvHeaderName { get; internal set; }

        /// <summary>
        /// The name of the payload field where to write/read the one-time usage encrypted symmetric key.
        /// </summary>
        public string EncryptedKeyFieldName { get; internal set; }

        /// <summary>
        /// The name of the header where to write/read the one-time usage encrypted symmetric key.
        /// </summary>
        public string EncryptedKeyHeaderName { get; internal set; }

        /// <summary>
        /// The name of the payload field where to write/read the digest of the encryption
        /// certificate (optional, the field won't be set if the name is null or empty).
        /// </summary>
        public string EncryptionCertificateFingerprintFieldName { get; internal set; }

        /// <summary>
        /// The name of the header where to write/read the digest of the encryption
        /// certificate (optional, the header won't be set if the name is null or empty).
        /// </summary>
        public string EncryptionCertificateFingerprintHeaderName { get; internal set; }

        /// <summary>
        /// The name of the payload field where to write/read the digest of the encryption
        /// key (optional, the field won't be set if the name is null or empty).
        /// </summary>
        public string EncryptionKeyFingerprintFieldName { get; internal set; }

        /// <summary>
        /// The name of the header where to write/read the digest of the encryption
        /// key (optional, the header won't be set if the name is null or empty).
        /// </summary>
        public string EncryptionKeyFingerprintHeaderName { get; internal set; }

        /// <summary>
        /// How the field/header values have to be encoded.
        /// </summary>
        public FieldValueEncoding ValueEncoding { get; internal set; }

        /// <summary>
        /// If the encryption parameters must be written to/read from HTTP payloads.
        /// </summary>
        public bool UseHttpPayloads() => !string.IsNullOrEmpty(EncryptedKeyFieldName) && !string.IsNullOrEmpty(IvFieldName);

        /// <summary>
        /// If the encryption parameters must be written to/read from HTTP headers.
        /// </summary>
        public bool UseHttpHeaders() => !string.IsNullOrEmpty(EncryptedKeyHeaderName) && !string.IsNullOrEmpty(IvHeaderName);
    }
}
