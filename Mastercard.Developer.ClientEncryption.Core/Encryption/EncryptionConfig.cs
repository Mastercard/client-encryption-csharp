using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
#pragma warning disable 1591 // "Missing XML comment for publicly visible type or member."

namespace Mastercard.Developer.ClientEncryption.Core.Encryption
{
    /// <summary>
    /// A POCO for storing the encryption/decryption configuration.
    /// </summary>
    public abstract class EncryptionConfig
    {
        /// <summary>
        /// The different methods of encryption
        /// </summary>
        public enum EncryptionScheme
        {
            Legacy,
            Jwe
        }

        /// <summary>
        /// The encryption scheme to be used
        /// </summary>
        public EncryptionScheme Scheme { get; internal set; }

        /// <summary>
        /// The digest algorithm to be used for the RSA OAEP padding. Example: "SHA-512".
        /// </summary>
        public string OaepPaddingDigestAlgorithm { get; internal set; }

        /// <summary>
        /// The SHA-256 hex-encoded digest of the key used for encryption (optional, the digest will be
        /// automatically computed if this field is null or empty).
        /// Example: "c3f8ef7053c4fb306f7476e7d1956f0aa992ff9dfdd5244b912a1d377ff3a84f"
        /// </summary>
        public string EncryptionKeyFingerprint { get; internal set; }

        /// <summary>
        /// A certificate object whose public key will be used for encryption.
        /// </summary>
        public X509Certificate2 EncryptionCertificate { get; internal set; }

        /// <summary>
        /// A private key object to be used for decryption.
        /// </summary>
        public RSA DecryptionKey { get; internal set; }

        /// <summary>
        /// A list of JSON paths to encrypt in request payloads.
        /// </summary>
        /// <example>
        /// new Dictionary&lt;string, string&gt;
        /// {
        ///     { "$.path.to.element.to.be.encrypted", "$.path.to.object.where.to.store.encryption.fields" }
        /// };
        /// </example>
        public Dictionary<string, string> EncryptionPaths { get; internal set; } = new Dictionary<string, string>();

        /// <summary>
        /// A list of JSON paths to decrypt in response payloads.
        /// </summary>
        /// <example>
        /// new Dictionary&lt;string, string&gt;
        /// {
        ///     { "$.path.to.object.with.encryption.fields", "$.path.where.to.write.decrypted.element" }
        /// };
        /// </example>
        public Dictionary<string, string> DecryptionPaths { get; internal set; } = new Dictionary<string, string>();

        /// <summary>
        /// The name of the payload field where to write/read the encrypted data value.
        /// </summary>
        public string EncryptedValueFieldName { get; internal set; }
    }
}
