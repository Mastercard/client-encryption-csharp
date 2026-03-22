#pragma warning disable 1591 // "Missing XML comment for publicly visible type or member."

namespace Mastercard.Developer.ClientEncryption.Core.Encryption
{
    public class JweConfig : EncryptionConfig
    {
        /// <summary>
        /// Enable HMAC verification for CBC mode encryption algorithms (A128CBC-HS256, A192CBC-HS384, A256CBC-HS512).
        /// Default is false for backward compatibility.
        /// </summary>
        public bool EnableCbcHmacVerification { get; internal set; }

        internal JweConfig() {  }
    }
}
