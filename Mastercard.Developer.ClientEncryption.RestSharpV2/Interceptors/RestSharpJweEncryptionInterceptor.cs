using RestSharp;
using Mastercard.Developer.ClientEncryption.Core.Encryption;
using Mastercard.Developer.ClientEncryption.Core.Encryption.JWE;

namespace Mastercard.Developer.ClientEncryption.RestSharpV2.Interceptors
{
    /// <summary>
    /// A class for encrypting RestSharp requests and decrypting RestSharp responses,
    /// using JSON Web Encryption.
    /// </summary>
    public class RestSharpJweEncryptionInterceptor : RestSharpEncryptionInterceptor
    {
        private readonly JweConfig _config;

        /// <summary>
        /// Constructor.
        /// </summary>
        public RestSharpJweEncryptionInterceptor(JweConfig config)
        {
            _config = config;
        }

        /// <summary>
        /// Encrypt a RestSharp request payload.
        /// </summary>
        /// <param name="request">A RestSharp request object</param>
        /// <param name="payload">The payload to be encrypted</param>
        /// <returns>The encrypted payload</returns>
        internal override string EncryptPayload(IRestRequest request, string payload)
        {
            return JweEncryption.EncryptPayload(payload, _config);
        }

        /// <summary>
        /// Decrypt a RestSharp response payload
        /// </summary>
        /// <param name="response">A RestSharp response object</param>
        /// <param name="encryptedPayload">The encrypted payload to be decrypted</param>
        /// <returns>The decrypted payload</returns>
        internal override string DecryptPayload(IRestResponse response, string encryptedPayload)
        {
            return JweEncryption.DecryptPayload(encryptedPayload, _config);
        }
    }
}
