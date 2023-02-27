using RestSharp;
using Mastercard.Developer.ClientEncryption.Core.Encryption;

namespace Mastercard.Developer.ClientEncryption.RestSharpV2.Interceptors
{
    /// <summary>
    /// A class for encrypting RestSharp requests and decrypting RestSharp responses,
    /// using Field Level Encryption
    /// </summary>
    public class RestSharpFieldLevelEncryptionInterceptor : RestSharpEncryptionInterceptor
    {
        private readonly FieldLevelEncryptionConfig _config;

        /// <summary>
        /// Constructor.
        /// </summary>
        public RestSharpFieldLevelEncryptionInterceptor(FieldLevelEncryptionConfig config)
        {
            _config = config;
        }

        /// <summary>
        /// Encrypt a RestSharp request payload.
        /// </summary>
        /// <param name="request">A RestSharp request object</param>
        /// <param name="payload">The payload to be encrypted</param>
        /// <returns>The encrypted payload</returns>
        internal override string EncryptPayload(RestRequest request, string payload)
        {
            // Encrypt fields & update headers
            string encryptedPayload;
            if (_config.UseHttpHeaders())
            {
                // Generate encryption params and add them as HTTP headers
                var parameters = FieldLevelEncryptionParams.Generate(_config);
                UpdateRequestHeader(request, _config.IvHeaderName, parameters.IvValue);
                UpdateRequestHeader(request, _config.EncryptedKeyHeaderName, parameters.EncryptedKeyValue);
                UpdateRequestHeader(request, _config.EncryptionCertificateFingerprintHeaderName, _config.EncryptionCertificateFingerprint);
                UpdateRequestHeader(request, _config.EncryptionKeyFingerprintHeaderName, _config.EncryptionKeyFingerprint);
                UpdateRequestHeader(request, _config.OaepPaddingDigestAlgorithmHeaderName, parameters.OaepPaddingDigestAlgorithmValue);
                encryptedPayload = FieldLevelEncryption.EncryptPayload(payload.ToString(), _config, parameters);
            }
            else
            {
                // Encryption params will be stored in the payload
                encryptedPayload = FieldLevelEncryption.EncryptPayload(payload.ToString(), _config);
            }
            return encryptedPayload;
        }

        /// <summary>
        /// Decrypt a RestSharp response payload
        /// </summary>
        /// <param name="response">A RestSharp response object</param>
        /// <param name="encryptedPayload">The encrypted payload to be decrypted</param>
        /// <returns>The decrypted payload</returns>
        internal override string DecryptPayload(RestResponse response, string encryptedPayload)
        {
            // Decrypt fields & update headers
            string decryptedPayload;
            if (_config.UseHttpHeaders())
            {
                // Read encryption params from HTTP headers and delete headers
                var ivValue = ReadAndRemoveHeader(response, _config.IvHeaderName);
                var encryptedKeyValue = ReadAndRemoveHeader(response, _config.EncryptedKeyHeaderName);
                var oaepPaddingDigestAlgorithmValue = ReadAndRemoveHeader(response, _config.OaepPaddingDigestAlgorithmHeaderName);
                ReadAndRemoveHeader(response, _config.EncryptionCertificateFingerprintHeaderName);
                ReadAndRemoveHeader(response, _config.EncryptionKeyFingerprintHeaderName);
                var parameters = new FieldLevelEncryptionParams(_config, ivValue, encryptedKeyValue, oaepPaddingDigestAlgorithmValue);
                decryptedPayload = FieldLevelEncryption.DecryptPayload(encryptedPayload, _config, parameters);
            }
            else
            {
                // Encryption params are stored in the payload
                decryptedPayload = FieldLevelEncryption.DecryptPayload(encryptedPayload, _config);
            }
            return decryptedPayload;
        }
    }
}
