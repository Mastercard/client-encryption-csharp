using System;
using System.Linq;
using System.Reflection;
using Mastercard.Developer.ClientEncryption.Core.Encryption;
using RestSharp.Portable;

namespace Mastercard.Developer.ClientEncryption.RestSharp.Interceptors
{
    /// <summary>
    /// A class for encrypting RestSharp requests and decrypting RestSharp responses.
    /// </summary>
    public class RestSharpFieldLevelEncryptionInterceptor
    {
        private readonly FieldLevelEncryptionConfig _config;

        public RestSharpFieldLevelEncryptionInterceptor(FieldLevelEncryptionConfig config)
        {
            _config = config;
        }

        /// <summary>
        ///  Encrypt RestSharp request payloads.
        /// </summary>
        /// <param name="request">A RestSharp request object</param>
        public void InterceptRequest(IRestRequest request)
        {
            if (request == null) throw new ArgumentNullException(nameof(request));

            try
            {
                // Check request actually has a payload
                var bodyParam = request.Parameters.FirstOrDefault(param => param.Type == ParameterType.RequestBody);
                if (bodyParam == null)
                {
                    // Nothing to encrypt
                    return;
                }
                var payload = bodyParam.Value.ToString();
                if (string.IsNullOrEmpty(payload))
                {
                    // Nothing to encrypt
                    return;
                }

                // Encrypt fields & update headers
                string encryptedPayload;
                if (_config.UseHttpHeaders())
                {
                    // Generate encryption params and add them as HTTP headers
                    var parameters = FieldLevelEncryptionParams.Generate(_config);
                    UpdateRequestHeader(request, _config.IvHeaderName, parameters.IvValue);
                    UpdateRequestHeader(request, _config.EncryptedKeyHeaderName, parameters.EncryptedKeyValue);
                    UpdateRequestHeader(request, _config.EncryptionCertificateFingerprintHeaderName, parameters.EncryptionCertificateFingerprintValue);
                    UpdateRequestHeader(request, _config.EncryptionKeyFingerprintHeaderName, parameters.EncryptionKeyFingerprintValue);
                    UpdateRequestHeader(request, _config.OaepPaddingDigestAlgorithmHeaderName, parameters.OaepPaddingDigestAlgorithmValue);
                    encryptedPayload = FieldLevelEncryption.EncryptPayload(payload, _config, parameters);
                }
                else
                {
                    // Encryption params will be stored in the payload
                    encryptedPayload = FieldLevelEncryption.EncryptPayload(payload, _config);
                }

                // Update body and content length
                bodyParam.Value = encryptedPayload;
                UpdateRequestHeader(request, "Content-Length", encryptedPayload.Length);
            }
            catch (EncryptionException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new EncryptionException("Failed to intercept and encrypt request!", e);
            }
        }

        /// <summary>
        /// Decrypt RestSharp response payloads.
        /// </summary>
        /// <param name="response">A RestSharp response object</param>
        public void InterceptResponse(IRestResponse response)
        {
            if (response == null) throw new ArgumentNullException(nameof(response));

            try
            {
                // Read response payload
                var encryptedPayload = response.Content;
                if (string.IsNullOrEmpty(encryptedPayload))
                {
                    // Nothing to decrypt
                    return;
                }

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

                // Update body and content length
                var contentTypeInfo = response.GetType().GetTypeInfo().GetDeclaredField("_content");
                contentTypeInfo.SetValue(response, new Lazy<string>(() => decryptedPayload));
                UpdateResponseHeader(response, "Content-Length", decryptedPayload.Length.ToString());
            }
            catch (EncryptionException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new EncryptionException("Failed to intercept and decrypt response!", e);
            }
        }

        private static void UpdateRequestHeader(IRestRequest request, string name, object value)
        {
            if (string.IsNullOrEmpty(name))
            {
                // Do nothing
                return;
            }

            request.AddOrUpdateHeader(name, value);
        }

        private static void UpdateResponseHeader(IRestResponse response, string name, string value)
        {
            if (string.IsNullOrEmpty(name))
            {
                // Do nothing
                return;
            }

            response.Headers.Remove(name);
            response.Headers.Add(name, value);
        }

        private static string ReadAndRemoveHeader(IRestResponse response, string name)
        {
            if (string.IsNullOrEmpty(name) || !response.Headers.Contains(name))
            {
                // Do nothing
                return null;
            }
            
            var value = response.Headers.GetValue(name);
            response.Headers.Remove(name);            
            return value;
        }
    }
}
