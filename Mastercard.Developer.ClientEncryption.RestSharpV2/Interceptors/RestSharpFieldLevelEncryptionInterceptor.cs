using System;
using System.Linq;
using System.Reflection;
using Mastercard.Developer.ClientEncryption.Core.Encryption;
using Newtonsoft.Json;
using RestSharp;

namespace Mastercard.Developer.ClientEncryption.RestSharpV2.Interceptors
{
    /// <summary>
    /// A class for encrypting RestSharp requests and decrypting RestSharp responses.
    /// </summary>
    public class RestSharpFieldLevelEncryptionInterceptor
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
                if (bodyParam?.Value == null)
                {
                    // Nothing to encrypt
                    return;
                }

                var payload = bodyParam.Value;
                if (!(payload is string))
                {
                    payload = request.JsonSerializer.Serialize(payload);
                }

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

                // Update body and content length
                bodyParam.Value = JsonConvert.DeserializeObject(encryptedPayload);
                request.OnBeforeDeserialization = InterceptResponse;
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

                response.Content = decryptedPayload;
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

            request.AddHeader(name, value.ToString());
        }

        private static string ReadAndRemoveHeader(IRestResponse response, string name)
        {
            var header = response.Headers.ToList().Find(h => h.Name == name);
            if (string.IsNullOrEmpty(name) || header == null)
            {
                // Do nothing
                return null;
            }

            // Headers has been made read only
            var headers = response.GetType().GetTypeInfo().GetDeclaredField("<Headers>k__BackingField");
            var newHeaders = response.Headers.ToList().FindAll(h => h.Name != name);
            headers.SetValue(response, newHeaders);

            return header.Value?.ToString() ?? string.Empty;
        }
    }
}
