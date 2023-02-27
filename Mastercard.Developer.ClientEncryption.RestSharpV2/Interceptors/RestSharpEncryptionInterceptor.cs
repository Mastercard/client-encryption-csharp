using System;
using System.Linq;
using System.Text.Json;
using System.Reflection;
using Mastercard.Developer.ClientEncryption.Core.Encryption;
using Header = RestSharp.HeaderParameter;
using RestSharp;
using System.Collections.ObjectModel;
using System.Collections.Generic;

namespace Mastercard.Developer.ClientEncryption.RestSharpV2.Interceptors
{
    /// <summary>
    /// A base class for encrypting RestSharp requests and decrypting RestSharp responses.
    /// </summary>
    public abstract class RestSharpEncryptionInterceptor
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="config"></param>
        /// <returns></returns>
        public static RestSharpEncryptionInterceptor From(EncryptionConfig config)
        {
            if (config.Scheme.Equals(EncryptionConfig.EncryptionScheme.Jwe))
            {
                return new RestSharpJweEncryptionInterceptor((JweConfig) config);
            }
            return new RestSharpFieldLevelEncryptionInterceptor((FieldLevelEncryptionConfig)config);
        }

        /// <summary>
        /// Encrypt RestSharp request payloads.
        /// </summary>
        /// <param name="request">A RestSharp request object</param>
        public void InterceptRequest(RestRequest request)
        {
            if (request == null) throw new ArgumentNullException(nameof(request));

            try
            {
                // We will have to intercept the response later
                request.OnBeforeDeserialization = InterceptResponse;
                
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
                    payload = JsonSerializer.Serialize(payload);
                }

                // Encrypt fields & update headers
                string encryptedPayload = EncryptPayload(request, payload.ToString());

                // Update body and content length
                request.RemoveParameter(bodyParam).AddJsonBody(payload);
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
        public void InterceptResponse(RestResponse response)
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

                // Decrypt fields & return
                string decryptedPayload = DecryptPayload(response, encryptedPayload);
                response.Content = decryptedPayload;
                UpdateResponseHeader(response, "Content-Length", decryptedPayload.Length);
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

        /// <summary>
        /// Encrypt a RestSharp request payload.
        /// </summary>
        /// <param name="request">A RestSharp request object</param>
        /// <param name="payload">The payload to be encrypted</param>
        /// <returns>The encrypted payload</returns>
        internal abstract string EncryptPayload(RestRequest request, string payload);

        /// <summary>
        /// Decrypt a RestSharp response payload
        /// </summary>
        /// <param name="response">A RestSharp response object</param>
        /// <param name="encryptedPayload">The encrypted payload to be decrypted</param>
        /// <returns>The decrypted payload</returns>
        internal abstract string DecryptPayload(RestResponse response, string encryptedPayload);

        internal static void UpdateResponseHeader(RestResponse response, string name, object value)
        {
            if (string.IsNullOrEmpty(name))
            {
                // Do nothing
                return;
            }

            // Scan
            foreach (Header p in response.Headers)
            {
                if (p.Name.Equals(name))
                {
                    List<Header> updatedHeaders = response.Headers.ToList();
                    updatedHeaders.Remove(p);
                    updatedHeaders.Add(new Header(name, value.ToString()));
                    response.Headers = updatedHeaders;
                    return;
                }
            }

            // If we get here, there is no such header, so add one
            var header = new HeaderParameter(name, value.ToString());
            response.Headers = response.Headers.Concat((System.Collections.Generic.IEnumerable<HeaderParameter>)header).ToList().AsReadOnly();
        }

        internal static void UpdateRequestHeader(RestRequest request, string name, object value)
        {
            if (string.IsNullOrEmpty(name))
            {
                // Do nothing
                return;
            }

            request.AddHeader(name, value.ToString());
        }

        internal static string ReadAndRemoveHeader(RestResponse response, string name)
        {
            var header = response.Headers.ToList().Find(h => h.Name == name);
            if (string.IsNullOrEmpty(name) || header == null)
            {
                // Do nothing
                return null;
            }

            // The "Headers" collection has been made read only, but we try to remove
            // the header from the response anyway.
            var headersField = response.GetType().GetTypeInfo().GetDeclaredField("<Headers>k__BackingField");
            if (headersField != null)
            {
                var updatedHeaders = response.Headers.ToList().FindAll(h => h.Name != name);
                headersField.SetValue(response, updatedHeaders);
            }

            return header.Value?.ToString() ?? string.Empty;
        }
    }
}
