using System;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Mastercard.Developer.ClientEncryption.Core.Utils;
#pragma warning disable 1591 // "Missing XML comment for publicly visible type or member."

namespace Mastercard.Developer.ClientEncryption.Core.Encryption.JWE
{
    public static class JweEncryption
    {
        private const string Algorithm = "RSA-OAEP-256";
        private const string Encryption = "A256GCM";
        private const string ContentType = "application/json";

        public static string EncryptPayload(string payload, JweConfig config)
        {
            try
            {
                // Parse the given payload
                var payloadToken = JToken.Parse(payload);

                // Encrypt
                foreach (var entry in config.EncryptionPaths)
                {
                    var jsonPathIn = entry.Key;
                    var jsonPathOut = entry.Value;
                    payloadToken = EncryptPayloadPath(payloadToken, jsonPathIn, jsonPathOut, config);
                }

                return payloadToken.ToString();
            }
            catch (Exception ex)
            {
                throw new EncryptionException("Payload encryption failed!", ex);
            }
        }

        public static string DecryptPayload(string payload, JweConfig config)
        {
            try
            {
                // Parse the given payload
                var payloadToken = JToken.Parse(payload);

                // Perform decryption
                foreach (var entry in config.DecryptionPaths)
                {
                    var jsonPathIn = entry.Key;
                    var jsonPathOut = entry.Value;
                    payloadToken = DecryptPayloadPath(payloadToken, jsonPathIn, jsonPathOut, config);
                }
                return payloadToken.ToString();
            }
            catch (Exception ex)
            {
                throw new EncryptionException("Payload decryption failed!", ex);
            }
        }

        private static JToken DecryptPayloadPath(JToken payload, string jsonPathIn, string jsonPathOut, JweConfig config)
        {
            var token = payload.SelectToken(jsonPathIn);
            if (JsonUtils.IsNullOrEmptyJson(token))
            {
                // Nothing to decrypt
                return payload;
            }

            // Read and remove encrypted data and encryption fields at the given JSON path
            var encryptedValue = ReadAndDeleteJsonKey(payload, token, config.EncryptedValueFieldName);
            if (string.IsNullOrEmpty(encryptedValue))
            {
                // Nothing to decrypt
                return payload;
            }
            var jweObject = JweObject.Parse(encryptedValue);
            var decryptedValue = jweObject.Decrypt(config);

            if ("$".Equals(jsonPathOut))
            {
                return JToken.Parse(decryptedValue);
            }

            JsonUtils.CheckOrCreateOutObject(payload, jsonPathOut);
            JsonUtils.AddDecryptedDataToPayload(payload, decryptedValue, jsonPathOut);

            // Remove the input
            token = payload.SelectToken(jsonPathIn);
            if (null != token && token.Parent != null)
            {
                token.Parent.Remove();
            }
            return payload;
        }

        private static string ReadAndDeleteJsonKey(JToken context, JToken token, string key)
        {
            if (string.IsNullOrEmpty(key)) return token.ToString();
            var value = context.SelectToken(key);
            if (null != value && null != value.Parent)
            {
                value.Parent.Remove();
            }
            return token.ToString();
        }

        private static JToken EncryptPayloadPath(JToken json, string jsonPathIn, string jsonPathOut, JweConfig config)
        {
            var token = json.SelectToken(jsonPathIn);
            if (JsonUtils.IsNullOrEmptyJson(token))
            {
                // Nothing to encrypt
                return json;
            }

            // Encode and encrypt
            var inJsonString = JsonUtils.SanitizeJson(token.ToString(Formatting.None));
            var header = new JweHeader(Algorithm, Encryption, config.EncryptionKeyFingerprint, ContentType);
            var encrypted = JweObject.Encrypt(config, inJsonString, header);

            // Delete data in the clear
            if ("$".Equals(jsonPathIn))
            {
                // Create a new object
                json = JObject.Parse("{}");
            }
            else
            {
                token.Parent.Remove();
            }

            JsonUtils.CheckOrCreateOutObject(json, jsonPathOut);
            var outJsonToken = json.SelectToken(jsonPathOut) as JObject;
            JsonUtils.AddOrReplaceJsonKey(outJsonToken, config.EncryptedValueFieldName, encrypted);
            return json;
        }
    }
}
