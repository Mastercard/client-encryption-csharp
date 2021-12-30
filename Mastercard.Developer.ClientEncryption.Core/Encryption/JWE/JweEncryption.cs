using System;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Mastercard.Developer.ClientEncryption.Core.Utils;
#pragma warning disable 1591 // "Missing XML comment for publicly visible type or member."

namespace Mastercard.Developer.ClientEncryption.Core.Encryption.JWE
{
    public class JweEncryption
    {
        private const string ALGORITHM = "RSA-OAEP-256";
        private const string ENCRYPTION = "A256GCM";
        private const string CONTENT_TYPE = "application/json";

        internal JweEncryption() { }

        public static string EncryptPayload(string payload, JweConfig config)
        {
            try
            {
                // Parse the given payload
                JToken json = JObject.Parse(payload);

                // Encrypt
                foreach (var entry in config.EncryptionPaths)
                {
                    string jsonPathIn = entry.Key;
                    string jsonPathOut = entry.Value;
                    json = EncryptPayloadPath(json, jsonPathIn, jsonPathOut, config);
                }

                return json.ToString();
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
                JToken json = JObject.Parse(payload);

                // Perform decryption
                foreach (var entry in config.DecryptionPaths)
                {
                    string jsonPathIn = entry.Key;
                    string jsonPathOut = entry.Value;
                    json = DecryptPayloadPath(json, jsonPathIn, jsonPathOut, config);
                }
                return json.ToString();
            }
            catch (Exception ex)
            {
                throw new EncryptionException("Payload decryption failed!", ex);
            }
        }

        private static JToken DecryptPayloadPath(JToken payload, string jsonPathIn, string jsonPathOut, JweConfig config)
        {
            JToken token = payload.SelectToken(jsonPathIn);
            if (JsonUtils.IsNullOrEmptyJson( token ))
            {
                // Nothing to decrypt
                return payload;
            }

            // Read and remove encrypted data and encryption fields at the given JSON path
            string encryptedValue = ReadAndDeleteJsonKey(payload, token, config.EncryptedValueFieldName);
            if (string.IsNullOrEmpty(encryptedValue))
            {
                // Nothing to decrypt
                return payload;
            }
            JweObject jweObject = JweObject.Parse(encryptedValue);
            string decryptedValue = jweObject.Decrypt(config);

            if ("$".Equals(jsonPathOut))
            {
                return JObject.Parse(decryptedValue);
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
            if (!string.IsNullOrEmpty(key))
            {
                var value = context.SelectToken(key);
                if (null != value && null != value.Parent)
                {
                    value.Parent.Remove();
                }
            }
            return token.ToString();
        }

        private static JToken EncryptPayloadPath(JToken json, string jsonPathIn, string jsonPathOut, JweConfig config)
        {
            JToken token = json.SelectToken(jsonPathIn);
            if (JsonUtils.IsNullOrEmptyJson(token))
            {
                // Nothing to encrypt
                return json;
            }

            // Encode and encrypt
            string inJsonString = JsonUtils.SanitizeJson(token.ToString(Formatting.None));
            JweHeader header = new JweHeader(ALGORITHM, ENCRYPTION, config.EncryptionKeyFingerprint, CONTENT_TYPE);
            string encrypted = JweObject.Encrypt(config, inJsonString, header);

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
            return outJsonToken;
        }
    }
}
