using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Mastercard.Developer.ClientEncryption.Core.Utils;
using Newtonsoft.Json.Linq;
// ReSharper disable ReturnTypeCanBeEnumerable.Local
// ReSharper disable ParameterOnlyUsedForPreconditionCheck.Local

namespace Mastercard.Developer.ClientEncryption.Core.Encryption
{
    /// <summary>
    /// Performs field level encryption on HTTP payloads.
    /// </summary>
    public static class FieldLevelEncryption
    {
        private const CipherMode SymmetricCipherMode = CipherMode.CBC;
        private const PaddingMode SymmetricPaddingMode = PaddingMode.PKCS7;

        /// <summary>
        /// Encrypt parts of a JSON payload using the given parameters and configuration.
        /// </summary>
        /// <param name="payload">A JSON string</param>
        /// <param name="config">A <see cref="FieldLevelEncryptionConfig"/> instance</param>
        /// <param name="parameters">A <see cref="FieldLevelEncryptionParams"/> instance</param>
        /// <returns>The updated payload</returns>
        /// <exception cref="EncryptionException"/>
        public static string EncryptPayload(string payload, FieldLevelEncryptionConfig config, FieldLevelEncryptionParams parameters = null)
        {
            if (payload == null) throw new ArgumentNullException(nameof(payload));
            if (config == null) throw new ArgumentNullException(nameof(config));

            try
            {
                // Parse the given payload
                var payloadToken = JToken.Parse(payload);

                // Perform encryption (if needed)
                foreach (var jsonPathIn in config.EncryptionPaths.Keys)
                {
                    var jsonPathOut = config.EncryptionPaths[jsonPathIn];
                    payloadToken = EncryptPayloadPath(payloadToken, jsonPathIn, jsonPathOut, config, parameters);
                }

                // Return the updated payload
                return payloadToken.ToString();
            }
            catch (EncryptionException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new EncryptionException("Payload encryption failed!", e);
            }
        }

        /// <summary>
        /// Decrypt parts of a JSON payload using the given parameters and configuration.
        /// </summary>
        /// <param name="payload">A JSON string</param>
        /// <param name="config">A <see cref="FieldLevelEncryptionConfig"/> instance</param>
        /// <param name="parameters">A <see cref="FieldLevelEncryptionParams"/> instance</param>
        /// <returns>The updated payload</returns>
        /// <exception cref="EncryptionException"/>
        public static string DecryptPayload(string payload, FieldLevelEncryptionConfig config, FieldLevelEncryptionParams parameters = null)
        {
            if (payload == null) throw new ArgumentNullException(nameof(payload));
            if (config == null) throw new ArgumentNullException(nameof(config));

            try
            {
                // Parse the given payload
                var payloadToken = JToken.Parse(payload);

                // Perform decryption (if needed)
                foreach (var jsonPathIn in config.DecryptionPaths.Keys)
                {
                    var jsonPathOut = config.DecryptionPaths[jsonPathIn];
                    payloadToken = DecryptPayloadPath(payloadToken, jsonPathIn, jsonPathOut, config, parameters);
                }

                // Return the updated payload
                return payloadToken.ToString();
            }
            catch (EncryptionException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new EncryptionException("Payload decryption failed!", e);
            }
        }

        private static JToken EncryptPayloadPath(JToken payloadToken, string jsonPathIn, string jsonPathOut,
                                               FieldLevelEncryptionConfig config, FieldLevelEncryptionParams parameters)
        {
            if (payloadToken == null) throw new ArgumentNullException(nameof(payloadToken));
            if (jsonPathIn == null) throw new ArgumentNullException(nameof(jsonPathIn));
            if (jsonPathOut == null) throw new ArgumentNullException(nameof(jsonPathOut));

            var inJsonToken = payloadToken.SelectToken(jsonPathIn);
            if (inJsonToken == null)
            {
                // Nothing to encrypt
                return payloadToken;
            }

            if (parameters == null) {
                // Generate encryption params
                parameters = FieldLevelEncryptionParams.Generate(config);
            }

            // Encrypt data at the given JSON path
            var inJsonString = JsonUtils.SanitizeJson(inJsonToken.ToString());
            var inJsonBytes = Encoding.ASCII.GetBytes(inJsonString);
            var encryptedValueBytes = EncryptBytes(parameters.GetSecretKeyBytes(), parameters.GetIvBytes(), inJsonBytes);
            var encryptedValue = EncodingUtils.EncodeBytes(encryptedValueBytes, config.ValueEncoding);

            // Delete data in clear
            if (!"$".Equals(jsonPathIn))
            {
                inJsonToken.Parent.Remove();
            }
            else
            {
                // We need a JObject (we can't work with a JArray for instance)
                payloadToken = JObject.Parse("{}");
            }

            // Add encrypted data and encryption fields at the given JSON path
            JsonUtils.CheckOrCreateOutObject(payloadToken, jsonPathOut);
            var outJsonToken = payloadToken.SelectToken(jsonPathOut) as JObject;
            JsonUtils.AddOrReplaceJsonKey(outJsonToken, config.EncryptedValueFieldName, encryptedValue);
            if (!string.IsNullOrEmpty(config.IvFieldName)) {
                JsonUtils.AddOrReplaceJsonKey(outJsonToken, config.IvFieldName, parameters.IvValue);
            }
            if (!string.IsNullOrEmpty(config.EncryptedKeyFieldName)) {
                JsonUtils.AddOrReplaceJsonKey(outJsonToken, config.EncryptedKeyFieldName, parameters.EncryptedKeyValue);
            }
            if (!string.IsNullOrEmpty(config.EncryptionCertificateFingerprintFieldName)) {
                JsonUtils.AddOrReplaceJsonKey(outJsonToken, config.EncryptionCertificateFingerprintFieldName, config.EncryptionCertificateFingerprint);
            }
            if (!string.IsNullOrEmpty(config.EncryptionKeyFingerprintFieldName)) {
                JsonUtils.AddOrReplaceJsonKey(outJsonToken, config.EncryptionKeyFingerprintFieldName, config.EncryptionKeyFingerprint);
            }
            if (!string.IsNullOrEmpty(config.OaepPaddingDigestAlgorithmFieldName)) {
                JsonUtils.AddOrReplaceJsonKey(outJsonToken, config.OaepPaddingDigestAlgorithmFieldName, parameters.OaepPaddingDigestAlgorithmValue);
            }

            return payloadToken;
        }

        private static JToken DecryptPayloadPath(JToken payloadToken, string jsonPathIn, string jsonPathOut,
                                               FieldLevelEncryptionConfig config, FieldLevelEncryptionParams parameters)
        {
            if (payloadToken == null) throw new ArgumentNullException(nameof(payloadToken));
            if (jsonPathIn == null) throw new ArgumentNullException(nameof(jsonPathIn));
            if (jsonPathOut == null) throw new ArgumentNullException(nameof(jsonPathOut));

            var inJsonToken = payloadToken.SelectToken(jsonPathIn);
            if (inJsonToken == null)
            {
                // Nothing to decrypt
                return payloadToken;
            }

            // Read and remove encrypted data and encryption fields at the given JSON path
            JsonUtils.AssertIsObject(inJsonToken, jsonPathIn);
            var encryptedValueJsonToken = ReadAndDeleteJsonKey(inJsonToken, config.EncryptedValueFieldName);
            if (IsNullOrEmptyJson(encryptedValueJsonToken))
            {
                // Nothing to decrypt
                return payloadToken;
            }

            if (!config.UseHttpPayloads() && parameters == null) {
                throw new InvalidOperationException("Encryption params have to be set when not stored in HTTP payloads!");
            }

            if (parameters == null) {
                // Read encryption params from the payload
                var oaepDigestAlgorithmJsonToken = ReadAndDeleteJsonKey(inJsonToken, config.OaepPaddingDigestAlgorithmFieldName);
                var oaepDigestAlgorithm = IsNullOrEmptyJson(oaepDigestAlgorithmJsonToken) ? config.OaepPaddingDigestAlgorithm : oaepDigestAlgorithmJsonToken;
                var encryptedKeyJsonToken = ReadAndDeleteJsonKey(inJsonToken, config.EncryptedKeyFieldName);
                var ivJsonToken = ReadAndDeleteJsonKey(inJsonToken, config.IvFieldName);
                ReadAndDeleteJsonKey(inJsonToken, config.EncryptionCertificateFingerprintFieldName);
                ReadAndDeleteJsonKey(inJsonToken, config.EncryptionKeyFingerprintFieldName);
                parameters = new FieldLevelEncryptionParams(config, ivJsonToken, encryptedKeyJsonToken, oaepDigestAlgorithm);
            }

            // Decrypt data
            var encryptedValueBytes = EncodingUtils.DecodeValue(encryptedValueJsonToken, config.ValueEncoding);
            var decryptedValueBytes = DecryptBytes(parameters.GetSecretKeyBytes(), parameters.GetIvBytes(), encryptedValueBytes);

            // Add decrypted data at the given JSON path
            var decryptedValue = JsonUtils.SanitizeJson(Encoding.UTF8.GetString(decryptedValueBytes));
            if ("$".Equals(jsonPathOut))
            {
                // The decrypted JSON is the new body
                return JToken.Parse(decryptedValue);
            }
            else
            {
                JsonUtils.CheckOrCreateOutObject(payloadToken, jsonPathOut);
                JsonUtils.AddDecryptedDataToPayload(payloadToken, decryptedValue, jsonPathOut);
                
                // Remove the input if now empty
                inJsonToken = payloadToken.SelectToken(jsonPathIn);
                if (inJsonToken.Type == JTokenType.Object && !inJsonToken.HasValues)
                {
                    inJsonToken.Parent.Remove();
                }
            }
            
            return payloadToken;
        }

        internal static byte[] EncryptBytes(byte[] keyBytes, byte[] ivBytes, byte[] bytes)
        {
            using (var aes = Aes.Create())
            {
                if (aes == null)
                {
                    throw new EncryptionException("Failed to encrypt bytes, AES instance == null!");
                }

                aes.Key = keyBytes;
                aes.IV = ivBytes;
                aes.Mode = SymmetricCipherMode;
                aes.Padding = SymmetricPaddingMode;

                var encryptor = aes.CreateEncryptor(keyBytes, ivBytes);
                using (var memoryStream = new MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(bytes, 0, bytes.Length);
                        cryptoStream.FlushFinalBlock();
                        return memoryStream.ToArray();
                    }
                }
            }
        }

        internal static byte[] DecryptBytes(byte[] keyBytes, byte[] ivBytes, byte[] encryptedBytes)
        {
            using (var aes = Aes.Create())
            {
                if (aes == null)
                {
                    throw new EncryptionException("Failed to decrypt bytes, AES instance == null!");
                }

                aes.Key = keyBytes;
                aes.IV = ivBytes;
                aes.Mode = SymmetricCipherMode;
                aes.Padding = SymmetricPaddingMode;

                var decryptor = aes.CreateDecryptor(keyBytes, ivBytes);
                using (var memoryStream = new MemoryStream(encryptedBytes))
                {
                    using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        var output = new MemoryStream();
                        var decrypted = new byte[1024];
                        int byteCount;
                        while ((byteCount = cryptoStream.Read(decrypted, 0, decrypted.Length)) > 0)
                        {
                            output.Write(decrypted, 0, byteCount);
                        }
                        return output.ToArray();
                    }
                }
            }
        }

        private static string ReadAndDeleteJsonKey(JToken inJsonToken, string key)
        {
            if (string.IsNullOrEmpty(key))
            {
                // Do nothing
                return null;
            }
            var value = inJsonToken.SelectToken(key);
            if (null == value)
            {
                // Do nothing
                return null;
            }
            value.Parent.Remove();
            return value.ToString();
        }

        private static bool IsNullOrEmptyJson(object element) => null == element;
    }
}
