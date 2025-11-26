using System;
using System.Text;
using Mastercard.Developer.ClientEncryption.Core.Utils;
using Mastercard.Developer.ClientEncryption.Core.Encryption.AES;
using System.Security.Cryptography.X509Certificates;
#pragma warning disable 1591 // "Missing XML comment for publicly visible type or member."

namespace Mastercard.Developer.ClientEncryption.Core.Encryption.JWE
{
    internal class JweObject
    {
        private const string A128CBC_HS256 = "A128CBC-HS256";
        private const string A192CBC_HS384 = "A192CBC-HS384";
        private const string A256CBC_HS512 = "A256CBC-HS512";
        private const string A256GCM = "A256GCM";
        private const string A128GCM = "A128GCM";
        private const string A192GCM = "A192GCM";

        public JweHeader Header { get; private set; }
        public string RawHeader { get; private set; }
        public string EncryptedKey { get; private set; }
        public string Iv { get; private set; }
        public string CipherText { get; private set; }
        public string AuthTag { get; private set; }

        public string Decrypt(JweConfig config)
        {
            var unwrappedKey = RsaEncryption.UnwrapSecretKey(config, Base64Utils.URLDecode(EncryptedKey), "SHA-256");
            if (unwrappedKey == null)
            {
                throw new EncryptionException($"Failed to unwrap key {EncryptedKey}");
            }

            var encryptionMethod = Header.Enc;

            byte[] plaintext;
            switch (encryptionMethod)
            {
                case A256GCM:
                    plaintext = AesGcm.Decrypt(unwrappedKey, this);
                    break;
                case A128GCM:
                    plaintext = AesGcm.Decrypt(unwrappedKey, this);
                    break;
                case A192GCM:
                    plaintext = AesGcm.Decrypt(unwrappedKey, this);
                    break;
                case A128CBC_HS256:
                    plaintext = AesCbc.Decrypt(unwrappedKey, this, config.EnableCbcHmacVerification);
                    break;
                case A192CBC_HS384:
                    plaintext = AesCbc.Decrypt(unwrappedKey, this, config.EnableCbcHmacVerification);
                    break;
                case A256CBC_HS512:
                    plaintext = AesCbc.Decrypt(unwrappedKey, this, config.EnableCbcHmacVerification);
                    break;
                default:
                    throw new EncryptionException($"Encryption method {encryptionMethod} is not supported");
            }
            return Encoding.UTF8.GetString(plaintext);
        }

        public static string Encrypt(JweConfig config, string payload, JweHeader header)
        {
            var encryptionMethod = header.Enc;
            
            // Determine CEK size based on encryption method
            int cekSize;
            bool isCbcHmac = false;
            switch (encryptionMethod)
            {
                case A128CBC_HS256:
                    cekSize = 256; // 128-bit AES + 128-bit HMAC
                    isCbcHmac = true;
                    break;
                case A192CBC_HS384:
                    cekSize = 384; // 192-bit AES + 192-bit HMAC
                    isCbcHmac = true;
                    break;
                case A256CBC_HS512:
                    cekSize = 512; // 256-bit AES + 256-bit HMAC
                    isCbcHmac = true;
                    break;
                case A128GCM:
                    cekSize = 128;
                    break;
                case A192GCM:
                    cekSize = 192;
                    break;
                case A256GCM:
                    cekSize = 256;
                    break;
                default:
                    // Default to A256GCM for backward compatibility
                    cekSize = 256;
                    break;
            }

            var cek = AesEncryption.GenerateCek(cekSize);
            var encryptedSecretKeyBytes = RsaEncryption.WrapSecretKey(config.EncryptionCertificate.GetRSAPublicKey(), cek, "SHA-256");
            var encryptedKey = Base64Utils.URLEncode(encryptedSecretKeyBytes);

            var payloadBytes = Encoding.UTF8.GetBytes(payload);

            var headerString = header.Json.ToString();
            var encodedHeader = Base64Utils.URLEncode(Encoding.UTF8.GetBytes(headerString));
            var aad = Encoding.ASCII.GetBytes(encodedHeader);

            if (isCbcHmac)
            {
                // Use 16-byte IV for CBC mode
                var iv = new byte[16];
                using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
                {
                    rng.GetBytes(iv);
                }
                
                var encrypted = AesCbc.Encrypt(cek, iv, payloadBytes, aad, config.EnableCbcHmacVerification);
                return Serialize(encodedHeader, encryptedKey, Base64Utils.URLEncode(iv), Base64Utils.URLEncode(encrypted.Ciphertext), Base64Utils.URLEncode(encrypted.AuthTag));
            }
            else
            {
                // Use 12-byte IV for GCM mode
                var iv = AesEncryption.GenerateIV();
                var encrypted = AesGcm.Encrypt(cek, iv, payloadBytes, aad);
                return Serialize(encodedHeader, encryptedKey, Base64Utils.URLEncode(iv), Base64Utils.URLEncode(encrypted.Ciphertext), Base64Utils.URLEncode(encrypted.AuthTag));
            }
        }

        public static JweObject Parse(string encryptedPayload)
        {
            var fields = encryptedPayload.Trim().Split('.');

            var jweObject = new JweObject();
            jweObject.RawHeader = fields[0];
            jweObject.Header = JweHeader.Parse(jweObject.RawHeader);
            jweObject.EncryptedKey = fields[1];
            jweObject.Iv = fields[2];
            jweObject.CipherText = fields[3];
            jweObject.AuthTag = fields[4];
            return jweObject;
        }

        internal static string Serialize(string header, string encryptedKey, string iv, string cipherText, string authTag)
        {
            return header + "." +
                encryptedKey +
                '.' +
                iv +
                '.' +
                cipherText +
                '.' +
                authTag;
        }
    }
}
