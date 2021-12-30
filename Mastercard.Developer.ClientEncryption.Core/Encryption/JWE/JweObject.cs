using System;
using System.Text;
using Mastercard.Developer.ClientEncryption.Core.Utils;
using Mastercard.Developer.ClientEncryption.Core.Encryption.AES;
using System.Security.Cryptography.X509Certificates;
#pragma warning disable 1591 // "Missing XML comment for publicly visible type or member."

namespace Mastercard.Developer.ClientEncryption.Core.Encryption.JWE
{
    public class JweObject
    {
        private const string A128CBC_HS256 = "A128CBC-HS256";
        private const string A256GCM = "A256GCM";

        public JweHeader Header { get; private set; }
        public string RawHeader { get; private set; }
        public string EncryptedKey { get; private set; }
        public string Iv { get; private set; }
        public string CipherText { get; private set; }
        public string AuthTag { get; private set; }

        public string Decrypt(JweConfig config)
        {
            byte[] unwrappedKey = RsaEncryption.UnwrapSecretKey(config, Base64Utils.URLDecode(EncryptedKey), "SHA-256");
            if (unwrappedKey == null)
            {
                throw new EncryptionException(String.Format("Failed to unwrap key {0}", EncryptedKey));
            }

            string encryptionMethod = Header.Enc;

            byte[] plaintext;
            if (A256GCM.Equals(encryptionMethod))
            {
                plaintext = AESGCM.Decrypt(unwrappedKey, this);
            }
            else if (A128CBC_HS256.Equals(encryptionMethod))
            {
                plaintext = AESCBC.Decrypt(unwrappedKey, this);
            }
            else
            {
                throw new EncryptionException(String.Format("Encryption method {0} is not supported", encryptionMethod));
            }
            return Encoding.UTF8.GetString(plaintext);
        }

        public static string Encrypt(JweConfig config, String payload, JweHeader header)
        {
            byte[] cek = AesEncryption.GenerateCek(256);
            byte[] encryptedSecretKeyBytes = RsaEncryption.WrapSecretKey(config.EncryptionCertificate.GetRSAPublicKey(), cek, "SHA-256");
            string encryptedKey = Base64Utils.URLEncode(encryptedSecretKeyBytes);

            byte[] iv = AesEncryption.GenerateIV();
            byte[] payloadBytes = Encoding.UTF8.GetBytes(payload);

            string headerString = header.Json.ToString();
            string encodedHeader = Base64Utils.URLEncode(Encoding.UTF8.GetBytes(headerString));
            byte[] aad = Encoding.ASCII.GetBytes(encodedHeader);

            var encrypted = AESGCM.Encrypt(cek, iv, payloadBytes, aad);
            return Serialize(encodedHeader, encryptedKey, Base64Utils.URLEncode(iv), Base64Utils.URLEncode(encrypted.Ciphertext), Base64Utils.URLEncode(encrypted.AuthTag));
        }

        public static JweObject Parse(String encryptedPayload)
        {
            string[] fields = encryptedPayload.Trim().Split('.');

            JweObject jweObject = new JweObject();
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
