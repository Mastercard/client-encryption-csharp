using System;
using System.Text;
using System.Security.Cryptography;
using Mastercard.Developer.ClientEncryption.Core.Utils;
using Mastercard.Developer.ClientEncryption.Core.Encryption.JWE;

namespace Mastercard.Developer.ClientEncryption.Core.Encryption.AES
{
    internal class AESGCMAuthenticated
    {
        public byte[] Ciphertext { get; private set; }
        public byte[] AuthTag { get; private set; }

        internal AESGCMAuthenticated(byte[] ciphertext, byte[] authTag)
        {
            Ciphertext = ciphertext;
            AuthTag = authTag;
        }
    }

    class AESGCM
    {
        private AESGCM() { }

        internal static byte[] Decrypt(byte[] secretKeyBytes, JweObject jweObject)
        {
#if NETSTANDARD2_1
            byte[] plaintext;
            using (var aes = new AesGcm(secretKeyBytes))
            {
                byte[] nonce = Base64Utils.URLDecode(jweObject.Iv);
                byte[] aad = Encoding.ASCII.GetBytes(jweObject.RawHeader);
                byte[] authTag = Base64Utils.URLDecode(jweObject.AuthTag);
                byte[] ciphertext = Base64Utils.URLDecode(jweObject.CipherText);
                plaintext = new byte[ciphertext.Length];

                aes.Decrypt(nonce, ciphertext, authTag, plaintext, aad);
            }
            return plaintext;
#else
            throw new EncryptionException("AES/GCM/NoPadding is unsupported on .NET Standard < 2.1");
#endif
        }

        internal static AESGCMAuthenticated Encrypt(byte[] secretKeyBytes, byte[] nonce, byte[] plaintext, byte[] aad)
        {
#if NETSTANDARD2_1
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] authTag = new byte[AesGcm.TagByteSizes.MaxSize];
            using (var aes = new AesGcm(secretKeyBytes))
            {
                aes.Encrypt(nonce, plaintext, ciphertext, authTag, aad);
            }
            return new AESGCMAuthenticated(ciphertext, authTag);
#else
            throw new EncryptionException("AES/GCM/NoPadding is unsupported on .NET Standard < 2.1");
#endif
        }
    }
}
