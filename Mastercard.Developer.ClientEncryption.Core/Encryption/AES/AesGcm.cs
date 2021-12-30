using System;
using System.Text;
using System.Security.Cryptography;
using Mastercard.Developer.ClientEncryption.Core.Utils;
using Mastercard.Developer.ClientEncryption.Core.Encryption.JWE;

namespace Mastercard.Developer.ClientEncryption.Core.Encryption.AES
{
    internal class AesGcmAuthenticated
    {
        public byte[] Ciphertext { get; private set; }
        public byte[] AuthTag { get; private set; }

        internal AesGcmAuthenticated(byte[] ciphertext, byte[] authTag)
        {
            Ciphertext = ciphertext;
            AuthTag = authTag;
        }
    }

    internal static class AesGcm
    {
        internal static byte[] Decrypt(byte[] secretKeyBytes, JweObject jweObject)
        {
#if NETSTANDARD2_1
            byte[] plaintext;
            using (var aes = new System.Security.Cryptography.AesGcm(secretKeyBytes))
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

        internal static AesGcmAuthenticated Encrypt(byte[] secretKeyBytes, byte[] nonce, byte[] plaintext, byte[] aad)
        {
#if NETSTANDARD2_1
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] authTag = new byte[System.Security.Cryptography.AesGcm.TagByteSizes.MaxSize];
            using (var aes = new System.Security.Cryptography.AesGcm(secretKeyBytes))
            {
                aes.Encrypt(nonce, plaintext, ciphertext, authTag, aad);
            }
            return new AesGcmAuthenticated(ciphertext, authTag);
#else
            throw new EncryptionException("AES/GCM/NoPadding is unsupported on .NET Standard < 2.1");
#endif
        }
    }
}
