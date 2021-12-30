using System;
using System.IO;
using System.Security.Cryptography;
using Mastercard.Developer.ClientEncryption.Core.Utils;
using Mastercard.Developer.ClientEncryption.Core.Encryption.JWE;

namespace Mastercard.Developer.ClientEncryption.Core.Encryption.AES
{
    internal static class AesCbc
    {
        public static byte[] Decrypt(byte[] secretKeyBytes, JweObject jweObject)
        {
            // Extract the encryption key
            byte[] aesKey = new byte[16];
            Array.Copy(secretKeyBytes, 16, aesKey, 0, aesKey.Length);

            byte[] plaintext;
            using (var aes = Aes.Create())
            {
                aes.Key = aesKey;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.IV = Base64Utils.URLDecode(jweObject.Iv);

                byte[] ciphertext = Base64Utils.URLDecode(jweObject.CipherText);
                using (var decryptor = aes.CreateDecryptor())
                {
                    using (var memoryStream = new MemoryStream(ciphertext))
                    {
                        using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                        {
                            var output = new MemoryStream();
                            var decrypted = new byte[Math.Min(1024, ciphertext.Length)];
                            int byteCount;
                            while ((byteCount = cryptoStream.Read(decrypted, 0, decrypted.Length)) > 0)
                            {
                                output.Write(decrypted, 0, byteCount);
                            }
                            plaintext = output.ToArray();
                        }
                    }
                }
            }
            return plaintext;
        }
    }
}
