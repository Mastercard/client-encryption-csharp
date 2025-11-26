using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Mastercard.Developer.ClientEncryption.Core.Utils;
using Mastercard.Developer.ClientEncryption.Core.Encryption.JWE;

namespace Mastercard.Developer.ClientEncryption.Core.Encryption.AES
{
    internal class AesCbcAuthenticated
    {
        public byte[] Ciphertext { get; private set; }
        public byte[] AuthTag { get; private set; }

        internal AesCbcAuthenticated(byte[] ciphertext, byte[] authTag)
        {
            Ciphertext = ciphertext;
            AuthTag = authTag;
        }
    }

    internal static class AesCbc
    {
        public static byte[] Decrypt(byte[] secretKeyBytes, JweObject jweObject, bool enableHmacVerification)
        {
            // Determine key sizes based on the total secret key length
            // A128CBC-HS256: 32 bytes (16 for HMAC, 16 for AES)
            // A192CBC-HS384: 48 bytes (24 for HMAC, 24 for AES)
            // A256CBC-HS512: 64 bytes (32 for HMAC, 32 for AES)
            int keyLength = secretKeyBytes.Length / 2;
            
            // Extract HMAC key (first half) and encryption key (second half)
            byte[] hmacKey = new byte[keyLength];
            byte[] aesKey = new byte[keyLength];
            Array.Copy(secretKeyBytes, 0, hmacKey, 0, keyLength);
            Array.Copy(secretKeyBytes, keyLength, aesKey, 0, keyLength);

            // Decode values needed for both HMAC and decryption
            byte[] authTag = Base64Utils.URLDecode(jweObject.AuthTag);
            byte[] iv = Base64Utils.URLDecode(jweObject.Iv);
            byte[] ciphertext = Base64Utils.URLDecode(jweObject.CipherText);

            // Verify HMAC only if enabled
            if (enableHmacVerification)
            {
                byte[] aad = Encoding.ASCII.GetBytes(jweObject.RawHeader);

                if (!VerifyHmac(hmacKey, aad, iv, ciphertext, authTag))
                {
                    throw new EncryptionException("HMAC verification failed");
                }
            }

            // Decrypt
            byte[] plaintext;
            using (var aes = Aes.Create())
            {
                aes.Key = aesKey;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.IV = iv;

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

        internal static AesCbcAuthenticated Encrypt(byte[] secretKeyBytes, byte[] iv, byte[] plaintext, byte[] aad, bool enableHmacGeneration)
        {
            // Determine key sizes based on the total secret key length
            int keyLength = secretKeyBytes.Length / 2;
            
            // Extract HMAC key (first half) and encryption key (second half)
            byte[] hmacKey = new byte[keyLength];
            byte[] aesKey = new byte[keyLength];
            Array.Copy(secretKeyBytes, 0, hmacKey, 0, keyLength);
            Array.Copy(secretKeyBytes, keyLength, aesKey, 0, keyLength);

            // Encrypt
            byte[] ciphertext;
            using (var aes = Aes.Create())
            {
                aes.Key = aesKey;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.IV = iv;

                using (var encryptor = aes.CreateEncryptor())
                {
                    using (var memoryStream = new MemoryStream())
                    {
                        using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                        {
                            cryptoStream.Write(plaintext, 0, plaintext.Length);
                            cryptoStream.FlushFinalBlock();
                            ciphertext = memoryStream.ToArray();
                        }
                    }
                }
            }

            // Compute HMAC only if enabled
            byte[] authTag;
            if (enableHmacGeneration)
            {
                byte[] fullHmac = ComputeHmac(hmacKey, aad, iv, ciphertext);
                // Truncate to half the length for the authentication tag (same as keyLength)
                authTag = new byte[keyLength];
                Array.Copy(fullHmac, 0, authTag, 0, keyLength);
            }
            else
            {
                authTag = new byte[0]; // Empty auth tag when HMAC is disabled
            }

            return new AesCbcAuthenticated(ciphertext, authTag);
        }

        private static bool VerifyHmac(byte[] hmacKey, byte[] aad, byte[] iv, byte[] ciphertext, byte[] authTag)
        {
            byte[] expectedTag = ComputeHmac(hmacKey, aad, iv, ciphertext);
            
            // Truncate to half the length for the authentication tag
            int tagLength = hmacKey.Length;
            byte[] truncatedExpectedTag = new byte[tagLength];
            Array.Copy(expectedTag, 0, truncatedExpectedTag, 0, tagLength);

            // Constant-time comparison
            if (authTag.Length != truncatedExpectedTag.Length)
            {
                return false;
            }

            int result = 0;
            for (int i = 0; i < authTag.Length; i++)
            {
                result |= authTag[i] ^ truncatedExpectedTag[i];
            }

            return result == 0;
        }

        private static byte[] ComputeHmac(byte[] hmacKey, byte[] aad, byte[] iv, byte[] ciphertext)
        {
            // Construct Additional Authenticated Data (AAD) length in bits as 64-bit big-endian
            long aadLengthBits = (long)aad.Length * 8;
            byte[] aadLength = BitConverter.GetBytes(aadLengthBits);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(aadLength);
            }

            // Concatenate: AAD || IV || Ciphertext || AAD Length
            var hmacInput = new MemoryStream();
            hmacInput.Write(aad, 0, aad.Length);
            hmacInput.Write(iv, 0, iv.Length);
            hmacInput.Write(ciphertext, 0, ciphertext.Length);
            hmacInput.Write(aadLength, 0, aadLength.Length);

            // Determine HMAC algorithm based on key length
            HMAC hmac;
            switch (hmacKey.Length)
            {
                case 16: // HS256
                    hmac = new HMACSHA256(hmacKey);
                    break;
                case 24: // HS384
                    hmac = new HMACSHA384(hmacKey);
                    break;
                case 32: // HS512
                    hmac = new HMACSHA512(hmacKey);
                    break;
                default:
                    throw new EncryptionException($"Unsupported HMAC key length: {hmacKey.Length}");
            }

            using (hmac)
            {
                return hmac.ComputeHash(hmacInput.ToArray());
            }
        }
    }
}
