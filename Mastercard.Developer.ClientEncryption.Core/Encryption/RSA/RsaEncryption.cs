using System;
using System.Security.Cryptography;

namespace Mastercard.Developer.ClientEncryption.Core.Encryption
{
    static internal class RsaEncryption
    {
        internal static byte[] WrapSecretKey(System.Security.Cryptography.RSA publicKey, byte[] keyBytes, String oaepDigestAlgorithm)
        {
            try
            {
                return publicKey.Encrypt(keyBytes,
                    "SHA-256".Equals(oaepDigestAlgorithm)
                        ? RSAEncryptionPadding.OaepSHA256
                        : RSAEncryptionPadding.OaepSHA512);
            }
            catch (Exception e)
            {
                throw new EncryptionException("Failed to wrap secret key!", e);
            }
        }

        internal static byte[] UnwrapSecretKey(EncryptionConfig config, byte[] keyBytes, string oaepDigestAlgorithm)
        {
            try
            {
                if (!oaepDigestAlgorithm.Contains("-"))
                {
                    oaepDigestAlgorithm = oaepDigestAlgorithm.Replace("SHA", "SHA-");
                }

                var decryptionKey = config.DecryptionKey;
                return decryptionKey.Decrypt(keyBytes,
                    "SHA-256".Equals(oaepDigestAlgorithm)
                        ? RSAEncryptionPadding.OaepSHA256
                        : RSAEncryptionPadding.OaepSHA512);
            }
            catch (Exception e)
            {
                throw new EncryptionException("Failed to unwrap secret key!", e);
            }
        }
    }
}
