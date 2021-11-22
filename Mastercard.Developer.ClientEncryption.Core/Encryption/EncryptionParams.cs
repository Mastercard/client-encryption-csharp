using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
#pragma warning disable 1591 // "Missing XML comment for publicly visible type or member."

namespace Mastercard.Developer.ClientEncryption.Core.Encryption
{
    public class EncryptionParams
    {
        protected internal static byte[] WrapSecretKey(EncryptionConfig config, byte[] keyBytes)
        {
            try
            {
                var publicEncryptionKey = config.EncryptionCertificate.GetRSAPublicKey();
                return publicEncryptionKey.Encrypt(keyBytes,
                    "SHA-256".Equals(config.OaepPaddingDigestAlgorithm)
                        ? RSAEncryptionPadding.OaepSHA256
                        : RSAEncryptionPadding.OaepSHA512);
            }
            catch (Exception e)
            {
                throw new EncryptionException("Failed to wrap secret key!", e);
            }
        }

        protected internal static byte[] UnwrapSecretKey(EncryptionConfig config, byte[] keyBytes, string oaepDigestAlgorithm)
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
