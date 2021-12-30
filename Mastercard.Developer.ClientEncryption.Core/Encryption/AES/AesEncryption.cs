using System.Security.Cryptography;
using Mastercard.Developer.ClientEncryption.Core.Utils;

namespace Mastercard.Developer.ClientEncryption.Core.Encryption.AES
{
    static internal class AesEncryption
    {
        static internal byte[] GenerateIV()
        {
            byte[] iv = new byte[12]; // 96 bytes as per NIST recommendation..
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(iv);
            }
            return iv;
        }

        static internal byte[] GenerateCek(int bitLength)
        {
            byte[] cekMaterial = new byte[ByteUtils.ByteCount(bitLength)];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(cekMaterial);
            }
            return cekMaterial;
        }
    }
}
