using System;
using System.Linq;
using static Mastercard.Developer.ClientEncryption.Core.Encryption.FieldLevelEncryptionConfig;

namespace Mastercard.Developer.ClientEncryption.Core.Utils
{
    internal static class EncodingUtils
    {
        internal static string EncodeBytes(byte[] bytes, FieldValueEncoding encoding)
        {
            return encoding == FieldValueEncoding.Hex ? HexEncode(bytes) : Convert.ToBase64String(bytes);
        }

        internal static byte[] DecodeValue(string value, FieldValueEncoding encoding)
        {
            return encoding == FieldValueEncoding.Hex ? HexDecode(value) : Convert.FromBase64String(value);
        }

        internal static byte[] HexDecode(string value)
        {
            if (value == null) throw new ArgumentNullException(nameof(value));
            return Enumerable.Range(0, value.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(value.Substring(x, 2), 16))
                .ToArray();
        }

        internal static string HexEncode(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            var hexString = BitConverter.ToString(bytes);
            return hexString.Replace("-", string.Empty).ToLower();
        }
    }
}
