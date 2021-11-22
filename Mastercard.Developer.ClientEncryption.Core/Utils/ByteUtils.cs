namespace Mastercard.Developer.ClientEncryption.Core.Utils
{
    internal static class ByteUtils
    {
        static internal int ByteCount(int bitCount)
        {
            int byteCount = (bitCount / 8);
            return ((bitCount % 8) == 0)
                ? byteCount
                : (byteCount + 1);
        }
    }
}
