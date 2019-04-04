using System;
#pragma warning disable 1591 // "Missing XML comment for publicly visible type or member."

namespace Mastercard.Developer.ClientEncryption.Core.Encryption
{
    public class EncryptionException : Exception
    {
        public EncryptionException(string message, Exception innerException) : base(message, innerException) {}
        public EncryptionException(string message) : base(message) {}
    }
}
