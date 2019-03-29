using System;

namespace Mastercard.Developer.ClientEncryption.Core.Encryption
{
    public class EncryptionException : Exception
    {
        public EncryptionException(string message, Exception innerException) : base(message, innerException) {}
        public EncryptionException(string message) : base(message) {}
    }
}
