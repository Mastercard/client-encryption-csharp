using System.Text;
using Newtonsoft.Json.Linq;
using Mastercard.Developer.ClientEncryption.Core.Utils;
#pragma warning disable 1591 // "Missing XML comment for publicly visible type or member."

namespace Mastercard.Developer.ClientEncryption.Core.Encryption.JWE
{
    internal sealed class JweHeader
    {
        private const string Algorithm = "alg";
        private const string KeyId = "kid";
        private const string EncryptionAlgorithm = "enc";
        private const string ContentType = "cty";

        public string Enc { get; }
        public string Kid { get; }
        public string Alg { get; }
        public string Cty { get; }

        public JweHeader(string alg, string enc, string kid, string cty)
        {
            Alg = alg;
            Enc = enc;
            Kid = kid;
            Cty = cty;
        }

        public JObject Json =>
            new JObject(
                new JProperty(KeyId, Kid),
                new JProperty(ContentType, Cty),
                new JProperty(EncryptionAlgorithm, Enc),
                new JProperty(Algorithm, Alg)
            );

        public static JweHeader Parse(string encoded)
        {
            // Decode and parse the string
            var decoded = Base64Utils.URLDecode(encoded);
            var json = Encoding.UTF8.GetString(decoded);
            var jobject = JObject.Parse(json);

            // Wrap it up
            return new JweHeader(
                ((string)jobject[Algorithm]),
                ((string)jobject[EncryptionAlgorithm]),
                ((string)jobject[KeyId]),
                ((string)jobject[ContentType])
            );
        }
    }
}
