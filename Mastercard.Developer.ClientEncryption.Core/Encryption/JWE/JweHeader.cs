using System;
using System.Text;
using Newtonsoft.Json.Linq;
using Mastercard.Developer.ClientEncryption.Core.Utils;
#pragma warning disable 1591 // "Missing XML comment for publicly visible type or member."

namespace Mastercard.Developer.ClientEncryption.Core.Encryption.JWE
{
    internal sealed class JweHeader
    {
        const string ALGORITHM = "alg";
        const string KEY_ID = "kid";
        const string ENCRYPTION_ALGORITHM = "enc";
        const string CONTENT_TYPE = "cty";

        public string Enc { get; private set; }
        public string Kid { get; private set; }
        public string Alg { get; private set; }
        public string Cty { get; private set; }

        public JweHeader(string alg, string enc, string kid, string cty)
        {
            Alg = alg;
            Enc = enc;
            Kid = kid;
            Cty = cty;
        }

        public JObject Json
        {
            get
            {
                return new JObject(
                    new JProperty(KEY_ID, Kid),
                    new JProperty(CONTENT_TYPE, Cty),
                    new JProperty(ENCRYPTION_ALGORITHM, Enc),
                    new JProperty(ALGORITHM, Alg)
                );
            }
        }

        public static JweHeader Parse(String encoded)
        {
            // Decode and parse the string
            byte[] decoded = Base64Utils.URLDecode(encoded);
            string json = Encoding.UTF8.GetString(decoded);
            JObject jobject = JObject.Parse(json);

            // Wrap it up
            return new JweHeader(
                ((string)jobject[ALGORITHM]),
                ((string)jobject[ENCRYPTION_ALGORITHM]),
                ((string)jobject[KEY_ID]),
                ((string)jobject[CONTENT_TYPE])
            );
        }
    }
}
