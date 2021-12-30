using System;

namespace Mastercard.Developer.ClientEncryption.Core.Utils
{
    internal static class Base64Utils
    {
        // c.f. https://datatracker.ietf.org/doc/html/rfc7515#appendix-C
        internal static string URLEncode(byte[] bytes)
        {
            string s = Convert.ToBase64String(bytes);
            s = s.Split('=')[0];
            s = s.Replace('+', '-');
            s = s.Replace('/', '_');
            return s;
        }

        internal static byte[] URLDecode(string encoded)
        {
            string s = encoded.Replace('_', '/').Replace('-', '+');
            switch (s.Length % 4)
            {
                case 2:
                    s += "==";
                    break;

                case 3:
                    s += "=";
                    break;
            }
            return Convert.FromBase64String(s);
        }
    }
}
