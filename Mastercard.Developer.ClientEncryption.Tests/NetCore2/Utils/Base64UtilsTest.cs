using System;
using Mastercard.Developer.ClientEncryption.Core.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Mastercard.Developer.ClientEncryption.Tests.NetCore.Utils
{
    [TestClass]
    public class Base64UtilsTest
    {
        private static readonly Tuple<string, string> TestVector1 = Tuple.Create("Ct6FrAEg4OVsWaeI+2wNIG0RSCFEW/PLWzueZqUbwDw=", "Ct6FrAEg4OVsWaeI-2wNIG0RSCFEW_PLWzueZqUbwDw");
        private static readonly Tuple<string, string> TestVector2 = Tuple.Create("zRbseYGWpTaOpr4o+aBDjwQ9Pn/yHTxm5uPt0JKIH5nRdg==", "zRbseYGWpTaOpr4o-aBDjwQ9Pn_yHTxm5uPt0JKIH5nRdg");

        [TestMethod]
        public void TestBase64URLEncode()
        {
            var vectors = new Tuple<string, string>[]{ TestVector1, TestVector2 };
            foreach (var vector in vectors)
            {
                Assert.AreEqual(
                    vector.Item2,
                    Base64Utils.URLEncode(
                        Convert.FromBase64String(vector.Item1)
                    )
                );
            }
        }

        [TestMethod]
        public void TestBase64URLDecode()
        {
            var vectors = new Tuple<string, string>[] { TestVector1, TestVector2 };
            foreach (var vector in vectors)
            {
                CollectionAssert.AreEqual(
                    Convert.FromBase64String(vector.Item1),
                    Base64Utils.URLDecode(vector.Item2)
                );
            }
        }
    }
}
