using Newtonsoft.Json;
using Mastercard.Developer.ClientEncryption.Core.Encryption.JWE;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Mastercard.Developer.ClientEncryption.Tests.NetCore.Encryption.JWE
{
    [TestClass]
    public class JweHeaderTest
    {
        [TestMethod]
        public void TestToJson_ShouldReturnJsonJweHeader()
        {
            JweHeader header = new JweHeader("RSA-OAEP-256", "A256GCM", "123", "application/json");

            Assert.AreEqual(
                "{\"kid\":\"123\",\"cty\":\"application/json\",\"enc\":\"A256GCM\",\"alg\":\"RSA-OAEP-256\"}",
                header.Json.ToString(Formatting.None)
            );
        }

        [TestMethod]
        public void TestParseJweHeader_ShouldCorrectlyParseJweHeader()
        {
            JweHeader header = JweHeader.Parse("eyJraWQiOiI3NjFiMDAzYzFlYWRlM2E1NDkwZTUwMDBkMzc4ODdiYWE1ZTZlYzBlMjI2YzA3NzA2ZTU5OTQ1MWZjMDMyYTc5IiwiY3R5IjoiYXBwbGljYXRpb25cL2pzb24iLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0");

            Assert.AreEqual("A256GCM", header.Enc);
            Assert.AreEqual("RSA-OAEP-256", header.Alg);
            Assert.AreEqual("application/json", header.Cty);
            Assert.AreEqual("761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79", header.Kid);
        }
    }
}
