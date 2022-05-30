using Mastercard.Developer.ClientEncryption.Core.Encryption;
using Mastercard.Developer.ClientEncryption.Core.Encryption.JWE;
using Mastercard.Developer.ClientEncryption.Tests.NetCore.Test;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json.Linq;

namespace Mastercard.Developer.ClientEncryption.Tests.NetCore.Encryption.JWE
{
    [TestClass]
    public class JweEncryptionTest
    {
        [TestMethod]
#if !NETCOREAPP3_1 && !NET5_0_OR_GREATER
        [ExpectedException(typeof(EncryptionException), "AES/GCM/NoPadding is unsupported on .NET Standard < 2.1")]
#endif
        public void TestEncryptPayload_ShouldEncryptRootArrays()
        {
            // GIVEN
            const string payload = @"[
                {},
                {}
            ]";
            var config = TestUtils.GetTestJweConfigBuilder()
                .WithEncryptionPath("$", "$")
                .WithDecryptionPath("$.encryptedData", "$")
                .Build();

            // WHEN
            var encryptedPayload = JweEncryption.EncryptPayload(payload, config);

            // THEN
            var encryptedPayloadObject = JObject.Parse(encryptedPayload);
            Assert.IsNotNull(encryptedPayloadObject);
            TestUtils.AssertDecryptedJweEquals("[{},{}]", encryptedPayload, config);
        }

        [TestMethod]
#if !NETCOREAPP3_1 && !NET5_0_OR_GREATER
        [ExpectedException(typeof(EncryptionException), "AES/GCM/NoPadding is unsupported on .NET Standard < 2.1")]
#endif
        public void TestEncryptPayload_ShouldCreateEncryptedValue_WhenOutPathParentDoesNotExistInPayload()
        {
            // GIVEN
            const string payload = @"{""data"": {}}";
            var config = TestUtils.GetTestJweConfigBuilder()
                .WithEncryptionPath("$", "$.encryptedDataParent")
                .Build();

            // WHEN
            var encryptedPayload = JweEncryption.EncryptPayload(payload, config);

            // THEN
            var encryptedPayloadObject = JObject.Parse(encryptedPayload);
            Assert.IsNull(encryptedPayloadObject["data"]);
            Assert.IsNotNull(encryptedPayloadObject["encryptedDataParent"]);
            Assert.IsNotNull(encryptedPayloadObject["encryptedDataParent"]["encryptedData"]);
        }

        [TestMethod]
#if !NETCOREAPP3_1 && !NET5_0_OR_GREATER
        [ExpectedException(typeof(EncryptionException), "AES/GCM/NoPadding is unsupported on .NET Standard < 2.1")]
#endif
        public void TestDecryptPayload_ShouldDecryptRootArrays()
        {
            // GIVEN
            const string encryptedPayload = @"{
	            ""encryptedData"": ""ew0KICAia2lkIjogIjc2MWIwMDNjMWVhZGUzYTU0OTBlNTAwMGQzNzg4N2JhYTVlNmVjMGUyMjZjMDc3MDZlNTk5NDUxZmMwMzJhNzkiLA0KICAiY3R5IjogImFwcGxpY2F0aW9uL2pzb24iLA0KICAiZW5jIjogIkEyNTZHQ00iLA0KICAiYWxnIjogIlJTQS1PQUVQLTI1NiINCn0.ycN7kc7qfknufAz96VcgA6L-oTeY38S9oD6iFNTyw72sA4r82dyJeHL14z_Zd7V2NoOh1XEro6zPaG78jdRpq62F0Ajyqbupem2a-E5LtKRXXH3CucVlVtMoLfbt2Ao8u_oFLwytMjV_lVO7YH5UsOXjfzL2Bw7KNRdz4wQEQ2yXQpf8ajLPp98RBSLMxStv7vhIDuZxVpCRBx_KqKuB8Y0kF_CxRUQZVlgumCv97rGG_nsW01XfnfekMuAJntnG9Bi9NmrX8bwkLV3YZf7iO_kzR_D-kuyFtaXqUvXBLpUkchESgLX8IXYMLXxevk04VNl2WiPH5gs_VVzSCfXbHw.8l1G7U85BKOQh5Tu.Omcqk8Sung.TNzFb9bt57TioF-zpEOZBA""
            }"; 
            var config = TestUtils.GetTestJweConfigBuilder()
                .WithDecryptionPath("$.encryptedData", "$")
                .Build();

            // WHEN
            var payload = JweEncryption.DecryptPayload(encryptedPayload, config);

            // THEN
            TestUtils.AssertPayloadEquals("[{},{}]", payload);
        }

        [TestMethod]
#if !NETCOREAPP3_1 && !NET5_0_OR_GREATER
        [ExpectedException(typeof(EncryptionException), "AES/GCM/NoPadding is unsupported on .NET Standard < 2.1")]
#endif
        public void TestDecryptPayload_ShouldSupportPayloadWithEncryptedValueParent()
        {
            // GIVEN
            const string encryptedPayload = @"{
	            ""encryptedDataParent"": {
		            ""encryptedData"": ""ew0KICAia2lkIjogIjc2MWIwMDNjMWVhZGUzYTU0OTBlNTAwMGQzNzg4N2JhYTVlNmVjMGUyMjZjMDc3MDZlNTk5NDUxZmMwMzJhNzkiLA0KICAiY3R5IjogImFwcGxpY2F0aW9uL2pzb24iLA0KICAiZW5jIjogIkEyNTZHQ00iLA0KICAiYWxnIjogIlJTQS1PQUVQLTI1NiINCn0.QHdpgZKcR7e4TNddxHQOTk6R8IYhB4wfnHwUu5d3UhCcr6x6u8KWgPLrn2M95WV1xkjF7jnbOVYO-xE0e5Kx5laIVQNvjYpPxxYqzOQ-F16NwkkGgiZ8UnVi8qYYR1RO2fuqt6xP0_9VNnWpO541_kEMcCrk-6HFRjPU_4AF-wKAUdxInXOrUCOWi7-2uocraAYyLuh1PR0W002p9nVoOY7KXbA-Pf3gmEO9TgCDBFxmtn2dKwYxRPI6tkBYCB2n6h1rIIjQNI4kb-ErV8_vdppIPlB0-o0ONVlHWfnDbgZ3b8SIBEnZNn01MAPbC8visu41ODoNwhuKirD_MzvhTQ.GFYD8LCwXkc2eHPC.T1v8SZikvVAd76g.NbdYvwvKsUVbbSUqaX3Afw""
	            }
            }";
            var config = TestUtils.GetTestJweConfigBuilder()
                .WithDecryptionPath("$.encryptedDataParent.encryptedData", "$")
                .Build();

            // WHEN
            var payload = JweEncryption.DecryptPayload(encryptedPayload, config);

            // THEN
            TestUtils.AssertPayloadEquals("{\"data\": {}}", payload);
        }
    }
}
