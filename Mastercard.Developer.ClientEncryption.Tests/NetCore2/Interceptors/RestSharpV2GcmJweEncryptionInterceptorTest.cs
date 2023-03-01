using System.Linq;
using Mastercard.Developer.ClientEncryption.Core.Encryption;
using Mastercard.Developer.ClientEncryption.RestSharpV2.Interceptors;
using Mastercard.Developer.ClientEncryption.Tests.NetCore.Test;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RestSharp;
using Method = RestSharp.Method;
using ParameterType = RestSharp.ParameterType;
using RestRequest = RestSharp.RestRequest;

namespace Mastercard.Developer.ClientEncryption.Tests.NetCore.Interceptors
{
    [TestClass]
    public class RestSharpV2GcmJweEncryptionInterceptorTest
    {
        [TestMethod]
#if !NETCOREAPP3_1 && !NET5_0_OR_GREATER
        [ExpectedException(typeof(EncryptionException), "AES/GCM/NoPadding is unsupported on .NET Standard < 2.1")]
# endif
        public void TestIntercept_ShouldEncryptRequestPayloadAndUpdateContentLengthHeader()
        {
            // GIVEN
            var config = TestUtils.GetTestJweConfigBuilder()
                .WithEncryptionPath("$","$")
                .WithEncryptedValueFieldName("encryptedFoo")
                .Build();
            var request = new RestRequest
            {
                Method = Method.Post,
                Resource = "/service"
            };
            request.AddBody("{\"foo\":\"bar\"}");

            // WHEN
            var fixture = RestSharpEncryptionInterceptor.From(config);
            fixture.InterceptRequest(request);

            // THEN
            var encryptedPayloadParam = request.Parameters.FirstOrDefault(param => param.Type == ParameterType.RequestBody);
            Assert.IsNotNull(encryptedPayloadParam);
            var encryptedPayload = encryptedPayloadParam.Value?.ToString();
            Assert.IsNotNull(encryptedPayload);
            Assert.IsFalse(encryptedPayload.Contains("foo"));
            Assert.IsTrue(encryptedPayload.Contains("encryptedFoo"));
            var contentLengthHeaderParam = request.Parameters.FirstOrDefault(param => param.Type == ParameterType.HttpHeader);
            Assert.IsNotNull(contentLengthHeaderParam);
            Assert.AreEqual(encryptedPayload.Length.ToString(), contentLengthHeaderParam.Value);
        }

        [TestMethod]
#if !NETCOREAPP3_1 && !NET5_0_OR_GREATER
        [ExpectedException(typeof(EncryptionException), "AES/GCM/NoPadding is unsupported on .NET Standard < 2.1")]
# endif
        public void TestInterceptResponse_ShouldDecryptResponsePayloadAndUpdateContentLengthHeader()
        {
            // GIVEN
            const string encryptedPayload = "{" +
                "\"encryptedPayload\":\"eyJraWQiOiI3NjFiMDAzYzFlYWRlM2E1NDkwZTUwMDBkMzc4ODdiYWE1ZTZlYzBlMjI2YzA3NzA2ZTU5OTQ1MWZjMDMyYTc5IiwiY3R5IjoiYXBwbGljYXRpb25cL2pzb24iLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.8c6vxeZOUBS8A9SXYUSrRnfl1ht9xxciB7TAEv84etZhQQ2civQKso-htpa2DWFBSUm-UYlxb6XtXNXZxuWu-A0WXjwi1K5ZAACc8KUoYnqPldEtC9Q2bhbQgc_qZF_GxeKrOZfuXc9oi45xfVysF_db4RZ6VkLvY2YpPeDGEMX_nLEjzqKaDz_2m0Ae_nknr0p_Nu0m5UJgMzZGR4Sk1DJWa9x-WJLEyo4w_nRDThOjHJshOHaOU6qR5rdEAZr_dwqnTHrjX9Qm9N9gflPGMaJNVa4mvpsjz6LJzjaW3nJ2yCoirbaeJyCrful6cCiwMWMaDMuiBDPKa2ovVTy0Sw.w0Nkjxl0T9HHNu4R.suRZaYu6Ui05Z3-vsw.akknMr3Dl4L0VVTGPUszcA\"}";
            var config = TestUtils.GetTestJweConfigBuilder()
                .WithDecryptionPath("$.encryptedPayload", "$")
                .Build();

            // WHEN
            var response = RestSharpV2CbcJweEncryptionInterceptorTest.RestResponseWithContentLength(encryptedPayload);
            var fixture = RestSharpEncryptionInterceptor.From(config);
            fixture.InterceptResponse(response);

            // THEN
            var payload = response.Content;
            TestUtils.AssertPayloadEquals("{\"foo\":\"bar\"}", payload);
            var contentLengthHeaderParam = response.Headers.FirstOrDefault(param => param.Type == ParameterType.HttpHeader);
            Assert.IsNotNull(contentLengthHeaderParam);
            Assert.AreEqual(payload.Length.ToString(), contentLengthHeaderParam.Value);
        }
    }
}
