using System.Linq;
using Mastercard.Developer.ClientEncryption.Core.Encryption;
using Mastercard.Developer.ClientEncryption.RestSharpV2.Interceptors;
using Mastercard.Developer.ClientEncryption.Tests.NetCore.Test;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Method = RestSharp.Method;
using Header = RestSharp.HeaderParameter;
using ParameterType = RestSharp.ParameterType;
using RestRequest = RestSharp.RestRequest;
using RestSharp;

namespace Mastercard.Developer.ClientEncryption.Tests.NetCore.Interceptors
{
    [TestClass]
    public class RestSharpV2CbcJweEncryptionInterceptorTest
    {
        [TestMethod]
        public void TestFrom_ShouldReturnTheCorrectInterceptor()
        {
            // GIVEN
            EncryptionConfig config = TestUtils.GetTestJweConfigBuilder().Build();

            // WHEN
            RestSharpEncryptionInterceptor interceptor = RestSharpEncryptionInterceptor.From(config);

            // THEN
            Assert.IsTrue(interceptor is RestSharpJweEncryptionInterceptor);
        }

        [TestMethod]
        public void TestIntercept_ShouldDoNothing_WhenNoPayload()
        {
            // GIVEN
            var config = TestUtils.GetTestJweConfigBuilder().Build();

            // WHEN
            var request = new RestRequest
            {
                Method = Method.Get,
                Resource = "/service"
            };

            // THEN
            var fixture = RestSharpEncryptionInterceptor.From(config);
            fixture.InterceptRequest(request);
        }

        [TestMethod]
        public void TestInterceptResponse_ShouldDecryptWithA128CBC_HS256Encryption()
        {
            // GIVEN
            string encryptedPayload = "{" +
                "\"encryptedPayload\":\"eyJraWQiOiI3NjFiMDAzYzFlYWRlM2E1NDkwZTUwMDBkMzc4ODdiYWE1ZTZlYzBlMjI2YzA3NzA2ZTU5OTQ1MWZjMDMyYTc5IiwiY3R5IjoiYXBwbGljYXRpb25cL2pzb24iLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.5bsamlChk0HR3Nqg2UPJ2Fw4Y0MvC2pwWzNv84jYGkOXyqp1iwQSgETGaplIa7JyLg1ZWOqwNHEx3N7gsN4nzwAnVgz0eta6SsoQUE9YQ-5jek0COslUkoqIQjlQYJnYur7pqttDibj87fcw13G2agle5fL99j1QgFPjNPYqH88DMv481XGFa8O3VfJhW93m73KD2gvE5GasOPOkFK9wjKXc9lMGSgSArp3Awbc_oS2Cho_SbsvuEQwkhnQc2JKT3IaSWu8yK7edNGwD6OZJLhMJzWJlY30dUt2Eqe1r6kMT0IDRl7jHJnVIr2Qpe56CyeZ9V0aC5RH1mI5dYk4kHg.yI0CS3NdBrz9CCW2jwBSDw.6zr2pOSmAGdlJG0gbH53Eg.UFgf3-P9UjgMocEu7QA_vQ\"}";
            var config = TestUtils.GetTestJweConfigBuilder()
                .WithDecryptionPath("$.encryptedPayload", "$.foo")
                .Build();

            // WHEN
            var response = RestResponseWithContentLength(encryptedPayload);
            var fixture = RestSharpEncryptionInterceptor.From(config);
            fixture.InterceptResponse(response);

            // THEN
            var payload = response.Content;
            TestUtils.AssertPayloadEquals("{\"foo\":\"bar\"}", payload);
            var contentLengthHeaderParam = response.Headers.FirstOrDefault(param => param.Type == ParameterType.HttpHeader);
            Assert.IsNotNull(contentLengthHeaderParam);
            Assert.AreEqual(payload.Length.ToString(), contentLengthHeaderParam.Value);
        }

        [TestMethod]
        public void TestInterceptResponse_ShouldDoNothing_WhenNoPayload()
        {
            // GIVEN
            var config = TestUtils.GetTestJweConfigBuilder().Build();
            var response = new RestResponseDouble(null, null);

            // WHEN
            var fixture = RestSharpEncryptionInterceptor.From(config);
            fixture.InterceptResponse(response);
        }

        [TestMethod]
        [ExpectedException(typeof(EncryptionException))] // <-- THEN
        public void TestInterceptResponse_ShouldThrowAnExceptionWhenEncryptionNotSupported()
        {
            // GIVEN
            string encryptedPayload = "{" +
                "\"encryptedPayload\":\"eyJraWQiOiI3NjFiMDAzYzFlYWRlM2E1NDkwZTUwMDBkMzc4ODdiYWE1ZTZlYzBlMjI2YzA3NzA2ZTU5OTQ1MWZjMDMyYTc5IiwiY3R5IjoiYXBwbGljYXRpb25cL2pzb24iLCJlbmMiOiJBMTkyR0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.peSgTt_lPbcNStWh-gI3yMzhOGtFCwExFwLxKeHwjzsXvHB0Fml5XnG0jRbJSfOHzKx02d0NVBzoDDRSAnafuabbbMKcoaUK-jZNHSg4BHdyBZpCO82kzvWeEm3TTNHIMBTfM00EmdFB03z_a0PaWsT-FIOzu4Sd5Z_nsNLhP9941CtVS-YtZ9WkgDezGipxA7ejQ3X5gFVy2RH1gL8OTbzIYCwBcrfSjAiCQgunNbLxPPlfZHB_6prPK7_50NS6FvuMnAhiqUiiAka8DHMdeGBWOie2Q0FV_bsRDHx_6CY8kQA3F_NXz1dELIclJhdZFfRt1y-TEfwOIj4nDi2JnA.8BYMB5MkH2ZNyFGS._xb3uDsUQcPT5fQyZw.O0MzJ5OvNyj_QMuqaloTWA\"}";
            var config = TestUtils.GetTestJweConfigBuilder()
                .WithDecryptionPath("$.encryptedPayload", "$.foo")
                .Build();
            var response = RestResponseWithContentLength(encryptedPayload);

            // WHEN
            var fixture = RestSharpEncryptionInterceptor.From(config);
            fixture.InterceptResponse(response);
        }

        [TestMethod]
        [ExpectedException(typeof(EncryptionException))] // <-- THEN
        public void TestInterceptResponse_ShouldThrowException_WhenDecryptionFails()
        {
            // GIVEN
            string encryptedPayload = "{\"encryptedPayload\":\"NOT-VALID\"}";
            var config = TestUtils.GetTestJweConfigBuilder()
                .WithDecryptionPath("$", "$")
                .WithEncryptedValueFieldName("encryptedPayload")
                .Build();
            var response = RestResponseWithContentLength(encryptedPayload);

            // WHEN
            var fixture = RestSharpEncryptionInterceptor.From(config);
            fixture.InterceptResponse(response);
        }

        internal static RestResponse RestResponseWithContentLength(string content)
        {
            Header[] headers = { new Header("Content-Length", content.Length.ToString()) };
            return new RestResponseDouble(headers, content);
        }
    }
}
