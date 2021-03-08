using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Mastercard.Developer.ClientEncryption.Core.Encryption;
using Mastercard.Developer.ClientEncryption.RestSharpV2.Interceptors;
using Mastercard.Developer.ClientEncryption.Tests.NetCore.Test;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RestSharp;
using IRestRequest = RestSharp.IRestRequest;
using IRestResponse = RestSharp.IRestResponse;
using Method = RestSharp.Method;
using Parameter = RestSharp.Parameter;
using ParameterType = RestSharp.ParameterType;
using RestRequest = RestSharp.RestRequest;

namespace Mastercard.Developer.ClientEncryption.Tests.NetCore.Interceptors
{
    [TestClass]
    public class RestSharpV2FieldLevelEncryptionInterceptorTest
    {
        [TestMethod]
        public void TestInterceptRequest_ShouldEncryptRequestPayloadAndUpdateContentLengthHeader()
        {
            // GIVEN
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithEncryptionPath("$.foo", "$.encryptedFoo")
                .Build();
            var request = new RestRequest
            {
                Method = Method.POST,
                Resource = "/service",
                Parameters =
                {
                    new Parameter("param1", "{\"foo\":\"bar\"}", ParameterType.RequestBody)
                }
            };

            // WHEN
            var instanceUnderTest = new RestSharpFieldLevelEncryptionInterceptor(config);
            instanceUnderTest.InterceptRequest(request);

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
        public void TestInterceptRequest_ShouldDoNothing_WhenNoPayload()
        {
            // GIVEN
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithEncryptionPath("$.foo", "$.encryptedFoo")
                .Build();
            var request = new RestRequest
            {
                Method = Method.GET,
                Resource = "/service"
            };

            // WHEN
            var instanceUnderTest = new RestSharpFieldLevelEncryptionInterceptor(config);
            instanceUnderTest.InterceptRequest(request);
        }
       
        [TestMethod]
        [ExpectedException(typeof(EncryptionException))] // THEN
        public void TestInterceptRequest_ShouldThrowEncryptionException_WhenEncryptionFails()
        {
            // GIVEN
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithEncryptionPath("$.foo", "$.encryptedFoo")
                .WithEncryptionCertificate(TestUtils.GetTestInvalidEncryptionCertificate()) // Invalid certificate
                .Build();
            var request = new RestRequest
            {
                Method = Method.POST,
                Resource = "/service",
                Parameters =
                {
                    new Parameter("param1", "{\"foo\":\"bar\"}", ParameterType.RequestBody )
                }
            };

            try
            {
                // WHEN
                var instanceUnderTest = new RestSharpFieldLevelEncryptionInterceptor(config);
                instanceUnderTest.InterceptRequest(request);
            }
            catch (Exception e)
            {
                // THEN
                Assert.AreEqual("Failed to wrap secret key!", e.Message);
                throw;
            }
        }

        [TestMethod]
        public void TestInterceptResponse_ShouldDecryptResponsePayload()
        {
            // GIVEN
            const string encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"iv\": \"a32059c51607d0d02e823faecda5fb15\"," +
                "        \"encryptedKey\": \"a31cfe7a7981b72428c013270619554c1d645c04b9d51c7eaf996f55749ef62fd7c7f8d334f95913be41ae38c46d192670fd1acb84ebb85a00cd997f1a9a3f782229c7bf5f0fdf49fe404452d7ed4fd41fbb95b787d25893fbf3d2c75673cecc8799bbe3dd7eb4fe6d3f744b377572cdf8aba1617194e10475b6cd6a8dd4fb8264f8f51534d8f7ac7c10b4ce9c44d15066724b03a0ab0edd512f9e6521fdb5841cd6964e457d6b4a0e45ba4aac4e77d6bbe383d6147e751fa88bc26278bb9690f9ee84b17123b887be2dcef0873f4f9f2c895d90e23456fafb01b99885e31f01a3188f0ad47edf22999cc1d0ddaf49e1407375117b5d66f1f185f2b57078d255\"," +
                "        \"encryptedValue\": \"21d754bdb4567d35d58720c9f8364075\"," +
                "        \"oaepHashingAlgorithm\": \"SHA256\"" +
                "    }" +
                "}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithDecryptionPath("$.encryptedData", "$.data")
                .Build();
            Parameter[] headers = { new Parameter("Content-Length", "100", ParameterType.HttpHeader) };
            var response = new RestResponseDouble(headers, encryptedPayload);

            // WHEN
            var instanceUnderTest = new RestSharpFieldLevelEncryptionInterceptor(config);
            instanceUnderTest.InterceptResponse(response);
        
            // THEN
            var payload = response.Content;
            TestUtils.AssertPayloadEquals("{\"data\":\"string\"}", payload);
        }

        [TestMethod]
        public void TestInterceptResponse_ShouldDoNothing_WhenNoPayload()
        {
            // GIVEN
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder().Build();
            var response = new RestResponseDouble(null, null);

            // WHEN
            var instanceUnderTest = new RestSharpFieldLevelEncryptionInterceptor(config);
            instanceUnderTest.InterceptResponse(response);
        }

        [TestMethod] 
        [ExpectedException(typeof(EncryptionException))] // THEN
        public void TestInterceptResponse_ShouldThrowEncryptionException_WhenDecryptionFails()
        {
            
            // GIVEN
            const string encryptedPayload = "{" +
                                            "    \"encryptedData\": {" +
                                            "        \"iv\": \"a2c494ca28dec4f3d6ce7d68b1044cfe\"," +
                                            "        \"encryptedKey\": \"NOT A VALID KEY!\"," +
                                            "        \"encryptedValue\": \"0672589113046bf692265b6ea6088184\"" +
                                            "    }" +
                                            "}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithDecryptionPath("$.encryptedData", "$.data")
                .Build();
            var response = new RestResponseDouble(null, encryptedPayload);

            try
            {
                // WHEN
                var instanceUnderTest = new RestSharpFieldLevelEncryptionInterceptor(config);
                instanceUnderTest.InterceptResponse(response);
            }
            catch (Exception e)
            {
                // THEN
                Assert.AreEqual("Failed to decode and unwrap the provided secret key value!", e.Message);
                throw;
            }
        }

        [TestMethod]
        public void TestInterceptRequest_ShouldEncryptRequestPayloadAndAddEncryptionHttpHeaders_WhenRequestedInConfig()
        {
            // GIVEN
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithEncryptionPath("$.foo", "$.encryptedFoo")
                .WithIvHeaderName("x-iv")
                .WithEncryptedKeyHeaderName("x-encrypted-key")
                .WithOaepPaddingDigestAlgorithmHeaderName("x-oaep-padding-digest-algorithm")
                .WithEncryptionCertificateFingerprintHeaderName("x-encryption-certificate-fingerprint")
                .WithEncryptionKeyFingerprintHeaderName("x-encryption-key-fingerprint")
                .Build();
            var request = new RestRequest
            {
                Method = Method.POST,
                Resource = "/service",
                Parameters =
                {
                    new Parameter("param1", "{\"foo\":\"bar\"}", ParameterType.RequestBody )
                }
            };

            // WHEN
            var instanceUnderTest = new RestSharpFieldLevelEncryptionInterceptor(config);
            instanceUnderTest.InterceptRequest(request);

            // THEN
            var encryptedPayloadParam = request.Parameters.FirstOrDefault(param => param.Type == ParameterType.RequestBody);
            Assert.IsNotNull(encryptedPayloadParam);
            var encryptedPayload = encryptedPayloadParam.Value?.ToString();
            Assert.IsNotNull(encryptedPayload);
            Assert.IsFalse(encryptedPayload.Contains("foo"));
            Assert.IsTrue(encryptedPayload.Contains("encryptedFoo"));
            Assert.AreEqual(encryptedPayload.Length.ToString(), request.Parameters.Find(param => param.Name == "Content-Length").Value);
            Assert.IsNotNull(request.Parameters.Find(param => param.Name == "x-iv"));
            Assert.IsNotNull(request.Parameters.Find(param => param.Name == "x-encrypted-key"));
            Assert.AreEqual("SHA256", request.Parameters.Find(param => param.Name == "x-oaep-padding-digest-algorithm").Value);
            Assert.AreEqual("80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279", request.Parameters.Find(param => param.Name == "x-encryption-certificate-fingerprint").Value);
            Assert.AreEqual("761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79", request.Parameters.Find(param => param.Name == "x-encryption-key-fingerprint").Value);
        }
        
        [TestMethod]
        public void TestInterceptResponse_ShouldDecryptResponsePayloadAndRemoveEncryptionHttpHeaders_WhenRequestedInConfig()
        {
            // GIVEN
            const string encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"encryptedValue\": \"21d754bdb4567d35d58720c9f8364075\"" +
                "    }" +
                "}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithDecryptionPath("$.encryptedData", "$.data")
                .WithIvHeaderName("x-iv")
                .WithEncryptedKeyHeaderName("x-encrypted-key")
                .WithOaepPaddingDigestAlgorithmHeaderName("x-oaep-padding-digest-algorithm")
                .WithEncryptionCertificateFingerprintHeaderName("x-encryption-certificate-fingerprint")
                .WithEncryptionKeyFingerprintHeaderName("x-encryption-key-fingerprint")
                .Build();
            Parameter[] param =
            {
                new Parameter("x-iv", "a32059c51607d0d02e823faecda5fb15", ParameterType.HttpHeader),
                new Parameter("x-encrypted-key",
                    "a31cfe7a7981b72428c013270619554c1d645c04b9d51c7eaf996f55749ef62fd7c7f8d334f95913be41ae38c46d192670fd1acb84ebb85a00cd997f1a9a3f782229c7bf5f0fdf49fe404452d7ed4fd41fbb95b787d25893fbf3d2c75673cecc8799bbe3dd7eb4fe6d3f744b377572cdf8aba1617194e10475b6cd6a8dd4fb8264f8f51534d8f7ac7c10b4ce9c44d15066724b03a0ab0edd512f9e6521fdb5841cd6964e457d6b4a0e45ba4aac4e77d6bbe383d6147e751fa88bc26278bb9690f9ee84b17123b887be2dcef0873f4f9f2c895d90e23456fafb01b99885e31f01a3188f0ad47edf22999cc1d0ddaf49e1407375117b5d66f1f185f2b57078d255",
                    ParameterType.HttpHeader),
                new Parameter("x-oaep-padding-digest-algorithm", "SHA256", ParameterType.HttpHeader),
                new Parameter("x-encryption-key-fingerprint",
                    "761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79", ParameterType.HttpHeader),
                new Parameter("x-encryption-certificate-fingerprint",
                    "80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279", ParameterType.HttpHeader)
            };
            var response = new RestResponseDouble(param, encryptedPayload);

            // WHEN
            var instanceUnderTest = new RestSharpFieldLevelEncryptionInterceptor(config);
            instanceUnderTest.InterceptResponse(response);

            // THEN
            var payload = response.Content;
            TestUtils.AssertPayloadEquals("{\"data\":\"string\"}", payload);
            var headers = response.Headers.ToList();
            Assert.IsNull(headers.Find(h => h.Name == "x-iv"));
            Assert.IsNull(headers.Find(h => h.Name == "x-encrypted-key"));
            Assert.IsNull(headers.Find(h => h.Name == "x-oaep-padding-digest-algorithm"));
            Assert.IsNull(headers.Find(h => h.Name == "x-encryption-key-fingerprint"));
            Assert.IsNull(headers.Find(h => h.Name == "x-encryption-certificate-fingerprint"));
        }

        private class RestResponseDouble : IRestResponse
        {
            public IRestRequest Request { get; set; } = null;
            public Uri ResponseUri { get; set; } = null;
            public string Server { get; set; }
            public byte[] RawBytes { get; set; } = null;
            public string ContentType { get; set; } = null;
            public long ContentLength { get; set; }
            public string ContentEncoding { get; set; }
            public IList<RestResponseCookie> Cookies { get; } = null;
            public IList<Parameter> Headers { get; }
            public ResponseStatus ResponseStatus { get; set; }
            public string ErrorMessage { get; set; }
            public Exception ErrorException { get; set; }
            public Version ProtocolVersion { get; set; }
            public HttpStatusCode StatusCode { get; set; } = HttpStatusCode.OK;
            public bool IsSuccessful => true;

            public string StatusDescription { get; set; } = null;

            private Lazy<string> _content;

            public RestResponseDouble(IList<Parameter> headers, string content)
            {
                Headers = headers;
                Content = content;
            }

            public string Content
            {
                get => _content.Value;
                set => _content = new Lazy<string>(() => value);
            }
        }
    }
}
