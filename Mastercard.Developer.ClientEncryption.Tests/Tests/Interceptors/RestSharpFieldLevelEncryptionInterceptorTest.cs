using System;
using System.Linq;
using System.Net;
using System.Text;
using Mastercard.Developer.ClientEncryption.Core.Encryption;
using Mastercard.Developer.ClientEncryption.RestSharp.Interceptors;
using Mastercard.Developer.ClientEncryption.Tests.NetCore.Test;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RestSharp.Portable;
using RestSharp.Portable.Impl;
using static RestSharp.Portable.ParameterType;

namespace Mastercard.Developer.ClientEncryption.Tests.NetCore.Interceptors
{
    [TestClass]
    public class RestSharpFieldLevelEncryptionInterceptorTest
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
                    new Parameter { Type = RequestBody, Encoding = Encoding.UTF8, Value = "{\"foo\":\"bar\"}"}
                }
            };

            // WHEN
            var instanceUnderTest = new RestSharpFieldLevelEncryptionInterceptor(config);
            instanceUnderTest.InterceptRequest(request);

            // THEN
            var encryptedPayloadParam = request.Parameters.FirstOrDefault(param => param.Type == RequestBody);
            Assert.IsNotNull(encryptedPayloadParam);
            var encryptedPayload = encryptedPayloadParam.Value.ToString();
            Assert.IsNotNull(encryptedPayload);
            Assert.IsFalse(encryptedPayload.Contains("foo"));
            Assert.IsTrue(encryptedPayload.Contains("encryptedFoo"));
            var contentLengthHeaderParam = request.Parameters.FirstOrDefault(param => param.Type == HttpHeader);
            Assert.IsNotNull(contentLengthHeaderParam);
            Assert.AreEqual(encryptedPayload.Length, contentLengthHeaderParam.Value);
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
                    new Parameter { Type = RequestBody, Encoding = Encoding.UTF8, Value = "{\"foo\":\"bar\"}"}
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
                Assert.AreEqual("Payload encryption failed!", e.Message);
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
            var response = new RestResponseDouble
            {
                Content = encryptedPayload,
                Headers = new GenericHttpHeaders { { "Content-Length", "100" } }
            };

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
            var response = new RestResponseDouble
            {
                Content = null
            };

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
            var response = new RestResponseDouble
            {
                Content = encryptedPayload
            };

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
                    new Parameter { Type = RequestBody, Encoding = Encoding.UTF8, Value = "{\"foo\":\"bar\"}"}
                }
            };

            // WHEN
            var instanceUnderTest = new RestSharpFieldLevelEncryptionInterceptor(config);
            instanceUnderTest.InterceptRequest(request);

            // THEN
            var encryptedPayloadParam = request.Parameters.FirstOrDefault(param => param.Type == RequestBody);
            Assert.IsNotNull(encryptedPayloadParam);
            var encryptedPayload = encryptedPayloadParam.Value.ToString();
            Assert.IsNotNull(encryptedPayload);
            Assert.IsFalse(encryptedPayload.Contains("foo"));
            Assert.IsTrue(encryptedPayload.Contains("encryptedFoo"));
            Assert.AreEqual(encryptedPayload.Length, request.Parameters.Find(HttpHeader, "Content-Length").First().Value);
            Assert.IsNotNull(request.Parameters.Find(HttpHeader, "x-iv").First());
            Assert.IsNotNull(request.Parameters.Find(HttpHeader, "x-encrypted-key").First());
            Assert.AreEqual("SHA256", request.Parameters.Find(HttpHeader, "x-oaep-padding-digest-algorithm").First().Value);
            Assert.AreEqual("80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279", request.Parameters.Find(HttpHeader, "x-encryption-certificate-fingerprint").First().Value);
            Assert.AreEqual("761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79", request.Parameters.Find(HttpHeader, "x-encryption-key-fingerprint").First().Value);
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
            var response = new RestResponseDouble
            {
                Content = encryptedPayload,
                Headers = new GenericHttpHeaders
                {
                    { "x-iv", "a32059c51607d0d02e823faecda5fb15" },
                    { "x-encrypted-key", "a31cfe7a7981b72428c013270619554c1d645c04b9d51c7eaf996f55749ef62fd7c7f8d334f95913be41ae38c46d192670fd1acb84ebb85a00cd997f1a9a3f782229c7bf5f0fdf49fe404452d7ed4fd41fbb95b787d25893fbf3d2c75673cecc8799bbe3dd7eb4fe6d3f744b377572cdf8aba1617194e10475b6cd6a8dd4fb8264f8f51534d8f7ac7c10b4ce9c44d15066724b03a0ab0edd512f9e6521fdb5841cd6964e457d6b4a0e45ba4aac4e77d6bbe383d6147e751fa88bc26278bb9690f9ee84b17123b887be2dcef0873f4f9f2c895d90e23456fafb01b99885e31f01a3188f0ad47edf22999cc1d0ddaf49e1407375117b5d66f1f185f2b57078d255" },
                    { "x-oaep-padding-digest-algorithm", "SHA256" },
                    { "x-encryption-key-fingerprint", "761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79" },
                    { "x-encryption-certificate-fingerprint", "80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279" }
                }
            };
            
            // WHEN
            var instanceUnderTest = new RestSharpFieldLevelEncryptionInterceptor(config);
            instanceUnderTest.InterceptResponse(response);

            // THEN
            var payload = response.Content;
            TestUtils.AssertPayloadEquals("{\"data\":\"string\"}", payload);
            Assert.IsNull(response.Headers.GetValue("x-iv"));
            Assert.IsNull(response.Headers.GetValue("x-encrypted-key"));
            Assert.IsNull(response.Headers.GetValue("x-oaep-padding-digest-algorithm"));
            Assert.IsNull(response.Headers.GetValue("x-encryption-key-fingerprint"));
            Assert.IsNull(response.Headers.GetValue("x-encryption-certificate-fingerprint"));
        }

        private class RestResponseDouble : IRestResponse
        {
            public IRestRequest Request { get; } = null;
            public Uri ResponseUri { get; } = null;
            public byte[] RawBytes { get; } = null;
            public string ContentType { get; } = null;
            public CookieCollection Cookies { get; } = null;
            public IHttpHeaders Headers { get; internal set; }
            public bool IsSuccess { get; } = true;
            public HttpStatusCode StatusCode { get; } = HttpStatusCode.OK;
            public string StatusDescription { get; } = null;

            private Lazy<string> _content;
            public string Content
            {
                get => _content.Value;
                set => _content = new Lazy<string>(() => value);
            }
        }
    }
}
