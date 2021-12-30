using System;
using System.Linq;
using System.Text;
using Mastercard.Developer.ClientEncryption.Core.Encryption;
using Mastercard.Developer.ClientEncryption.Core.Utils;
using Mastercard.Developer.ClientEncryption.Tests.NetCore.Test;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json.Linq;
using static System.Security.Cryptography.X509Certificates.X509KeyStorageFlags;
using static Mastercard.Developer.ClientEncryption.Core.Encryption.FieldLevelEncryptionConfig;

namespace Mastercard.Developer.ClientEncryption.Tests.NetCore.Encryption
{
    [TestClass]
    public class FieldLevelEncryptionTest
    {
        [TestMethod]
        public void TestEncryptBytes_InteroperabilityTest()
        {
            // GIVEN
            const string ivValue = "VNm/scgd1jhWF0z4+Qh6MA==";
            const string keyValue = "mZzmzoURXI3Vk0vdsPkcFw==";
            const string dataValue = "some data ù€@";
            var ivBytes = Convert.FromBase64String(ivValue);
            var keyBytes = Convert.FromBase64String(keyValue);
            var dataBytes = Encoding.UTF8.GetBytes(dataValue);

            // WHEN
            var encryptedBytes = FieldLevelEncryption.EncryptBytes(keyBytes, ivBytes, dataBytes);

            // THEN
            var expectedEncryptedBytes = Convert.FromBase64String("Y6X9YneTS4VuPETceBmvclrDoCqYyBgZgJUdnlZ8/0g=");
            Assert.IsTrue(expectedEncryptedBytes.SequenceEqual(encryptedBytes));
        }

        [TestMethod]
        public void TestDecryptBytes_InteroperabilityTest()
        {
            // GIVEN
            const string ivValue = "VNm/scgd1jhWF0z4+Qh6MA==";
            const string keyValue = "mZzmzoURXI3Vk0vdsPkcFw==";
            const string encryptedDataValue = "Y6X9YneTS4VuPETceBmvclrDoCqYyBgZgJUdnlZ8/0g=";
            var ivBytes = Convert.FromBase64String(ivValue);
            var keyBytes = Convert.FromBase64String(keyValue);
            var encryptedDataBytes = Convert.FromBase64String(encryptedDataValue);

            // WHEN
            var decryptedDataBytes = FieldLevelEncryption.DecryptBytes(keyBytes, ivBytes, encryptedDataBytes);

            // THEN
            const string expectedData = "some data ù€@";
            Assert.IsTrue(Encoding.UTF8.GetBytes(expectedData).SequenceEqual(decryptedDataBytes));
        }

        [TestMethod]
        public void TestDecryptPayload_InteroperabilityTest()
        {
            // GIVEN
            const string encryptedPayload = "{\"data\":\"WtBPYHL5jdU/BsECYzlyRUPIElWCwSCgKhk5RPy2AMZBGmC8OUJ1L9HC/SF2QpCU+ucZTmo7XOjhSdVi0/yrdZP1OG7dVWcW4MEWpxiU1gl0fS0LKKPOFjEymSP5f5otdTFCp00xPfzp+l6K3S3kZTAuSG1gh6TaRL+qfC1POz8KxhCEL8D1MDvxnlmchPx/hEyAzav0AID3T7T4WomzUXErNrnbDCCiL6pm4IBR8cDAzU4eSmTxdzZFyvTpBQDXVyFdkaNTo3GXk837wujVK8EX3c+gsJvMq4XVJFwGmPNhPM6P7OmdK45cldWrD5j2gO2VBH5aW1EXfot7d11bjJC9T8D/ZOQFF6uLIG7J9x9R0Ts0zXD/H24y9/jF30rKKX7TNmKHn5uh1Czd+h7ryIAqaQsOu6ILBKfH7W/NIR5qYN1GiL/kOYwx2pdIGQdcdolVdxV8Z6bt4Tcvq3jSZaCbhJI/kphZL7QHJgcG6luz9k0457x/0QCDPlve6JNgUQzAOYC64X0a07JpERH0O08/YbntKEq6qf7UhloyI5A=\"}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithDecryptionKey(EncryptionUtils.LoadDecryptionKey("./_Resources/Keys/Pkcs1/test_key_pkcs1-2048.pem"))
                .WithDecryptionPath("$", "$")
                .WithEncryptedValueFieldName("data")
                .WithValueEncoding(FieldValueEncoding.Base64)
                .Build();
            const string oaepPaddingDigest = "SHA256";
            const string encryptedKey = "dobCRy+NUxdQdN0oMLT4dXUzQ+We7BahMfJunoAmwwUpk9jJrW66BASPalS2QWChPaKDM4Ft/BeNsu0wBoUZ0hHIT9ftx5g4tY6Xu2iLRiFWFDCHYOSdL+yVv98FcM6fxc34FNyg3/rOPWeyS3Q9YAOgcqiCwWYu4kqa34tNWCW1vnTmtz+dCKiiCZo/uHUkCtoAI5fEe+inHHToZL+LFlQ2Xd0u/nsu5Ep14Il5mTv8FyfLgwRgfilcqy4t2Kh3bpZ46LllO36DHXtQoI1e0ayMFfKTO87++NWxYNOilrverJ01WHnA+PyXhg4XU3RlU0CVWBN06fKbHBDH6GCmOA==";
            const string iv = "+yBXlo+gYGe2q0xzLDLLzQ==";

            // WHEN
            var parameters = new FieldLevelEncryptionParams(config, iv, encryptedKey, oaepPaddingDigest);
            var payload = FieldLevelEncryption.DecryptPayload(encryptedPayload, config, parameters);

            // THEN
            Assert.IsTrue(payload.Contains("account"));
        }

        [TestMethod]
        public void TestEncryptPayload_Nominal()
        {
            // GIVEN
            const string payload = "{" +
                "    \"data\": {" +
                "        \"field1\": \"value1\"," +
                "        \"field2\": \"value2\"" +
                "    }," +
                "    \"encryptedData\": {}" +
                "}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithEncryptionPath("data", "encryptedData")
                .WithDecryptionPath("encryptedData", "data")
                .WithOaepPaddingDigestAlgorithm("SHA-256")
                .Build();

            // WHEN
            var encryptedPayload = FieldLevelEncryption.EncryptPayload(payload, config);

            // THEN
            var encryptedPayloadObject = JObject.Parse(encryptedPayload);
            Assert.IsNull(encryptedPayloadObject["data"]);
            var encryptedDataToken = encryptedPayloadObject["encryptedData"] as JObject;
            Assert.IsNotNull(encryptedDataToken);
            Assert.AreEqual(6, encryptedDataToken.Count);
            Assert.AreEqual("SHA256", encryptedDataToken["oaepHashingAlgorithm"]);
            Assert.AreEqual("761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79", encryptedDataToken["encryptionKeyFingerprint"]);
            Assert.AreEqual("80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279", encryptedDataToken["encryptionCertificateFingerprint"]);
            Assert.IsNotNull(encryptedDataToken["encryptedValue"]);
            Assert.IsNotNull(encryptedDataToken["encryptedKey"]);
            Assert.IsNotNull(encryptedDataToken["iv"]);
            TestUtils.AssertDecryptedPayloadEquals("{\"data\":{\"field1\":\"value1\",\"field2\":\"value2\"}}", encryptedPayload, config);
        }

        [TestMethod]
        public void TestEncryptPayload_ShouldSupportBase64FieldValueEncoding()
        {
            // GIVEN
            const string payload = "{\"data\": {}, \"encryptedData\": {}}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithEncryptionPath("data", "encryptedData")
                .WithOaepPaddingDigestAlgorithm("SHA-256")
                .WithValueEncoding(FieldValueEncoding.Base64)
                .WithEncryptionCertificateFingerprint(null)
                .WithEncryptionKeyFingerprint(null)
                .Build();

            // WHEN
            var encryptedPayload = FieldLevelEncryption.EncryptPayload(payload, config);

            // THEN
            var encryptedPayloadObject = JObject.Parse(encryptedPayload);
            Assert.IsNull(encryptedPayloadObject["data"]);
            var encryptedData = encryptedPayloadObject["encryptedData"];
            Assert.IsNotNull(encryptedData);
            Assert.AreEqual("SHA256", encryptedData["oaepHashingAlgorithm"]);
            Assert.AreEqual("761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79", encryptedData["encryptionKeyFingerprint"]);
            Assert.AreEqual("80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279", encryptedData["encryptionCertificateFingerprint"]);
            Assert.AreEqual(16, Convert.FromBase64String(encryptedData["encryptedValue"].ToString()).Length);
            Assert.AreEqual(256, Convert.FromBase64String(encryptedData["encryptedKey"].ToString()).Length);
            Assert.AreEqual(16, Convert.FromBase64String(encryptedData["iv"].ToString()).Length);
        }

        [TestMethod]
        public void TestEncryptPayload_ShouldEncryptPrimitiveTypes_String()
        {
            // GIVEN
            const string payload = "{\"data\": \"string\", \"encryptedData\": {}}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithEncryptionPath("data", "encryptedData")
                .WithDecryptionPath("encryptedData", "data")
                .WithOaepPaddingDigestAlgorithm("SHA-256")
                .Build();

            // WHEN
            var encryptedPayload = FieldLevelEncryption.EncryptPayload(payload, config);

            // THEN
            var encryptedPayloadObject = JObject.Parse(encryptedPayload);
            Assert.IsNull(encryptedPayloadObject["data"]);
            Assert.IsNotNull(encryptedPayloadObject["encryptedData"]);
            TestUtils.AssertDecryptedPayloadEquals("{\"data\":\"string\"}", encryptedPayload, config);
        }

        [TestMethod]
        public void TestEncryptPayload_ShouldEncryptPrimitiveTypes_NumberAsString()
        {
            // GIVEN
            const string payload = "{\"data\": \"123\", \"encryptedData\": {}}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithEncryptionPath("data", "encryptedData")
                .WithDecryptionPath("encryptedData", "data")
                .WithOaepPaddingDigestAlgorithm("SHA-256")
                .Build();

            // WHEN
            var encryptedPayload = FieldLevelEncryption.EncryptPayload(payload, config);

            // THEN
            var encryptedPayloadObject = JObject.Parse(encryptedPayload);
            Assert.IsNull(encryptedPayloadObject["data"]);
            Assert.IsNotNull(encryptedPayloadObject["encryptedData"]);
            TestUtils.AssertDecryptedPayloadEquals("{\"data\":123}", encryptedPayload, config);
        }

        [TestMethod]
        public void TestEncryptPayload_ShouldEncryptPrimitiveTypes_Integer()
        {
            // GIVEN
            const string payload = "{\"data\": 1984, \"encryptedData\": {}}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithEncryptionPath("data", "encryptedData")
                .WithDecryptionPath("encryptedData", "data")
                .WithOaepPaddingDigestAlgorithm("SHA-256")
                .Build();

            // WHEN
            var encryptedPayload = FieldLevelEncryption.EncryptPayload(payload, config);

            // THEN
            var encryptedPayloadObject = JObject.Parse(encryptedPayload);
            Assert.IsNull(encryptedPayloadObject["data"]);
            Assert.IsNotNull(encryptedPayloadObject["encryptedData"]);
            TestUtils.AssertDecryptedPayloadEquals("{\"data\":1984}", encryptedPayload, config);
        }

        [TestMethod]
        public void TestEncryptPayload_ShouldEncryptPrimitiveTypes_Boolean()
        {
            // GIVEN
            const string payload = "{\"data\": false, \"encryptedData\": {}}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithEncryptionPath("data", "encryptedData")
                .WithDecryptionPath("encryptedData", "data")
                .WithOaepPaddingDigestAlgorithm("SHA-256")
                .Build();

            // WHEN
            var encryptedPayload = FieldLevelEncryption.EncryptPayload(payload, config);

            // THEN
            var encryptedPayloadObject = JObject.Parse(encryptedPayload);
            Assert.IsNull(encryptedPayloadObject["data"]);
            Assert.IsNotNull(encryptedPayloadObject["encryptedData"]);
            TestUtils.AssertDecryptedPayloadEquals("{\"data\":false}", encryptedPayload, config);
        }

        [TestMethod]
        public void TestEncryptPayload_ShouldEncryptArrayFields()
        {
            // GIVEN
            const string payload = "{" +
                "    \"items\": [" +
                "        {}," +
                "        {}" +
                "    ]" +
                "}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithEncryptionPath("items", "encryptedItems")
                .WithDecryptionPath("encryptedItems", "items")
                .WithOaepPaddingDigestAlgorithm("SHA-256")
                .Build();

            // WHEN
            var encryptedPayload = FieldLevelEncryption.EncryptPayload(payload, config);

            // THEN
            var encryptedPayloadObject = JObject.Parse(encryptedPayload);
            Assert.IsNull(encryptedPayloadObject["items"]);
            Assert.IsNotNull(encryptedPayloadObject["encryptedItems"]);
            TestUtils.AssertDecryptedPayloadEquals("{\"items\":[{},{}]}", encryptedPayload, config);
        }

        [TestMethod]
        public void TestEncryptPayload_ShouldEncryptRootArrays()
        {
            // GIVEN
            const string payload = "[" +
                                   "    {}," +
                                   "    {}" +
                                   "]";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithEncryptionPath("$", "$")
                .WithDecryptionPath("$", "$")
                .WithOaepPaddingDigestAlgorithm("SHA-256")
                .Build();

            // WHEN
            var encryptedPayload = FieldLevelEncryption.EncryptPayload(payload, config);

            // THEN
            var encryptedPayloadObject = JObject.Parse(encryptedPayload);
            Assert.IsNotNull(encryptedPayloadObject);
            TestUtils.AssertDecryptedPayloadEquals("[{},{}]", encryptedPayload, config);
        }

        [TestMethod]
        public void TestEncryptPayload_ShouldDoNothing_WhenInPathDoesNotExistInPayload()
        {
            // GIVEN
            const string payload = "{\"data\": {}, \"encryptedData\": {}}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                    .WithEncryptionPath("objectNotInPayload", "encryptedData")
                    .Build();

            // WHEN
            var encryptedPayload = FieldLevelEncryption.EncryptPayload(payload, config);

            // THEN
            TestUtils.AssertPayloadEquals("{\"data\":{},\"encryptedData\":{}}", encryptedPayload);
        }

        [TestMethod]
        public void TestEncryptPayload_ShouldCreateEncryptionFields_WhenOutPathParentExistsInPayload()
        {
            // GIVEN
            const string payload = "{\"data\": {}, \"encryptedDataParent\": {}}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                    .WithEncryptionPath("data", "encryptedDataParent.encryptedData")
                    .Build();

            // WHEN
            var encryptedPayload = FieldLevelEncryption.EncryptPayload(payload, config);

            // THEN
            var encryptedPayloadObject = JObject.Parse(encryptedPayload);
            Assert.IsNull(encryptedPayloadObject["data"]);
            Assert.IsNotNull(encryptedPayloadObject["encryptedDataParent"]["encryptedData"]);
        }

        [TestMethod]
        [ExpectedException(typeof(EncryptionException))]
        public void TestEncryptPayload_ShouldThrowInvalidOperationException_WhenOutPathParentDoesNotExistInPayload()
        {
            try
            {
                // GIVEN
                const string payload = "{\"data\": {}}";
                var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                    .WithEncryptionPath("data", "parentNotInPayload.encryptedData")
                    .Build();               

                // WHEN
                FieldLevelEncryption.EncryptPayload(payload, config);
            }
            catch (Exception e)
            {
                // THEN
                Assert.IsTrue(e.InnerException is InvalidOperationException);
                Assert.AreEqual("Parent path not found in payload: 'parentNotInPayload'!", e.InnerException.Message);
                Assert.AreEqual("Payload encryption failed!", e.Message);
                throw;
            }
        }

        [TestMethod]
        [ExpectedException(typeof(EncryptionException))]
        public void TestEncryptPayload_ShouldThrowInvalidOperationException_WhenOutPathIsPathToJsonPrimitive()
        {
            try
            {
                // GIVEN
                const string payload = "{\"data\": {}, \"encryptedData\": \"string\"}";
                var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                    .WithEncryptionPath("data", "encryptedData")
                    .WithOaepPaddingDigestAlgorithm("SHA-256")
                    .Build();

                // WHEN
                FieldLevelEncryption.EncryptPayload(payload, config);
            }
            catch (Exception e)
            {
                // THEN
                Assert.IsTrue(e.InnerException is InvalidOperationException);
                Assert.AreEqual("JSON object expected at path: 'encryptedData'!", e.InnerException.Message);
                Assert.AreEqual("Payload encryption failed!", e.Message);
                throw;
            }
        }
        
        [TestMethod]
        public void TestEncryptPayload_ShouldNotSetCertificateAndKeyFingerprints_WhenFieldNamesNotSetInConfig()
        {
            // GIVEN
            const string payload = "{\"data\": {}, \"encryptedData\": {}}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithEncryptionPath("data", "encryptedData")
                .WithEncryptionCertificateFingerprintFieldName(null)
                .WithEncryptionKeyFingerprintFieldName(null)
                .Build();

            // WHEN
            var encryptedPayload = FieldLevelEncryption.EncryptPayload(payload, config);

            // THEN
            var encryptedPayloadObject = JObject.Parse(encryptedPayload);
            var encryptedData = encryptedPayloadObject["encryptedData"];
            Assert.IsNull(encryptedData["encryptionKeyFingerprint"]);
            Assert.IsNull(encryptedData["encryptionCertificateFingerprint"]);
        }
       
        [TestMethod]
        public void TestEncryptPayload_ShouldSupportMultipleEncryptions()
        {
            // GIVEN
            const string payload = "{\"data1\": {}, \"data2\": {}, \"encryptedData1\": {}, \"encryptedData2\": {}}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                        .WithEncryptionPath("data1", "encryptedData1")
                        .WithEncryptionPath("data2", "encryptedData2")
                        .Build();

            // WHEN
            var encryptedPayload = FieldLevelEncryption.EncryptPayload(payload, config);

            // THEN
            var encryptedPayloadObject = JObject.Parse(encryptedPayload);
            Assert.IsNull(encryptedPayloadObject["data1"]);
            Assert.IsNull(encryptedPayloadObject["data2"]);
            var encryptedData1 = encryptedPayloadObject["encryptedData1"];
            Assert.IsNotNull(encryptedData1["encryptedValue"]);
            var encryptedData2 = encryptedPayloadObject["encryptedData2"];
            Assert.IsNotNull(encryptedData2["encryptedValue"]);
            // The 2 should use a different set of params (IV and symmetric key)
            var iv1 = encryptedData1["iv"].ToString();
            var iv2 = encryptedData2["iv"].ToString();
            Assert.AreNotEqual(iv1, iv2);
        }
        
        [TestMethod]
        public void TestEncryptPayload_ShouldSupportBasicExistingJsonPaths()
        {
            // GIVEN
            const string payload = "{\"data1\": {}, \"encryptedData1\": {}," +
                   " \"data2\": {}, \"encryptedData2\": {}," +
                   " \"data3\": {}, \"encryptedData3\": {}," +
                   " \"data4\": { \"object\": {} }, \"encryptedData4\": { \"object\": {} }}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                   .WithEncryptionPath("$.data1", "$.encryptedData1")
                   .WithEncryptionPath("data2", "encryptedData2")
                   .WithEncryptionPath("$['data3']", "$['encryptedData3']")
                   .WithEncryptionPath("$['data4']['object']", "$['encryptedData4']['object']")
                   .Build();

            // WHEN
            var encryptedPayload = FieldLevelEncryption.EncryptPayload(payload, config);

            // THEN
            var encryptedPayloadObject = JObject.Parse(encryptedPayload);
            Assert.IsNull(encryptedPayloadObject["data1"]);
            Assert.IsNull(encryptedPayloadObject["data2"]);
            Assert.IsNull(encryptedPayloadObject["data3"]);
            Assert.IsNull(encryptedPayloadObject["data4"]["object"]);
            Assert.IsNotNull(encryptedPayloadObject["encryptedData1"]["encryptedValue"]);
            Assert.IsNotNull(encryptedPayloadObject["encryptedData2"]["encryptedValue"]);
            Assert.IsNotNull(encryptedPayloadObject["encryptedData3"]["encryptedValue"]);
            Assert.IsNotNull(encryptedPayloadObject["encryptedData4"]["object"]["encryptedValue"]);
        }

        [TestMethod]
        public void TestEncryptPayload_ShouldSupportBasicNotExistingJsonPaths()
        {
            // GIVEN
            const string payload = "{\"data1\": {}, \"data2\": {}, \"data3\": {}, " +
                                   " \"data4\": { \"object\": {} }, \"encryptedData4\": {}}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithEncryptionPath("$.data1", "$.encryptedData1")
                .WithEncryptionPath("data2", "encryptedData2")
                .WithEncryptionPath("$['data3']", "$['encryptedData3']")
                .WithEncryptionPath("$['data4']['object']", "$['encryptedData4']['object']")
                .Build();

            // WHEN
            var encryptedPayload = FieldLevelEncryption.EncryptPayload(payload, config);

            // THEN
            var encryptedPayloadObject = JObject.Parse(encryptedPayload);
            Assert.IsNull(encryptedPayloadObject["data1"]);
            Assert.IsNull(encryptedPayloadObject["data2"]);
            Assert.IsNull(encryptedPayloadObject["data3"]);
            Assert.IsNull(encryptedPayloadObject["data4"]["object"]);
            Assert.IsNotNull(encryptedPayloadObject["encryptedData1"]["encryptedValue"]);
            Assert.IsNotNull(encryptedPayloadObject["encryptedData2"]["encryptedValue"]);
            Assert.IsNotNull(encryptedPayloadObject["encryptedData3"]["encryptedValue"]);
            Assert.IsNotNull(encryptedPayloadObject["encryptedData4"]["object"]["encryptedValue"]);
        }
        
        [TestMethod]
        public void TestEncryptPayload_ShouldMergeJsonObjects_WhenOutPathAlreadyContainData()
        {
            // GIVEN
            const string payload = "{" +
                "    \"data\": {}," +
                "    \"encryptedData\": {" +
                "        \"field1\": \"field1Value\"," +
                "        \"iv\": \"previousIvValue\"" +
                "    }" +
                "}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithEncryptionPath("data", "encryptedData")
                .WithOaepPaddingDigestAlgorithm("SHA-256")
                .Build();

            // WHEN
            var encryptedPayload = FieldLevelEncryption.EncryptPayload(payload, config);

            // THEN
            var encryptedPayloadObject = JObject.Parse(encryptedPayload);
            var encryptedData = encryptedPayloadObject["encryptedData"];
            Assert.IsNotNull(encryptedData);
            Assert.AreEqual("field1Value", encryptedData["field1"]);
            Assert.AreNotEqual("previousIvValue", encryptedData["iv"]);
        }

        [TestMethod]
        public void TestEncryptPayload_ShouldOverwriteInputObject_WhenOutPathSameAsInPath()
        {
            // GIVEN
            const string payload = "{" +
                "    \"data\": {" +
                "        \"encryptedData\": {}" +
                "    }   " +
                "}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithEncryptionPath("data.encryptedData", "data")
                .WithEncryptedValueFieldName("encryptedData")
                .WithOaepPaddingDigestAlgorithm("SHA-256")
                .Build();

            // WHEN
            var encryptedPayload = FieldLevelEncryption.EncryptPayload(payload, config);

            // THEN
            var encryptedPayloadObject = JObject.Parse(encryptedPayload);
            var dataObject = encryptedPayloadObject["data"];
            Assert.IsNotNull(dataObject["iv"]);
            Assert.IsNotNull(dataObject["encryptedKey"]);
            Assert.IsNotNull(dataObject["encryptionCertificateFingerprint"]);
            Assert.IsNotNull(dataObject["encryptionKeyFingerprint"]);
            Assert.IsNotNull(dataObject["oaepHashingAlgorithm"]);
            Assert.IsNotNull(dataObject["encryptedData"]);
        }

        [TestMethod]
        public void TestEncryptPayload_ShouldNotAddOaepPaddingDigestAlgorithm_WhenOaepPaddingDigestAlgorithmFieldNameNotSet()
        {
            // GIVEN
            const string payload = "{\"data\": {}, \"encryptedData\": {}}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithEncryptionPath("data", "encryptedData")
                .WithOaepPaddingDigestAlgorithm("SHA-256")
                .WithOaepPaddingDigestAlgorithmFieldName(null)
                .Build();

            // WHEN
            var encryptedPayload = FieldLevelEncryption.EncryptPayload(payload, config);

            // THEN
            var encryptedPayloadObject = JObject.Parse(encryptedPayload);
            var encryptedData = encryptedPayloadObject["encryptedData"];
            Assert.IsNotNull(encryptedData);
            Assert.AreEqual(5, encryptedData.Count());
        }

        [TestMethod]
        public void TestEncryptPayload_ShouldSupportRootAsInputPath()
        {
            // GIVEN
            const string payload = "{" +
                "    \"field1\": \"value1\"," +
                "    \"field2\": \"value2\"" +
                "}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithEncryptionPath("$", "encryptedData")
                .WithOaepPaddingDigestAlgorithm("SHA-256")
                .Build();

            // WHEN
            var encryptedPayload = FieldLevelEncryption.EncryptPayload(payload, config);

            // THEN
            var encryptedPayloadObject = JObject.Parse(encryptedPayload);
            Assert.IsNull(encryptedPayloadObject["field1"]);
            Assert.IsNull(encryptedPayloadObject["field2"]);
            var encryptedData = encryptedPayloadObject["encryptedData"];
            Assert.IsNotNull(encryptedData);
            Assert.AreEqual(6, encryptedData.Count());
        }
      
        [TestMethod]
        public void TestEncryptPayload_ShouldSupportRootAsInputPathAndOutputPath()
        {
            // GIVEN
            const string payload = "{" +
                "    \"field1\": \"value1\"," +
                "    \"field2\": \"value2\"" +
                "}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithEncryptionPath("$", "$")
                .WithOaepPaddingDigestAlgorithm("SHA-256")
                .Build();

            // WHEN
            var encryptedPayload = FieldLevelEncryption.EncryptPayload(payload, config);

            // THEN
            var encryptedPayloadObject = JObject.Parse(encryptedPayload);
            Assert.IsNull(encryptedPayloadObject["field1"]);
            Assert.IsNull(encryptedPayloadObject["field2"]);
            Assert.AreEqual(6, encryptedPayloadObject.Children().Count());
        }
      
        [TestMethod]
        [ExpectedException(typeof(EncryptionException))]
        public void TestEncryptPayload_ShouldThrowEncryptionException_WhenEncryptionErrorOccurs()
        {
            try
            {
                // GIVEN
                const string payload = "{\"data\": {}, \"encryptedData\": {}}";
                var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                    .WithEncryptionPath("data", "encryptedData")
                    .WithEncryptionCertificate(TestUtils.GetTestInvalidEncryptionCertificate()) // Invalid certificate
                    .WithOaepPaddingDigestAlgorithm("SHA-256")
                    .Build();

                // WHEN
                FieldLevelEncryption.EncryptPayload(payload, config);
            }
            catch (Exception e)
            {
                // THEN
                Assert.AreEqual("Payload encryption failed!", e.Message);
                throw;
            }
        }
 
        [TestMethod]
        public void TestEncryptPayload_ShouldUseProvidedEncryptionParams_WhenPassedAsArgument()
        {
            // GIVEN
            const string payload = "{\"data\": {}, \"encryptedData\": {}}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithEncryptionPath("data", "encryptedData")
                .Build();
            var parameters = FieldLevelEncryptionParams.Generate(config);

            // WHEN
            var encryptedPayload = FieldLevelEncryption.EncryptPayload(payload, config, parameters);

            // THEN
            var encryptedPayloadObject = JObject.Parse(encryptedPayload);
            var encryptedData = encryptedPayloadObject["encryptedData"];
            Assert.AreEqual(parameters.IvValue, encryptedData["iv"].ToString());
            Assert.AreEqual(parameters.EncryptedKeyValue, encryptedData["encryptedKey"].ToString());
            Assert.AreEqual(parameters.OaepPaddingDigestAlgorithmValue, encryptedData["oaepHashingAlgorithm"].ToString());
            Assert.AreEqual(config.EncryptionCertificateFingerprint, encryptedData["encryptionCertificateFingerprint"].ToString());
            Assert.AreEqual(config.EncryptionKeyFingerprint, encryptedData["encryptionKeyFingerprint"].ToString());
        }

        [TestMethod]
        public void TestEncryptPayload_ShouldGenerateEncryptionParams_WhenNullArgument()
        {
            // GIVEN
            const string payload = "{" +
                "    \"data\": {" +
                "        \"field1\": \"value1\"," +
                "        \"field2\": \"value2\"" +
                "    }," +
                "    \"encryptedData\": {}" +
                "}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithEncryptionPath("data", "encryptedData")
                .WithOaepPaddingDigestAlgorithm("SHA-256")
                .Build();

            // WHEN
            var encryptedPayload = FieldLevelEncryption.EncryptPayload(payload, config);

            // THEN
            var encryptedPayloadObject = JObject.Parse(encryptedPayload);
            Assert.IsNull(encryptedPayloadObject["data"]);
            var encryptedData = encryptedPayloadObject["encryptedData"];
            Assert.IsNotNull(encryptedData);
            Assert.AreEqual(6, encryptedData.Count());
        }

        [TestMethod]
        public void TestEncryptPayload_ShouldNotAddEncryptionParamsToPayload_WhenFieldNamesNotSetInConfig()
        {
            // GIVEN
            const string payload = "{" +
                "    \"data\": {" +
                "        \"field1\": \"value1\"," +
                "        \"field2\": \"value2\"" +
                "    }," +
                "    \"encryptedData\": {}" +
                "}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithEncryptionPath("data", "encryptedData")
                .WithOaepPaddingDigestAlgorithm("SHA-256")
                .WithOaepPaddingDigestAlgorithmFieldName(null)
                .WithEncryptedKeyFieldName(null)
                .WithEncryptedKeyHeaderName("x-encrypted-key")
                .WithEncryptionKeyFingerprintFieldName(null)
                .WithEncryptionCertificateFingerprintFieldName(null)
                .WithIvFieldName(null)
                .WithIvHeaderName("x-iv")
                .Build();

            // WHEN
            var encryptedPayload = FieldLevelEncryption.EncryptPayload(payload, config);

            // THEN
            var encryptedPayloadObject = JObject.Parse(encryptedPayload);
            Assert.IsNull(encryptedPayloadObject["data"]);
            var encryptedData = encryptedPayloadObject["encryptedData"];
            Assert.IsNotNull(encryptedData);
            Assert.AreEqual(1, encryptedData.Count()); // "encryptedValue" only
        }

        [TestMethod]
        public void TestDecryptPayload_Nominal()
        {
            // GIVEN
            const string encryptedPayload = "{" +
            "    \"encryptedData\": {" +
            "        \"iv\": \"ba574b07248f63756bce778f8a115819\"," +
            "        \"encryptedKey\": \"26687f6d03d27145451d20bdaa29cc199e2533bb9eb7351772e31d1290b98380b43dbf47b9a337cc2ecaff9d3d9fb45305950f13382c5ad822ee6df79e1a57b14a3c58c71090121994a9f771ef96472669671718b55a0fa8d9f76de9e172fedcabbc87d64b5a994899e43abb19afa840269012c397b5b18d4babc0e41c1ad698db98c89121bbe5b2d227cfc5d3c3c87f4f4c8b04b509d326199b39adfbd8bca8bf0a150fcf3c37b9717382af502ad8d4d28b17b91762bf108d34aba0fb40ca410c2ecaeb30d68003af20dce27d9d034e4c557b8104e85f859de0eb709b23f9978869bae545c7f1b62173887eae9e75e4b6d6b4b01d7172ccc8c5774c0db51c24\"," +
            "        \"encryptedValue\": \"2867e67545b2f3d0708500a1cea649e3\"," +
            "        \"encryptionCertificateFingerprint\": \"80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279\"," +
            "        \"encryptionKeyFingerprint\": \"761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79\"," +
            "        \"oaepHashingAlgorithm\": \"SHA256\"" +
            "    }" +
            "}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithDecryptionPath("encryptedData", "data")
                .Build();

            // WHEN
            var payload = FieldLevelEncryption.DecryptPayload(encryptedPayload, config);

            // THEN
            TestUtils.AssertPayloadEquals("{\"data\":{}}", payload);
        }

        [TestMethod]
        public void TestDecryptPayload_ShouldDecryptPrimitiveTypes_String()
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
                .WithDecryptionPath("encryptedData", "data")
                .Build();

            // WHEN
            var payload = FieldLevelEncryption.DecryptPayload(encryptedPayload, config);

            // THEN
            TestUtils.AssertPayloadEquals("{\"data\":\"string\"}", payload);
        }

        [TestMethod]
        public void TestDecryptPayload_ShouldDecryptPrimitiveTypes_Integer()
        {
            // GIVEN
            const string encryptedPayload = "{" +
                    "    \"encryptedData\": {" +
                    "        \"iv\": \"5bb681fb4ca4a8f85a9c80b8f234e87c\"," +
                    "        \"encryptedKey\": \"d6819275d3a692bddce0baa10187769e0d683c351fb4e1857ab30f2572fbe1db95c34583d20ea5b224a638e99d26f6935104500b49fc1e855b7af30f34ac1d148090c6393e77e0f16d710614d00817ac862f9af730e9b3596d2c0dacf1349abd18717792ac3040f4ef1cc2e8fd9e0d685a192bfc6800e79022393eb3ce326757ba556107be28c02590390fad73117f7da3d96c05f54aaa36541b05680f23a222f1b7bbe54f1b070515dfbea8e5312708d5c27bfe9d9350e7bb72914351a6db1d83cdefee7d7514d04b73b6e285f334b27c674ad50ec830494ebc2901f1fe1738863b2d7940c98a15e1467d501545bffa724fd97b2d673e92629c9be79ca7381f\"," +
                    "        \"encryptedValue\": \"072b6ef69afd42d43b89afdf8f8bb172\"," +
                    "        \"oaepHashingAlgorithm\": \"SHA256\"" +
                    "    }" +
                    "}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                    .WithDecryptionPath("encryptedData", "data")
                    .Build();

            // WHEN
            var payload = FieldLevelEncryption.DecryptPayload(encryptedPayload, config);

            // THEN
            TestUtils.AssertPayloadEquals("{\"data\":1984}", payload);
        }

        [TestMethod]
        public void TestDecryptPayload_ShouldDecryptPrimitiveTypes_Boolean()
        {
            // GIVEN
            const string encryptedPayload = "{" +
                    "    \"encryptedData\": {" +
                    "        \"iv\": \"683c1559d6b9366f21efc4dec682cca2\"," +
                    "        \"encryptedKey\": \"631f0729018db2aa4f02823eeac6c1bf4bc766897dfd8159ec831086acb68cf37d91427347db77869fe1088e4cd8553b5bb0308accb43e92a3977245e0005385fc538aacea323cb62d44d21c932b7fbb3fc2039de44d18fff130108b30bd5c9925a3463ace729099ce63375dfa1dd9ec9f1e277de6b4ace5161a0e47ae81908aa2f8b44a654be2b863d6dfc5112a422dda065d8fbc0d5e47ea435409262c608edfc28a49e90fbda035c1743ec8cabd453d75775b0ab7b660b20b3a1f37c6eecffa32a26b07adf78432e1dd479a2ce19002846cb2fa2488ade423265ce7c4b003373837971c7b803925624f8eeb9254dad347941ebab8f641522b5b1efe53f572\"," +
                    "        \"encryptedValue\": \"cc8bb0cc778d508f198c39364cce9137\"," +
                    "        \"oaepHashingAlgorithm\": \"SHA256\"" +
                    "    }" +
                    "}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                    .WithDecryptionPath("encryptedData", "data")
                    .Build();

            // WHEN
            var payload = FieldLevelEncryption.DecryptPayload(encryptedPayload, config);

            // THEN
            TestUtils.AssertPayloadEquals("{\"data\":false}", payload);
        }

        [TestMethod]
        public void TestDecryptPayload_ShouldDecryptArrayFields()
        {
            // GIVEN
            const string encryptedPayload = "{" +
                "    \"encryptedItems\": {" +
                "        \"iv\": \"34010a3ea7231126a0d1e088ec8db173\"," +
                "        \"encryptedKey\": \"072aee9f7dd6cf381eb61e6d93c2e19e4032e1166d36d3ccb32ec379815f472e27d82a0de48617ff440d37a534bb38b170cf236a78148a375971e83b087eb7d05807863e70b43baa446934fe6f70150e3ca4e49e70fecabb1969c1fc5a38f13a75e318077760e4fe53e25ca011781d1038d19bb3a16928d35302bc7e389c8fb089230b8c0acc3c7e59c120cfe3aece6ff346aaa598a2baf003026f0a32307af022b9515fea564bb5d491b0159b20d909deb9cb5e8077d6471ad1ad3d7e743d6c3cf09f999c22006038980268b9d0cac1fd2e53b1a6e8e4d63b0a3e4457ff27ffab7cd025011b678e0ff56537c29e81ed087fe11988c2c92a7c7695f1fc6f856a\"," +
                "        \"encryptedValue\": \"d91268566c92621d394b5e5d94069387\"," +
                "        \"oaepHashingAlgorithm\": \"SHA256\"" +
                "    }" +
                "}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithDecryptionPath("$.encryptedItems", "$.items")
                .Build();

            // WHEN
            var payload = FieldLevelEncryption.DecryptPayload(encryptedPayload, config);

            // THEN
            TestUtils.AssertPayloadEquals("{\"items\":[{},{}]}", payload);
        }

        [TestMethod]
        public void TestDecryptPayload_ShouldDecryptRootArrays()
        {
            // GIVEN
            const string encryptedPayload = "{" +
                "    \"iv\": \"ed82c0496e9d5ac769d77bdb2eb27958\"," +
                "    \"encryptedKey\": \"29ea447b70bdf85dd509b5d4a23dc0ffb29fd1acf50ed0800ec189fbcf1fb813fa075952c3de2915d63ab42f16be2ed46dc27ba289d692778a1d585b589039ba0b25bad326d699c45f6d3cffd77b5ec37fe12e2c5456d49980b2ccf16402e83a8e9765b9b93ca37d4d5181ec3e5327fd58387bc539238f1c20a8bc9f4174f5d032982a59726b3e0b9cf6011d4d7bfc3afaf617e768dea6762750bce07339e3e55fdbd1a1cd12ee6bbfbc3c7a2d7f4e1313410eb0dad13e594a50a842ee1b2d0ff59d641987c417deaa151d679bc892e5c051b48781dbdefe74a12eb2b604b981e0be32ab81d01797117a24fbf6544850eed9b4aefad0eea7b3f5747b20f65d3f\"," +
                "    \"encryptedValue\": \"3496b0c505bcea6a849f8e30b553e6d4\"," +
                "    \"oaepHashingAlgorithm\": \"SHA256\"" +
                "}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithDecryptionPath("$", "$")
                .Build();

            // WHEN
            var payload = FieldLevelEncryption.DecryptPayload(encryptedPayload, config);

            // THEN
            TestUtils.AssertPayloadEquals("[{},{}]", payload);
        }

        [TestMethod]
        public void TestDecryptPayload_ShouldSupportBase64FieldValueDecoding()
        {
            // GIVEN
            const string encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"iv\": \"uldLBySPY3VrznePihFYGQ==\"," +
                "        \"encryptedKey\": \"Jmh/bQPScUVFHSC9qinMGZ4lM7uetzUXcuMdEpC5g4C0Pb9HuaM3zC7K/509n7RTBZUPEzgsWtgi7m33nhpXsUo8WMcQkBIZlKn3ce+WRyZpZxcYtVoPqNn3benhcv7cq7yH1ktamUiZ5Dq7Ga+oQCaQEsOXtbGNS6vA5Bwa1pjbmMiRIbvlstInz8XTw8h/T0yLBLUJ0yYZmzmt+9i8qL8KFQ/PPDe5cXOCr1Aq2NTSixe5F2K/EI00q6D7QMpBDC7K6zDWgAOvINzifZ0DTkxVe4EE6F+FneDrcJsj+ZeIabrlRcfxtiFziH6unnXktta0sB1xcszIxXdMDbUcJA==\"," +
                "        \"encryptedValue\": \"KGfmdUWy89BwhQChzqZJ4w==\"," +
                "        \"encryptionCertificateFingerprint\": \"gIEPwTqDGfzw4uwyLIKkwwS3gsw85nEXY0PP6BYMInk=\"," +
                "        \"encryptionKeyFingerprint\": \"dhsAPB6t46VJDlAA03iHuqXm7A4ibAdwblmUUfwDKnk=\"," +
                "        \"oaepHashingAlgorithm\": \"SHA256\"" +
                "    }" +
                "}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithDecryptionPath("encryptedData", "data")
                .WithValueEncoding(FieldValueEncoding.Base64)
                .Build();

            // WHEN
            var payload = FieldLevelEncryption.DecryptPayload(encryptedPayload, config);

            // THEN
            TestUtils.AssertPayloadEquals("{\"data\":{}}", payload);
        }

        [TestMethod]
        public void TestDecryptPayload_ShouldDoNothing_WhenInPathDoesNotExistInPayload()
        {
            // GIVEN
            const string encryptedPayload = "{\"data\": {}}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithDecryptionPath("objectNotInPayload", "data")
                .Build();

            // WHEN
            var payload = FieldLevelEncryption.DecryptPayload(encryptedPayload, config);

            // THEN
            TestUtils.AssertPayloadEquals("{\"data\":{}}", payload);
        }

        [TestMethod]
        public void TestDecryptPayload_ShouldDoNothing_WhenEncryptedValueDoesNotExistInPayload()
        {
            // GIVEN
            const string encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"iv\": \"ba574b07248f63756bce778f8a115819\"," +
                "        \"encryptedKey\": \"26687f6d03d27145451d20bdaa29cc199e2533bb9eb7351772e31d1290b98380b43dbf47b9a337cc2ecaff9d3d9fb45305950f13382c5ad822ee6df79e1a57b14a3c58c71090121994a9f771ef96472669671718b55a0fa8d9f76de9e172fedcabbc87d64b5a994899e43abb19afa840269012c397b5b18d4babc0e41c1ad698db98c89121bbe5b2d227cfc5d3c3c87f4f4c8b04b509d326199b39adfbd8bca8bf0a150fcf3c37b9717382af502ad8d4d28b17b91762bf108d34aba0fb40ca410c2ecaeb30d68003af20dce27d9d034e4c557b8104e85f859de0eb709b23f9978869bae545c7f1b62173887eae9e75e4b6d6b4b01d7172ccc8c5774c0db51c24\"," +
                "        \"oaepHashingAlgorithm\": \"SHA256\"" +
                "    }" +
                "}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithDecryptionPath("encryptedData", "data")
                .Build();

            // WHEN
            var payload = FieldLevelEncryption.DecryptPayload(encryptedPayload, config);

            // THEN
            var payloadObject = JObject.Parse(payload);
            Assert.IsNotNull(payloadObject["encryptedData"]);
            Assert.IsNotNull(payloadObject["encryptedData"]["iv"]);
        }

        [TestMethod]
        public void TestDecryptPayload_ShouldCreateDataFields_WhenOutPathParentExistsInPayload()
        {
            // GIVEN
            const string encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"iv\": \"ba574b07248f63756bce778f8a115819\"," +
                "        \"encryptedKey\": \"26687f6d03d27145451d20bdaa29cc199e2533bb9eb7351772e31d1290b98380b43dbf47b9a337cc2ecaff9d3d9fb45305950f13382c5ad822ee6df79e1a57b14a3c58c71090121994a9f771ef96472669671718b55a0fa8d9f76de9e172fedcabbc87d64b5a994899e43abb19afa840269012c397b5b18d4babc0e41c1ad698db98c89121bbe5b2d227cfc5d3c3c87f4f4c8b04b509d326199b39adfbd8bca8bf0a150fcf3c37b9717382af502ad8d4d28b17b91762bf108d34aba0fb40ca410c2ecaeb30d68003af20dce27d9d034e4c557b8104e85f859de0eb709b23f9978869bae545c7f1b62173887eae9e75e4b6d6b4b01d7172ccc8c5774c0db51c24\"," +
                "        \"encryptedValue\": \"2867e67545b2f3d0708500a1cea649e3\"," +
                "        \"oaepHashingAlgorithm\": \"SHA256\"" +
                "    }, " +
                "    \"dataParent\": {}" +
                "}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithDecryptionPath("encryptedData", "dataParent.data")
                .Build();

            // WHEN
            var payload = FieldLevelEncryption.DecryptPayload(encryptedPayload, config);

            // THEN
            var payloadObject = JObject.Parse(payload);
            Assert.IsNull(payloadObject["encryptedData"]);
            Assert.AreEqual("{}", payloadObject["dataParent"]["data"].ToString());
        }

        [TestMethod]
        [ExpectedException(typeof(EncryptionException))]
        public void TestDecryptPayload_ShouldThrowInvalidOperationException_WhenOutPathParentDoesNotExistInPayload()
        {
            try
            {
                // GIVEN
                const string encryptedPayload = "{" +
                    "    \"encryptedData\": {" +
                    "        \"iv\": \"ba574b07248f63756bce778f8a115819\"," +
                    "        \"encryptedKey\": \"26687f6d03d27145451d20bdaa29cc199e2533bb9eb7351772e31d1290b98380b43dbf47b9a337cc2ecaff9d3d9fb45305950f13382c5ad822ee6df79e1a57b14a3c58c71090121994a9f771ef96472669671718b55a0fa8d9f76de9e172fedcabbc87d64b5a994899e43abb19afa840269012c397b5b18d4babc0e41c1ad698db98c89121bbe5b2d227cfc5d3c3c87f4f4c8b04b509d326199b39adfbd8bca8bf0a150fcf3c37b9717382af502ad8d4d28b17b91762bf108d34aba0fb40ca410c2ecaeb30d68003af20dce27d9d034e4c557b8104e85f859de0eb709b23f9978869bae545c7f1b62173887eae9e75e4b6d6b4b01d7172ccc8c5774c0db51c24\"," +
                    "        \"encryptedValue\": \"2867e67545b2f3d0708500a1cea649e3\"," +
                    "        \"oaepHashingAlgorithm\": \"SHA256\"" +
                    "    }" +
                    "}";
                var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                    .WithDecryptionPath("encryptedData", "parentNotInPayload.data")
                    .Build();

                // WHEN
                FieldLevelEncryption.DecryptPayload(encryptedPayload, config);
            }
            catch (Exception e)
            {
                // THEN
                Assert.IsTrue(e.InnerException is InvalidOperationException);
                Assert.AreEqual("Parent path not found in payload: 'parentNotInPayload'!", e.InnerException.Message);
                Assert.AreEqual("Payload decryption failed!", e.Message);
                throw;
            }
        }

        [TestMethod]
        [ExpectedException(typeof(EncryptionException))]
        public void TestDecryptPayload_ShouldThrowInvalidOperationException_WhenOutPathIsPathToJsonPrimitive()
        {
            try
            {
                // GIVEN
                const string encryptedPayload = "{" +
                    "    \"encryptedData\": {" +
                    "        \"iv\": \"ba574b07248f63756bce778f8a115819\"," +
                    "        \"encryptedKey\": \"26687f6d03d27145451d20bdaa29cc199e2533bb9eb7351772e31d1290b98380b43dbf47b9a337cc2ecaff9d3d9fb45305950f13382c5ad822ee6df79e1a57b14a3c58c71090121994a9f771ef96472669671718b55a0fa8d9f76de9e172fedcabbc87d64b5a994899e43abb19afa840269012c397b5b18d4babc0e41c1ad698db98c89121bbe5b2d227cfc5d3c3c87f4f4c8b04b509d326199b39adfbd8bca8bf0a150fcf3c37b9717382af502ad8d4d28b17b91762bf108d34aba0fb40ca410c2ecaeb30d68003af20dce27d9d034e4c557b8104e85f859de0eb709b23f9978869bae545c7f1b62173887eae9e75e4b6d6b4b01d7172ccc8c5774c0db51c24\"," +
                    "        \"encryptedValue\": \"2867e67545b2f3d0708500a1cea649e3\"," +
                    "        \"oaepHashingAlgorithm\": \"SHA256\"" +
                    "    }, " +
                    "    \"data\": \"string\"" +
                    "}";
                var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                    .WithDecryptionPath("encryptedData", "data")
                    .Build();

                // WHEN
                FieldLevelEncryption.DecryptPayload(encryptedPayload, config);
            }
            catch (Exception e)
            {
                // THEN
                Assert.IsTrue(e.InnerException is InvalidOperationException);
                Assert.AreEqual("JSON object expected at path: 'data'!", e.InnerException.Message);
                Assert.AreEqual("Payload decryption failed!", e.Message);
                throw;
            }
        }

        [TestMethod]
        [ExpectedException(typeof(EncryptionException))]
        public void TestDecryptPayload_ShouldThrowInvalidOperationException_WhenInPathIsPathToJsonPrimitive()
        {
            try
            {
                // GIVEN
                const string encryptedPayload = "{ \"encryptedData\": \"string\" }";
                var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                    .WithDecryptionPath("encryptedData", "data")
                    .Build();

                // WHEN
                FieldLevelEncryption.DecryptPayload(encryptedPayload, config);
            }
            catch (Exception e)
            {
                // THEN
                Assert.IsTrue(e.InnerException is InvalidOperationException);
                Assert.AreEqual("JSON object expected at path: 'encryptedData'!", e.InnerException.Message);
                Assert.AreEqual("Payload decryption failed!", e.Message);
                throw;
            }
        }

        [TestMethod]
        public void TestDecryptPayload_ShouldUseOaepDigestAlgorithmFromConfig_WhenOaepDigestAlgorithmNotReturnedInPayload()
        {
            // GIVEN
            const string encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"iv\": \"ba574b07248f63756bce778f8a115819\"," +
                "        \"encryptedKey\": \"26687f6d03d27145451d20bdaa29cc199e2533bb9eb7351772e31d1290b98380b43dbf47b9a337cc2ecaff9d3d9fb45305950f13382c5ad822ee6df79e1a57b14a3c58c71090121994a9f771ef96472669671718b55a0fa8d9f76de9e172fedcabbc87d64b5a994899e43abb19afa840269012c397b5b18d4babc0e41c1ad698db98c89121bbe5b2d227cfc5d3c3c87f4f4c8b04b509d326199b39adfbd8bca8bf0a150fcf3c37b9717382af502ad8d4d28b17b91762bf108d34aba0fb40ca410c2ecaeb30d68003af20dce27d9d034e4c557b8104e85f859de0eb709b23f9978869bae545c7f1b62173887eae9e75e4b6d6b4b01d7172ccc8c5774c0db51c24\"," +
                "        \"encryptedValue\": \"2867e67545b2f3d0708500a1cea649e3\"" +
                "    }" +
                "}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithDecryptionPath("encryptedData", "data")
                .Build();

            // WHEN
            var payload = FieldLevelEncryption.DecryptPayload(encryptedPayload, config);

            // THEN
            TestUtils.AssertPayloadEquals("{\"data\":{}}", payload);
        }

        [TestMethod]
        public void TestDecryptPayload_ShouldSupportMultipleDecryptions()
        {
            // GIVEN
            const string encryptedPayload = "{" +
                "    \"encryptedData2\": {" +
                "        \"iv\": \"c1ffb457798714b679e5b59e5b8fb62c\"," +
                "        \"encryptedKey\": \"f16425f1550c28515bc83e25f7f63ca8102a2cbbadd6452c610f03d920563856f1a7318d98bc0939a3a6a84922caebc3691b34aa96ed4d2d016727a30d3622966dec3cb13f9da9d149106afc2b81846e624aa6134551bca169fa539df4034b48e47923cb4f2636b993c805b851cc046a7e98a70ff1c6b43207ac8dcbfbf6132a070860040093d4399af70b0d45cf44854390df9c24f2eb17aa6e745da1a2b7a765f8b4970f6764731d6a7d51af85be669e35ad433ff0942710764265253c956797cd1e3c8ba705ee8578373a14bbab368426d3797bd68076f6ec9c4ef8d43c2959f4fd4c17897a9d6d0622ffc662d5f5c304fb6d5ca84de63f7cf9b9dfe700d2\"," +
                "        \"encryptedValue\": \"a49dff0a6f9ca58bdd3e991f13eb8e53\"" +
                "    }," +
                "    \"encryptedData1\": {" +
                "        \"iv\": \"4c278e7b0c0890973077960f682181b6\"," +
                "        \"encryptedKey\": \"c2c4a40433e91d1175ba933ddb7eb014e9839e3bf639c6c4e2ea532373f146ee6a88515103cb7aeb9df328c67b747c231bfdf4a6b3d366792b6e9ec0f106447f28518a864cc9dd59ed6e1a9ed017229166f23389b4c141b4492981e51ad6863ed48e8c93394378a8e8ab922b8c96dfdf6c683c334eef4c668d9f059b6ac6c26a7d623032ef0bac0e3d4fde5a735d4c09879364efb723c2f2bd3288f8619f9f1a63ed1e283ae7cb40726632fe271fea08252991a158bce3aeca90a4ce7b6895f7b94516ada042de80942ddbc3462baeee49c4169c18c0024fec48743610281cec0333906953da783b3bcd246226efccff4cdefa62c26753db228e0120feff2bdc\"," +
                "        \"encryptedValue\": \"1ea73031bc0cf9c67b61bc1684d78f2b\"" +
                "    }" +
                "}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithDecryptionPath("encryptedData1", "data1")
                .WithDecryptionPath("encryptedData2", "data2")
                .Build();

            // WHEN
            var payload = FieldLevelEncryption.DecryptPayload(encryptedPayload, config);

            // THEN
            var payloadObject = JObject.Parse(payload);
            Assert.IsNull(payloadObject["encryptedData1"]);
            Assert.IsNull(payloadObject["encryptedData2"]);
            Assert.IsNotNull(payloadObject["data1"]);
            Assert.IsNotNull(payloadObject["data2"]);
        }

        [TestMethod]
        public void TestDecryptPayload_ShouldMergeJsonObjects_WhenOutPathAlreadyContainData()
        {
            // GIVEN
            const string encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"iv\": \"17492f69d92d2008ee9289cf3e07bd36\"," +
                "        \"encryptedKey\": \"22b3df5e70777cef394c39ac74bacfcdbfc8cef4a4da771f1d07611f18b4dc9eacde7297870acb421abe77b8b974f53b2e5b834a68e11a4ddab53ece2d37ae7dee5646dc3f4c5c17166906258615b9c7c52f7242a1afa6edf24815c3dbec4b2092a027de11bcdab4c47de0159ce76d2449394f962a07196a5a5b41678a085d77730baee0d3d0e486eb4719aae8f1f1c0fd7026aea7b0872c049e8df1e7eed088fa84fc613602e989fa4e7a7b77ac40da212a462ae5d3df5078be96fcf3d0fe612e0ec401d27a243c0df1feb8241d49248697db5ec79571b9d52386064ee3db11d200156bfd3af03a289ea37ec2c8f315840e7804669a855bf9e34190e3b14d28\"," +
                "        \"encryptedValue\": \"9cad34c0d7b2443f07bb7b7e19817ade132ba3f312b1176c09a312e5b5f908198e1e0cfac0fd8c9f66c70a9b05b1a701\"," +
                "        \"oaepHashingAlgorithm\": \"SHA256\"" +
                "    }, " +
                "    \"data\": {" +
                "        \"field1\": \"previousField1Value\"," +
                "        \"field3\": \"field3Value\"" +
                "    }" +
                "}";

            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithDecryptionPath("encryptedData", "data")
                .Build();

            // WHEN
            var payload = FieldLevelEncryption.DecryptPayload(encryptedPayload, config);

            // THEN
            var payloadObject = JObject.Parse(payload);
            Assert.IsNull(payloadObject["encryptedData"]);
            var dataObject = payloadObject["data"];
            Assert.IsNotNull(dataObject);
            Assert.AreEqual("field1Value", dataObject["field1"].ToString());
            Assert.AreEqual("field2Value", dataObject["field2"].ToString());
            Assert.AreEqual("field3Value", dataObject["field3"].ToString());
        }
        
        [TestMethod]
        public void TestDecryptPayload_ShouldKeepInputObject_WhenContainsAdditionalFields()
        {
            // GIVEN
            const string encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"iv\": \"ba574b07248f63756bce778f8a115819\"," +
                "        \"encryptedKey\": \"26687f6d03d27145451d20bdaa29cc199e2533bb9eb7351772e31d1290b98380b43dbf47b9a337cc2ecaff9d3d9fb45305950f13382c5ad822ee6df79e1a57b14a3c58c71090121994a9f771ef96472669671718b55a0fa8d9f76de9e172fedcabbc87d64b5a994899e43abb19afa840269012c397b5b18d4babc0e41c1ad698db98c89121bbe5b2d227cfc5d3c3c87f4f4c8b04b509d326199b39adfbd8bca8bf0a150fcf3c37b9717382af502ad8d4d28b17b91762bf108d34aba0fb40ca410c2ecaeb30d68003af20dce27d9d034e4c557b8104e85f859de0eb709b23f9978869bae545c7f1b62173887eae9e75e4b6d6b4b01d7172ccc8c5774c0db51c24\"," +
                "        \"encryptedValue\": \"2867e67545b2f3d0708500a1cea649e3\"," +
                "        \"oaepHashingAlgorithm\": \"SHA256\"," +
                "        \"field\": \"fieldValue\"" +
                "    }" +
                "}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithDecryptionPath("encryptedData", "data")
                .Build();

            // WHEN
            var payload = FieldLevelEncryption.DecryptPayload(encryptedPayload, config);

            // THEN
            var payloadObject = JObject.Parse(payload);
            Assert.AreEqual("fieldValue", payloadObject["encryptedData"]["field"]);
        }

        [TestMethod]
        public void TestDecryptPayload_ShouldOverwriteInputObject_WhenOutPathSameAsInPath_ObjectData()
        {
            // GIVEN
            const string encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"iv\": \"17492f69d92d2008ee9289cf3e07bd36\"," +
                "        \"encryptedKey\": \"22b3df5e70777cef394c39ac74bacfcdbfc8cef4a4da771f1d07611f18b4dc9eacde7297870acb421abe77b8b974f53b2e5b834a68e11a4ddab53ece2d37ae7dee5646dc3f4c5c17166906258615b9c7c52f7242a1afa6edf24815c3dbec4b2092a027de11bcdab4c47de0159ce76d2449394f962a07196a5a5b41678a085d77730baee0d3d0e486eb4719aae8f1f1c0fd7026aea7b0872c049e8df1e7eed088fa84fc613602e989fa4e7a7b77ac40da212a462ae5d3df5078be96fcf3d0fe612e0ec401d27a243c0df1feb8241d49248697db5ec79571b9d52386064ee3db11d200156bfd3af03a289ea37ec2c8f315840e7804669a855bf9e34190e3b14d28\"," +
                "        \"encryptedValue\": \"9cad34c0d7b2443f07bb7b7e19817ade132ba3f312b1176c09a312e5b5f908198e1e0cfac0fd8c9f66c70a9b05b1a701\"," +
                "        \"oaepHashingAlgorithm\": \"SHA256\"" +
                "    } " +
                "}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithDecryptionPath("encryptedData", "encryptedData")
                .WithOaepPaddingDigestAlgorithm("SHA-256")
                .Build();

            // WHEN
            var payload = FieldLevelEncryption.DecryptPayload(encryptedPayload, config);

            // THEN
            var payloadObject = JObject.Parse(payload);
            Assert.AreEqual("field1Value", payloadObject["encryptedData"]["field1"]);
            Assert.AreEqual("field2Value", payloadObject["encryptedData"]["field2"]);
        }

        [TestMethod]
        public void TestDecryptPayload_ShouldOverwriteInputObject_WhenOutPathSameAsInPath_PrimitiveTypeData()
        {
            // GIVEN
            const string encryptedPayload = "{" +
                "    \"data\": {" +
                "        \"iv\": \"3ce861359fa1630c7a794901ee14bf41\"," +
                "        \"encryptedKey\": \"02bb8d5c7d113ef271f199c09f0d76db2b6d5d2d209ad1a20dbc4dd0d04576a92ceb917eea5f403ccf64c3c39dda564046909af96c82fad62f89c3cbbec880ea3105a0a171af904cd3b86ea68991202a2795dca07050ca58252701b7ecea06055fd43e96f4beee48b6275e86af93c88c21994ff46f0610171bd388a2c0a1f518ffc8346f7f513f3283feae5b102c8596ddcb2aea5e62ceb17222e646c599f258463405d28ac012bfd4cc431f94111ee07d79e660948485e38c13cdb8bba8e1df3f7dba0f4c77696f71930533c955f3a430658edaa03b0b0c393934d60f5ac3ea5c06ed64bf969fc01942eac432b8e0c56f7538659a72859d445d150c169ae690\"," +
                "        \"encryptedValue\": \"e2d6a3a76ea6e605e55b400e5a4eba11\"," +
                "        \"oaepHashingAlgorithm\": \"SHA256\"" +
                "    } " +
                "}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithDecryptionPath("$.data", "$.data")
                .Build();

            // WHEN
            var payload = FieldLevelEncryption.DecryptPayload(encryptedPayload, config);

            // THEN
            var payloadObject = JObject.Parse(payload);
            Assert.AreEqual("string", payloadObject["data"]);
        }

        [TestMethod]
        public void TestDecryptPayload_ShouldSupportRootAsInputPath()
        {
            // GIVEN
            const string encryptedPayload = "{" +
                "    \"iv\": \"6fef040c8fe8ad9ec56b74efa194b5f7\"," +
                "    \"encryptedKey\": \"b04c69e1ca944fd7641ea79f03e5cd540144759212fa50d07c8a97ab30ca8bded324e2d4b8cd2613b25cd6bceac35b76c2fa1b521ff205b5f33eafaf4102efbefd35cae6707f985953d6dac366cca36295b29d8af3d94d5d5d1532158066b9fecfc2cc000f10e4757967e84c043d7db164d7488f5bef28f59c989c4cd316c870da7b7c1d10cfd73b6d285cd43447e9e96702e3e818011b45b0ecda21b02286db04b7c77ab193dcc4a9036beff065a404689b7cea40b6a348554900ae3eb819af9cb53ab800e158051aac8d8075045a06808e3730cd8cbc1b5334dcdc922d0227f6da1518442914ac5f3abf6751dfb5721074459d0626b62e934f6a6e6fd96020\"," +
                "    \"encryptedValue\": \"386cdb354a33a5b5ae44fa73622297d0372857d1f7634b45010f691964958e2afca0f7391742dc1243768ccf0b4fce8b\"," +
                "    \"encryptionCertificateFingerprint\": \"80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279\"," +
                "    \"encryptionKeyFingerprint\": \"761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79\"," +
                "    \"oaepHashingAlgorithm\": \"SHA256\"" +
                "}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithDecryptionPath("$", "$.encryptedData")
                .Build();

            // WHEN
            var payload = FieldLevelEncryption.DecryptPayload(encryptedPayload, config);

            // THEN
            var payloadObject = JObject.Parse(payload);
            Assert.IsNull(payloadObject["iv"]);
            Assert.IsNull(payloadObject["encryptedKey"]);
            Assert.IsNull(payloadObject["encryptedValue"]);
            Assert.IsNull(payloadObject["oaepHashingAlgorithm"]);
            Assert.IsNull(payloadObject["encryptionCertificateFingerprint"]);
            Assert.IsNull(payloadObject["encryptionKeyFingerprint"]);
            Assert.AreEqual("value1", payloadObject["encryptedData"]["field1"]);
            Assert.AreEqual("value2", payloadObject["encryptedData"]["field2"]);
        }

        [TestMethod]
        public void TestDecryptPayload_ShouldSupportRootAsInputPathAndOutputPath()
        {
            // GIVEN
            const string encryptedPayload = "{" +
                "    \"iv\": \"6fef040c8fe8ad9ec56b74efa194b5f7\"," +
                "    \"encryptedKey\": \"b04c69e1ca944fd7641ea79f03e5cd540144759212fa50d07c8a97ab30ca8bded324e2d4b8cd2613b25cd6bceac35b76c2fa1b521ff205b5f33eafaf4102efbefd35cae6707f985953d6dac366cca36295b29d8af3d94d5d5d1532158066b9fecfc2cc000f10e4757967e84c043d7db164d7488f5bef28f59c989c4cd316c870da7b7c1d10cfd73b6d285cd43447e9e96702e3e818011b45b0ecda21b02286db04b7c77ab193dcc4a9036beff065a404689b7cea40b6a348554900ae3eb819af9cb53ab800e158051aac8d8075045a06808e3730cd8cbc1b5334dcdc922d0227f6da1518442914ac5f3abf6751dfb5721074459d0626b62e934f6a6e6fd96020\"," +
                "    \"encryptedValue\": \"386cdb354a33a5b5ae44fa73622297d0372857d1f7634b45010f691964958e2afca0f7391742dc1243768ccf0b4fce8b\"," +
                "    \"encryptionCertificateFingerprint\": \"80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279\"," +
                "    \"encryptionKeyFingerprint\": \"761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79\"," +
                "    \"oaepHashingAlgorithm\": \"SHA256\"" +
                "}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithDecryptionPath("$", "$")
                .Build();

            // WHEN
            var payload = FieldLevelEncryption.DecryptPayload(encryptedPayload, config);

            // THEN
            TestUtils.AssertPayloadEquals("{\"field1\":\"value1\",\"field2\":\"value2\"}", payload);
        }

        [TestMethod]
        public void TestDecryptPayload_ShouldSupportRootAsOutputPath()
        {
            // GIVEN
            const string encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"iv\": \"6fef040c8fe8ad9ec56b74efa194b5f7\"," +
                "        \"encryptedKey\": \"b04c69e1ca944fd7641ea79f03e5cd540144759212fa50d07c8a97ab30ca8bded324e2d4b8cd2613b25cd6bceac35b76c2fa1b521ff205b5f33eafaf4102efbefd35cae6707f985953d6dac366cca36295b29d8af3d94d5d5d1532158066b9fecfc2cc000f10e4757967e84c043d7db164d7488f5bef28f59c989c4cd316c870da7b7c1d10cfd73b6d285cd43447e9e96702e3e818011b45b0ecda21b02286db04b7c77ab193dcc4a9036beff065a404689b7cea40b6a348554900ae3eb819af9cb53ab800e158051aac8d8075045a06808e3730cd8cbc1b5334dcdc922d0227f6da1518442914ac5f3abf6751dfb5721074459d0626b62e934f6a6e6fd96020\"," +
                "        \"encryptedValue\": \"386cdb354a33a5b5ae44fa73622297d0372857d1f7634b45010f691964958e2afca0f7391742dc1243768ccf0b4fce8b\"," +
                "        \"encryptionCertificateFingerprint\": \"80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279\"," +
                "        \"encryptionKeyFingerprint\": \"761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79\"," +
                "        \"oaepHashingAlgorithm\": \"SHA256\"" +
                "   }" +
                "}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithDecryptionPath("$.encryptedData", "$")
                .Build();

            // WHEN
            var payload = FieldLevelEncryption.DecryptPayload(encryptedPayload, config);

            // THEN
            TestUtils.AssertPayloadEquals("{\"field1\":\"value1\",\"field2\":\"value2\"}", payload);
        }

        [TestMethod]
        [ExpectedException(typeof(EncryptionException))]
        public void TestDecryptPayload_ShouldThrowEncryptionException_WhenDecryptionErrorOccurs()
        {
            try
            {
                // GIVEN
                const string encryptedPayload = "{" +
                    "    \"encryptedData\": {" +
                    "        \"iv\": \"ba574b07248f63756bce778f8a115819\"," +
                    "        \"encryptedKey\": \"26687f6d03d27145451d20bdaa29cc199e2533bb9eb7351772e31d1290b98380b43dbf47b9a337cc2ecaff9d3d9fb45305950f13382c5ad822ee6df79e1a57b14a3c58c71090121994a9f771ef96472669671718b55a0fa8d9f76de9e172fedcabbc87d64b5a994899e43abb19afa840269012c397b5b18d4babc0e41c1ad698db98c89121bbe5b2d227cfc5d3c3c87f4f4c8b04b509d326199b39adfbd8bca8bf0a150fcf3c37b9717382af502ad8d4d28b17b91762bf108d34aba0fb40ca410c2ecaeb30d68003af20dce27d9d034e4c557b8104e85f859de0eb709b23f9978869bae545c7f1b62173887eae9e75e4b6d6b4b01d7172ccc8c5774c0db51c24\"," +
                    "        \"encryptedValue\": \"2867e67545b2f3d0708500a1cea649e3\"" +
                    "    }" +
                    "}";
                var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                    .WithDecryptionPath("encryptedData", "data")
                    .WithOaepPaddingDigestAlgorithm("SHA-256")
                    // Not the right key
                    .WithDecryptionKey(EncryptionUtils.LoadDecryptionKey("./_Resources/Keys/Pkcs12/test_key.p12", "mykeyalias", "Password1", MachineKeySet | Exportable)) // https://github.com/dotnet/corefx/issues/14745
                    .Build();

                // WHEN
                FieldLevelEncryption.DecryptPayload(encryptedPayload, config);
            }
            catch (Exception e)
            {
                // THEN
                Assert.AreEqual("Failed to decode and unwrap the provided secret key value!", e.Message);
                throw;
            }
        }

        [TestMethod]
        public void TestDecryptPayload_ShouldKeepCertificateAndKeyFingerprints_WhenFieldNamesNotSetInConfig()
        {
            // GIVEN
            const string encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"iv\": \"ba574b07248f63756bce778f8a115819\"," +
                "        \"encryptedKey\": \"26687f6d03d27145451d20bdaa29cc199e2533bb9eb7351772e31d1290b98380b43dbf47b9a337cc2ecaff9d3d9fb45305950f13382c5ad822ee6df79e1a57b14a3c58c71090121994a9f771ef96472669671718b55a0fa8d9f76de9e172fedcabbc87d64b5a994899e43abb19afa840269012c397b5b18d4babc0e41c1ad698db98c89121bbe5b2d227cfc5d3c3c87f4f4c8b04b509d326199b39adfbd8bca8bf0a150fcf3c37b9717382af502ad8d4d28b17b91762bf108d34aba0fb40ca410c2ecaeb30d68003af20dce27d9d034e4c557b8104e85f859de0eb709b23f9978869bae545c7f1b62173887eae9e75e4b6d6b4b01d7172ccc8c5774c0db51c24\"," +
                "        \"encryptedValue\": \"2867e67545b2f3d0708500a1cea649e3\"," +
                "        \"encryptionCertificateFingerprint\": \"80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279\"," +
                "        \"encryptionKeyFingerprint\": \"761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79\"," +
                "        \"oaepHashingAlgorithm\": \"SHA256\"" +
                "    }" +
                "}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithDecryptionPath("encryptedData", "data")
                .WithEncryptionCertificateFingerprintFieldName(null)
                .WithEncryptionKeyFingerprintFieldName(null)
                .Build();

            // WHEN
            var payload = FieldLevelEncryption.DecryptPayload(encryptedPayload, config);

            // THEN
            var payloadObject = JObject.Parse(payload);
            var encryptedDataObject = payloadObject["encryptedData"];
            Assert.IsNotNull(encryptedDataObject);
            Assert.IsNotNull(encryptedDataObject["encryptionCertificateFingerprint"]);
            Assert.IsNotNull(encryptedDataObject["encryptionKeyFingerprint"]);
            Assert.AreEqual("{}", payloadObject["data"].ToString());
        }

        [TestMethod]
        public void TestDecryptPayload_ShouldUseProvidedEncryptionParams_WhenPassedAsArgument()
        {
            // GIVEN
            const string encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"encryptedValue\": \"2867e67545b2f3d0708500a1cea649e3\"" +
                "    }" +
                "}";
            var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                .WithDecryptionPath("encryptedData", "data")
                .Build();

            const string ivValue = "ba574b07248f63756bce778f8a115819";
            const string encryptedKeyValue = "26687f6d03d27145451d20bdaa29cc199e2533bb9eb7351772e31d1290b98380b43dbf47b9a337cc2ecaff9d3d9fb45305950f13382c5ad822ee6df79e1a57b14a3c58c71090121994a9f771ef96472669671718b55a0fa8d9f76de9e172fedcabbc87d64b5a994899e43abb19afa840269012c397b5b18d4babc0e41c1ad698db98c89121bbe5b2d227cfc5d3c3c87f4f4c8b04b509d326199b39adfbd8bca8bf0a150fcf3c37b9717382af502ad8d4d28b17b91762bf108d34aba0fb40ca410c2ecaeb30d68003af20dce27d9d034e4c557b8104e85f859de0eb709b23f9978869bae545c7f1b62173887eae9e75e4b6d6b4b01d7172ccc8c5774c0db51c24";
            const string oaepHashingAlgorithmValue = "SHA256";
            var parameters = new FieldLevelEncryptionParams(config, ivValue, encryptedKeyValue, oaepHashingAlgorithmValue);

            // WHEN
            var payload = FieldLevelEncryption.DecryptPayload(encryptedPayload, config, parameters);

            // THEN
            TestUtils.AssertPayloadEquals("{\"data\":{}}", payload);
        }
        
        [TestMethod]
        [ExpectedException(typeof(EncryptionException))]
        public void TestDecryptPayload_ShouldThrowInvalidOperationException_WhenEncryptionParamsAreMissing()
        {
            try {
                // GIVEN
                const string encryptedPayload = "{" +
                    "    \"encryptedData\": {" +
                    "        \"encryptedValue\": \"2867e67545b2f3d0708500a1cea649e3\"" +
                    "    }" +
                    "}";
                var config = TestUtils.GetTestFieldLevelEncryptionConfigBuilder()
                    .WithDecryptionPath("encryptedData", "data")
                    .WithEncryptedKeyFieldName(null)
                    .WithEncryptedKeyHeaderName("x-encrypted-key")
                    .WithIvFieldName(null)
                    .WithIvHeaderName("x-iv")
                    .Build();

                // WHEN
                FieldLevelEncryption.DecryptPayload(encryptedPayload, config);
            }
            catch (Exception e)
            {
                // THEN
                Assert.IsTrue(e.InnerException is InvalidOperationException);
                Assert.AreEqual("Encryption params have to be set when not stored in HTTP payloads!", e.InnerException.Message);
                Assert.AreEqual("Payload decryption failed!", e.Message);
                throw;
            }
        }
    }
}
