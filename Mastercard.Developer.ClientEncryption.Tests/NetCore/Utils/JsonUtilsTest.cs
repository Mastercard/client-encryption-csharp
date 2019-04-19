using System;
using Mastercard.Developer.ClientEncryption.Core.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Mastercard.Developer.ClientEncryption.Tests.Utils
{
    [TestClass]
    public class JsonUtilsTest
    {
        [TestMethod]
        public void TestGetParentJsonPath_Nominal()
        {
            // GIVEN
            const string jsonPath1 = "$['obj1']['obj2']['obj3']";
            const string jsonPath2 = "obj1.obj2";
            const string jsonPath3 = "$.obj1.obj2";
            const string jsonPath4 = "obj1";

            // WHEN
            var parentJsonPath1 = JsonUtils.GetParentJsonPath(jsonPath1);
            var parentJsonPath2 = JsonUtils.GetParentJsonPath(jsonPath2);
            var parentJsonPath3 = JsonUtils.GetParentJsonPath(jsonPath3);
            var parentJsonPath4 = JsonUtils.GetParentJsonPath(jsonPath4);

            // THEN
            Assert.AreEqual("$['obj1']['obj2']", parentJsonPath1);
            Assert.AreEqual("obj1", parentJsonPath2);
            Assert.AreEqual("$.obj1", parentJsonPath3);
            Assert.AreEqual("$", parentJsonPath4);
        }

        [TestMethod]
        public void TestGetJsonElementKey_Nominal()
        {
            // GIVEN
            const string jsonPath1 = "$['obj0']['obj1']['obj2']";
            const string jsonPath2 = "obj1.obj2";
            const string jsonPath3 = "$.obj1.obj2";
            const string jsonPath4 = "obj2";

            // WHEN
            var jsonElementKey1 = JsonUtils.GetJsonElementKey(jsonPath1);
            var jsonElementKey2 = JsonUtils.GetJsonElementKey(jsonPath2);
            var jsonElementKey3 = JsonUtils.GetJsonElementKey(jsonPath3);
            var jsonElementKey4 = JsonUtils.GetJsonElementKey(jsonPath4);

            // THEN
            Assert.AreEqual("obj2", jsonElementKey1);
            Assert.AreEqual("obj2", jsonElementKey2);
            Assert.AreEqual("obj2", jsonElementKey3);
            Assert.AreEqual("obj2", jsonElementKey4);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))] // THEN
        public void TestGetParentJsonPath_ShouldThrowArgumentException_WhenJsonPathNullOrEmpty()
        {
            try
            {
                // GIVEN
                const string jsonPath = "";

                // WHEN
                JsonUtils.GetParentJsonPath(jsonPath);
            }
            catch (Exception e)
            {
                // THEN
                Assert.AreEqual("jsonPath", e.Message);
                throw;
            }
            
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))] // THEN
        public void TestGetJsonElementKey_ShouldThrowArgumentException_WhenJsonPathNullOrEmpty()
        {
            try
            {
                // GIVEN
                const string jsonPath = "";

                // WHEN
                JsonUtils.GetJsonElementKey(jsonPath);
            }
            catch (Exception e)
            {
                // THEN
                Assert.AreEqual("jsonPath", e.Message);
                throw;
            }
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))] // THEN
        public void TestGetParentJsonPath_ShouldThrowInvalidOperationException_WhenNoParent()
        {
            try
            {
                // GIVEN
                const string jsonPath = "$";

                // WHEN
                JsonUtils.GetParentJsonPath(jsonPath);
            }
            catch (Exception e)
            {
                // THEN
                Assert.AreEqual("Unable to find parent for '$'", e.Message);
                throw;
            }
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))] // THEN
        public void TestGetJsonElementKey_ShouldThrowInvalidOperationException_WhenNoKey()
        {
            try
            {
                // GIVEN
                const string jsonPath = "$";

                // WHEN
                JsonUtils.GetJsonElementKey(jsonPath);
            }
            catch (Exception e)
            {
                // THEN
                Assert.AreEqual("Unable to find object key for '$'", e.Message);
                throw;
            }
        }
    }
}
