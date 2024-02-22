using System;
using Newtonsoft.Json.Linq;
using System.Text.RegularExpressions;
using Newtonsoft.Json;

namespace Mastercard.Developer.ClientEncryption.Core.Utils
{
    internal static class JsonUtils
    {
        private static readonly Regex LastElementInPathRegExp = new Regex(".*(\\['.*'\\])"); // Returns "['obj2']" for "$['obj1']['obj2']"
        
        /// <summary>
        /// Get JSON path to the parent of the object at the given JSON path.
        /// </summary>
        internal static string GetParentJsonPath(string jsonPath)
        {
            if (string.IsNullOrEmpty(jsonPath)) throw new ArgumentException(nameof(jsonPath));

            if ("$".Equals(jsonPath))
            {
                throw new InvalidOperationException($"Unable to find parent for '{jsonPath}'");
            }

            // "$.['path'].['to'].['object']"?
            var match = LastElementInPathRegExp.Match(jsonPath);
            if (match.Success)
            {
                return jsonPath.Replace(match.Groups[match.Groups.Count - 1].Value, string.Empty);
            }

            // "$.path.to.object"?
            var lastIndexOfDot = jsonPath.LastIndexOf(".", StringComparison.Ordinal);
            if (lastIndexOfDot != -1)
            {
                return jsonPath.Substring(0, lastIndexOfDot);
            }

            // "object"
            return "$";
        }

        /// <summary>
        /// Get object key at the given JSON path.
        /// </summary>
        internal static string GetJsonElementKey(string jsonPath)
        {
            if (string.IsNullOrEmpty(jsonPath)) throw new ArgumentException(nameof(jsonPath));

            if ("$".Equals(jsonPath))
            {
                throw new InvalidOperationException($"Unable to find object key for '{jsonPath}'");
            }

            // "$.['path'].['to'].['object']"?
            var match = LastElementInPathRegExp.Match(jsonPath);
            if (match.Success)
            {
                return match.Groups[match.Groups.Count - 1].Value.Replace("['", "").Replace("']", "");
            }

            // "$.path.to.object"?
            var lastIndexOfDot = jsonPath.LastIndexOf(".", StringComparison.Ordinal);
            if (lastIndexOfDot != -1)
            {
                return jsonPath.Substring(lastIndexOfDot + 1, jsonPath.Length - lastIndexOfDot - 1);
            }

            // "object"
            return jsonPath;
        }

        /// <summary>
        /// Checks if a JSON path points to a single item or if it potentially returns multiple items.
        /// See: https://github.com/json-path/JsonPath
        /// </summary>
        internal static bool IsPathDefinite(string path)
        {
            return !path.Contains("*") && !path.Contains("..") && !path.Contains("@") && !path.Contains(",");
        }
        /// <summary>
        /// Parses the Json payload with specified parameters
        /// </summary>
        /// <returns>payloadToken</returns>
        internal static JToken ParsePayload(string payload)
        {
            var jsonReader = new JsonTextReader(new System.IO.StringReader(payload)) {
                    DateParseHandling = DateParseHandling.None 
                };
                
            return JToken.ReadFrom(jsonReader);
        }

        internal static void CheckOrCreateOutObject(JToken payloadObject, string jsonPathOut)
        {
            var outJsonToken = payloadObject.SelectToken(jsonPathOut);
            if (null != outJsonToken)
            {
                // Object already exists
                AssertIsObject(outJsonToken, jsonPathOut);
                return;
            }

            // Path does not exist: if parent exists then we create a new object under the parent
            var parentJsonPath = GetParentJsonPath(jsonPathOut);
            var parentJsonObject = payloadObject.SelectToken(parentJsonPath);
            if (parentJsonObject == null)
            {
                throw new InvalidOperationException($"Parent path not found in payload: '{parentJsonPath}'!");
            }
            var elementKey = JsonUtils.GetJsonElementKey(jsonPathOut);
            (parentJsonObject as JObject)?.Add(elementKey, new JObject());
        }

        internal static void AssertIsObject(JToken jToken, string jsonPath)
        {
            if (!(jToken is JObject))
            {
                throw new InvalidOperationException($"JSON object expected at path: '{jsonPath}'!");
            }
        }

        internal static string SanitizeJson(string json)
        {
            return json.Replace("\n", string.Empty)
                .Replace("\r", string.Empty)
                .Replace("\t", string.Empty)
                .Replace(Environment.NewLine, string.Empty);
        }

        internal static void AddOrReplaceJsonKey(JObject jsonObject, string key, JToken value)
        {
            jsonObject.Remove(key);
            jsonObject.Add(key, value);
        }

        internal static bool IsNullOrEmptyJson(JToken token)
        {
            if (token == null)
            {
                return true;
            }
            switch (token.Type)
            {
                case JTokenType.Array:
                case JTokenType.Object:
                    return !token.HasValues;

                case JTokenType.String:
                    return token.ToString() == String.Empty;

                case JTokenType.Null:
                    return true;
            }
            return false;
        }

        internal static void AddDecryptedDataToPayload(JToken payloadObject, string decryptedValue, string jsonPathOut)
        {
            try
            {
                // Object?
                var decryptedValueObject = JObject.Parse(decryptedValue);
                var outJsonObject = payloadObject.SelectToken(jsonPathOut) as JObject;
                outJsonObject?.Merge(decryptedValueObject); // Merge the two objects
            }
            catch
            {
                try
                {
                    // Array?
                    var decryptedValueObject = JArray.Parse(decryptedValue);
                    payloadObject.SelectToken(jsonPathOut).Replace(decryptedValueObject);
                }
                catch
                {
                    // Primitive type
                    payloadObject.SelectToken(jsonPathOut).Replace(AsPrimitiveValue(decryptedValue));
                }
            }
        }

        private static JToken AsPrimitiveValue(string value)
        {
            // Boolean?
            if ("true".Equals(value.ToLower()) || "false".Equals(value.ToLower()))
            {
                return bool.Parse(value);
            }

            // Numeric?
            try
            {
                return long.Parse(value);
            }
            catch
            {
                // Not a number, do nothing
            }

            // String
            return value;
        }
    }
}
