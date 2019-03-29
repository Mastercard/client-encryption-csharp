using System;
using System.Text.RegularExpressions;

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
                throw new InvalidOperationException("Unable to find parent for '" + jsonPath + "'");
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
                throw new InvalidOperationException("Unable to find object key for '" + jsonPath + "'");
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
    }
}
