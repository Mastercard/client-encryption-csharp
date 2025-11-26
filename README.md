# client-encryption-csharp
[![](https://developer.mastercard.com/_/_/src/global/assets/svg/mcdev-logo-dark.svg)](https://developer.mastercard.com/)

[![](https://github.com/Mastercard/client-encryption-csharp/workflows/Build%20&%20Test/badge.svg)](https://github.com/Mastercard/client-encryption-csharp/actions?query=workflow%3A%22Build+%26+Test%22)
[![](https://github.com/Mastercard/client-encryption-csharp/workflows/Sonar/badge.svg)](https://github.com/Mastercard/client-encryption-csharp/actions?query=workflow%3ASonar)
[![](https://github.com/Mastercard/client-encryption-csharp/workflows/broken%20links%3F/badge.svg)](https://github.com/Mastercard/client-encryption-csharp/actions?query=workflow%3A%22broken+links%3F%22)
[![](https://img.shields.io/nuget/v/Mastercard.Developer.ClientEncryption.Core.svg?label=nuget%20|%20core)](https://www.nuget.org/packages/Mastercard.Developer.ClientEncryption.Core/)
[![](https://img.shields.io/nuget/v/Mastercard.Developer.ClientEncryption.RestSharp.svg?label=nuget%20|%20restsharp%20portable)](https://www.nuget.org/packages/Mastercard.Developer.ClientEncryption.RestSharp/)
[![](https://img.shields.io/nuget/v/Mastercard.Developer.ClientEncryption.RestSharpV2.svg?label=nuget%20|%20restsharp)](https://www.nuget.org/packages/Mastercard.Developer.ClientEncryption.RestSharpV2/)
[![](https://img.shields.io/badge/license-MIT-yellow.svg)](https://github.com/Mastercard/client-encryption-csharp/blob/main/LICENSE)

## Table of Contents
- [Overview](#overview)
  * [Compatibility](#compatibility)
  * [References](#references)
  * [Versioning and Deprecation Policy](#versioning)
- [Usage](#usage)
  * [Prerequisites](#prerequisites)
  * [Adding the Libraries to Your Project](#adding-the-libraries-to-your-project)
  * [Loading the Encryption Certificate](#loading-the-encryption-certificate) 
  * [Loading the Decryption Key](#loading-the-decryption-key)
  * [Performing Payload Encryption and Decryption](#performing-payload-encryption-and-decryption)
    * [Introduction](#introduction)
    * [JWE Encryption and Decryption](#jwe-encryption-and-decryption)
    * [Mastercard Encryption and Decryption](#mastercard-encryption-and-decryption)
  * [Integrating with OpenAPI Generator API Client Libraries](#integrating-with-openapi-generator-api-client-libraries)

## Overview <a name="overview"></a>
* [`ClientEncryption.Core`](https://www.nuget.org/packages/Mastercard.Developer.ClientEncryption.Core/) is a zero dependency library for Mastercard API compliant payload encryption/decryption
* [`ClientEncryption.RestSharpV2`](https://www.nuget.org/packages/Mastercard.Developer.ClientEncryption.RestSharpV2/) is an extension dedicated to [RestSharp](https://restsharp.dev/)
* [`ClientEncryption.RestSharp`](https://www.nuget.org/packages/Mastercard.Developer.ClientEncryption.RestSharp) is an extension dedicated to [RestSharp Portable](https://github.com/FubarDevelopment/restsharp.portable) (project no longer maintained)

### Compatibility <a name="compatibility"></a>

#### .NET <a name="net"></a>
* `ClientEncryption.Core` targets .NET Standard 2.1
* `ClientEncryption.RestSharpV2` targets .NET Standard 2.1
* `ClientEncryption.RestSharp` targets .NET Standard 2.1

.NET Standard versions supported by .NET implementations can be found in the following articles: [.NET Standard](https://docs.microsoft.com/en-us/dotnet/standard/net-standard), [.NET Standard versions](https://dotnet.microsoft.com/en-us/platform/dotnet-standard#versions).

#### Strong Naming <a name="strong-naming"></a>
Assemblies are strong-named as per [Strong naming and .NET libraries](https://docs.microsoft.com/en-us/dotnet/standard/library-guidance/strong-naming).
The SN key is available here: [`Identity.snk`](https://github.com/Mastercard/client-encryption-csharp/blob/main/Identity.snk).

### References <a name="references"></a>
* [JSON Web Encryption (JWE)](https://datatracker.ietf.org/doc/html/rfc7516)
* [Securing Sensitive Data Using Payload Encryption](https://developer.mastercard.com/platform/documentation/security-and-authentication/securing-sensitive-data-using-payload-encryption/)

### Versioning and Deprecation Policy <a name="versioning"></a>
* [Mastercard Versioning and Deprecation Policy](https://github.com/Mastercard/.github/blob/main/CLIENT_LIBRARY_DEPRECATION_POLICY.md)

## Usage <a name="usage"></a>
### Prerequisites <a name="prerequisites"></a>
Before using this library, you will need to set up a project in the [Mastercard Developers Portal](https://developer.mastercard.com). 

As part of this set up, you'll receive:
* A public request encryption certificate (aka _Client Encryption Keys_)
* A private response decryption key (aka _Mastercard Encryption Keys_)

### Adding the Libraries to Your Project <a name="adding-the-libraries-to-your-project"></a>

#### Package Manager
```shell
Install-Package Mastercard.Developer.ClientEncryption.{Core|RestSharp|RestSharpV2}
```

#### .NET CLI
```shell
dotnet add package Mastercard.Developer.ClientEncryption.{Core|RestSharp|RestSharpV2}
```

### Loading the Encryption Certificate <a name="loading-the-encryption-certificate"></a>

A `System.Security.Cryptography.X509Certificates.X509Certificate` object can be created from a file by calling `EncryptionUtils.LoadEncryptionCertificate`:
```cs
var encryptionCertificate = EncryptionUtils.LoadEncryptionCertificate("<insert certificate file path>");
```

Supported certificate formats: PEM, DER.

### Loading the Decryption Key <a name="loading-the-decryption-key"></a>

#### From a PKCS#12 Key Store

A `System.Security.Cryptography.RSA` object can be created from a PKCS#12 key store by calling `EncryptionUtils.LoadDecryptionKey` the following way:
```cs
var decryptionKey = EncryptionUtils.LoadDecryptionKey(
                                    "<insert PKCS#12 key file path>", 
                                    "<insert key alias>", 
                                    "<insert key password>");
```

#### From an Unencrypted Key File

A `System.Security.Cryptography.RSA` object can be created from an unencrypted key file by calling `EncryptionUtils.LoadDecryptionKey` the following way:
```cs
var decryptionKey = EncryptionUtils.LoadDecryptionKey("<insert key file path>");
```

Supported RSA key formats:
* PKCS#1 PEM (starts with "-----BEGIN RSA PRIVATE KEY-----")
* PKCS#8 PEM (starts with "-----BEGIN PRIVATE KEY-----")
* Binary DER-encoded PKCS#8

### Performing Payload Encryption and Decryption <a name="performing-payload-encryption-and-decryption"></a>

+ [Introduction](#introduction)
+ [JWE Encryption and Decryption](#jwe-encryption-and-decryption)
+ [Mastercard Encryption and Decryption](#mastercard-encryption-and-decryption)

#### Introduction <a name="introduction"></a>

This library supports two types of encryption/decryption, both of which support field level and entire payload encryption: JWE encryption and what the library refers to as Field Level Encryption (Mastercard encryption), a scheme used by many services hosted on Mastercard Developers before the library added support for JWE.

#### JWE Encryption and Decryption <a name="jwe-encryption-and-decryption"></a>

+ [Introduction](#jwe-introduction)
+ [Configuring the JWE Encryption](#configuring-the-jwe-encryption)
+ [Performing JWE Encryption](#performing-jwe-encryption)
+ [Performing JWE Decryption](#performing-jwe-decryption)
+ [Encrypting Entire Payloads](#encrypting-entire-payloads-jwe)
+ [Decrypting Entire Payloads](#decrypting-entire-payloads-jwe)

##### • Introduction <a name="jwe-introduction"></a>

This library uses [JWE compact serialization](https://datatracker.ietf.org/doc/html/rfc7516#section-7.1) for the encryption of sensitive data.
The core methods responsible for payload encryption and decryption are `EncryptPayload` and `DecryptPayload` in the `JweEncryption` class.

* `EncryptPayload` usage:
```cs
var encryptedRequestPayload = JweEncryption.EncryptPayload(requestPayload, config);

```

* `DecryptPayload` usage:
```cs
var responsePayload = JweEncryption.DecryptPayload(encryptedResponsePayload, config);
```

##### • Configuring the JWE Encryption <a name="configuring-the-jwe-encryption"></a>
Use the `JweConfigBuilder` to create `JweConfig` instances. Example:
```cs
var config = JweConfigBuilder.AJweEncryptionConfig()
    .WithEncryptionCertificate(encryptionCertificate)
    .WithDecryptionKey(decryptionKey)
    .WithEncryptionPath("$.path.to.foo", "$.path.to.encryptedFoo")
    .WithDecryptionPath("$.path.to.encryptedFoo", "$.path.to.foo")
    .WithEncryptedValueFieldName("encryptedValue")
    .Build();
```

###### Supported Encryption Algorithms

The library supports the following JWE encryption algorithms according to [RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516):

**Key Encryption Algorithms (`alg` header):**

| Algorithm | Description | Key Size |
|-----------|-------------|----------|
| `RSA-OAEP` | RSAES using Optimal Asymmetric Encryption Padding (OAEP) with SHA-1 and MGF1 | 2048+ bits |
| `RSA-OAEP-256` | RSAES-OAEP using SHA-256 and MGF1 with SHA-256 | 2048+ bits |

**Content Encryption Algorithms (`enc` header):**

| Algorithm | Description | Key Size | Authentication |
|-----------|-------------|----------|----------------|
| `A128GCM` | AES-128 with Galois/Counter Mode | 128 bits | Built-in |
| `A192GCM` | AES-192 with Galois/Counter Mode | 192 bits | Built-in |
| `A256GCM` | AES-256 with Galois/Counter Mode (default) | 256 bits | Built-in |
| `A128CBC-HS256` | AES-128-CBC with HMAC-SHA256 | 256 bits (128+128) | HMAC-SHA256 |
| `A192CBC-HS384` | AES-192-CBC with HMAC-SHA384 | 384 bits (192+192) | HMAC-SHA384 |
| `A256CBC-HS512` | AES-256-CBC with HMAC-SHA512 | 512 bits (256+256) | HMAC-SHA512 |

**Algorithm Selection:**

The encryption algorithm is determined by the `enc` parameter in the JWE header. For example:

```json
{
  "alg": "RSA-OAEP-256",
  "enc": "A256GCM",
  "kid": "761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79"
}
```

**GCM vs CBC-HMAC:**

- **AES-GCM (Recommended):** Provides both encryption and authentication in a single operation. Default choice for new implementations.
- **AES-CBC-HMAC:** Provides encryption via CBC mode and authentication via HMAC. Requires two separate operations and proper HMAC verification configuration.

###### Configuring CBC-HMAC Verification

For CBC-HMAC algorithms (`A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512`), HMAC verification is **disabled by default** for backward compatibility. You can enable HMAC authentication and verification using the `WithCbcHmacVerification()` method:

```cs
var config = JweConfigBuilder.AJweEncryptionConfig()
    .WithEncryptionCertificate(encryptionCertificate)
    .WithDecryptionKey(decryptionKey)
    .WithCbcHmacVerification(true)  // Enable HMAC verification
    .Build();
```

**When HMAC verification is enabled:**

- During encryption: HMAC authentication tags are generated according to RFC 7516
- During decryption: HMAC tags are verified before decryption, providing authenticated encryption
- Tampering with ciphertext or authentication tags will cause decryption to fail with an `EncryptionException`

**When HMAC verification is disabled (default):**

- Maintains backward compatibility with existing implementations
- HMAC verification is skipped during decryption
- Empty authentication tags are generated during encryption

**Security Recommendation:** Enable HMAC verification for new integrations using CBC-HMAC algorithms to ensure data integrity and authenticity.


##### • Performing JWE Encryption <a name="performing-jwe-encryption"></a>

Call `JweEncryption.EncryptPayload` with a JSON request payload and a `JweConfig` instance.

Example using the configuration [above](#configuring-the-jwe-encryption):
```cs
const string payload = "{" +
    "    \"path\": {" +
    "        \"to\": {" +
    "            \"foo\": {" +
    "                \"sensitiveField1\": \"sensitiveValue1\"," +
    "                \"sensitiveField2\": \"sensitiveValue2\"" +
    "            }" +
    "        }" +
    "    }" +
    "}";
var encryptedPayload = JweEncryption.EncryptPayload(payload, config);
Console.WriteLine(JObject.Parse(encryptedPayload));
```

Output:
```json
{
    "path": {
        "to": {
            "encryptedFoo": {
                "encryptedValue": "eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+oPYKZEMTKyYcSIVEgtQw"
            }
        }
    }
}
```

##### • Performing JWE Decryption <a name="performing-jwe-decryption"></a>

Call `JweEncryption.DecryptPayload` with a JSON response payload and a `JweConfig` instance.

Example using the configuration [above](#configuring-the-jwe-encryption):
```cs
const string encryptedPayload = "{" +
    "    \"path\": {" +
    "        \"to\": {" +
    "            \"encryptedFoo\": {" +
    "                \"encryptedValue\": \"eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+oPYKZEMTKyYcSIVEgtQw\"" +
    "            }" +
    "        }" +
    "    }" +
    "}";
var payload = JweEncryption.DecryptPayload(encryptedPayload, config);
Console.WriteLine(JObject.Parse(payload));
```

Output:
```json
{
    "path": {
        "to": {
            "foo": {
                "sensitiveField1": "sensitiveValue1",
                "sensitiveField2": "sensitiveValue2"
            }
        }
    }
}
```

##### • Encrypting Entire Payloads <a name="encrypting-entire-payloads-jwe"></a>

Entire payloads can be encrypted using the "$" operator as encryption path:

```cs
var config = JweConfigBuilder.AJweEncryptionConfig()
    .WithEncryptionCertificate(encryptionCertificate)
    .WithEncryptionPath("$", "$")
    // …
    .Build();
```

Example:
```cs
const string payload = "{" +
    "    \"sensitiveField1\": \"sensitiveValue1\"," +
    "    \"sensitiveField2\": \"sensitiveValue2\"" +
    "}";
var encryptedPayload = JweEncryption.EncryptPayload(payload, config);
Console.WriteLine(JObject.Parse(encryptedPayload));
```

Output:
```json
{
    "encryptedValue": "eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+oPYKZEMTKyYcSIVEgtQw"
}
```

##### • Decrypting Entire Payloads <a name="decrypting-entire-payloads-jwe"></a>

Entire payloads can be decrypted using the "$" operator as decryption path:

```cs
var config = JweConfigBuilder.AJweEncryptionConfig()
    .WithDecryptionKey(decryptionKey)
    .WithDecryptionPath("$", "$")
    // …
    .Build();
```

Example:
```cs
const string encryptedPayload = "{" +
    "  \"encryptedValue\": \"eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+oPYKZEMTKyYcSIVEgtQw\"" +
    "}";
var payload = JweEncryption.DecryptPayload(encryptedPayload, config);
Console.WriteLine(JObject.Parse(payload));
```

Output:
```json
{
    "sensitiveField1": "sensitiveValue1",
    "sensitiveField2": "sensitiveValue2"
}
```

#### Mastercard Encryption and Decryption <a name="mastercard-encryption-and-decryption"></a>

+ [Introduction](#mastercard-introduction)
+ [Configuring the Mastercard Encryption](#configuring-the-mastercard-encryption)
+ [Performing Mastercard Encryption](#performing-mastercard-encryption)
+ [Performing Mastercard Decryption](#performing-mastercard-decryption)
+ [Encrypting Entire Payloads](#encrypting-entire-mastercard-payloads)
+ [Decrypting Entire Payloads](#decrypting-entire-mastercard-payloads)
+ [Using HTTP Headers for Encryption Params](#using-http-headers-for-encryption-params)

##### • Introduction <a name="mastercard-introduction"></a>
 
The core methods responsible for payload encryption and decryption are `EncryptPayload` and `DecryptPayload` in the `FieldLevelEncryption` class.

* `EncryptPayload` usage:
```cs
var encryptedRequestPayload = FieldLevelEncryption.EncryptPayload(requestPayload, config);
```

* `DecryptPayload` usage:
```cs
var responsePayload = FieldLevelEncryption.DecryptPayload(encryptedResponsePayload, config);
```

##### • Configuring the Mastercard Encryption <a name="configuring-the-mastercard-encryption"></a>
Use the `FieldLevelEncryptionConfigBuilder` to create `FieldLevelEncryptionConfig` instances. Example:
```cs
var config = FieldLevelEncryptionConfigBuilder.AFieldLevelEncryptionConfig()
    .WithEncryptionCertificate(encryptionCertificate)
    .WithDecryptionKey(decryptionKey)
    .WithEncryptionPath("$.path.to.foo", "$.path.to.encryptedFoo")
    .WithDecryptionPath("$.path.to.encryptedFoo", "$.path.to.foo")
    .WithOaepPaddingDigestAlgorithm("SHA-256")
    .WithEncryptedValueFieldName("encryptedValue")
    .WithEncryptedKeyFieldName("encryptedKey")
    .WithIvFieldName("iv")
    .WithValueEncoding(FieldValueEncoding.Hex)
    .Build();
```

See also:
* [FieldLevelEncryptionConfig.cs](https://github.com/Mastercard/client-encryption-csharp/blob/main/Mastercard.Developer.ClientEncryption.Core/Encryption/FieldLevelEncryptionConfig.cs) for all config options

##### • Performing Mastercard Encryption <a name="performing-mastercard-encryption"></a>

Call `FieldLevelEncryption.EncryptPayload` with a JSON request payload and a `FieldLevelEncryptionConfig` instance.

Example using the configuration [above](#configuring-the-field-level-encryption):
```cs
const string payload = "{" +
    "    \"path\": {" +
    "        \"to\": {" +
    "            \"foo\": {" +
    "                \"sensitiveField1\": \"sensitiveValue1\"," +
    "                \"sensitiveField2\": \"sensitiveValue2\"" +
    "            }" +
    "        }" +
    "    }" +
    "}";
var encryptedPayload = FieldLevelEncryption.EncryptPayload(payload, config);
Console.WriteLine(JObject.Parse(encryptedPayload));
```

Output:
```json
{
    "path": {
        "to": {
            "encryptedFoo": {
                "iv": "7f1105fb0c684864a189fb3709ce3d28",
                "encryptedKey": "67f467d1b653d98411a0c6d3c…ffd4c09dd42f713a51bff2b48f937c8",
                "encryptedValue": "b73aabd267517fc09ed72455c2…dffb5fa04bf6e6ce9ade1ff514ed6141"
            }
        }
    }
}
```

##### • Performing Mastercard Decryption <a name="performing-mastercard-decryption"></a>

Call `FieldLevelEncryption.DecryptPayload` with a JSON response payload and a `FieldLevelEncryptionConfig` instance.

Example using the configuration [above](#configuring-the-field-level-encryption):
```cs
const string encryptedPayload = "{" +
    "    \"path\": {" +
    "        \"to\": {" +
    "            \"encryptedFoo\": {" +
    "                \"iv\": \"e5d313c056c411170bf07ac82ede78c9\"," +
    "                \"encryptedKey\": \"e3a56746c0f9109d18b3a2652b76…f16d8afeff36b2479652f5c24ae7bd\"," +
    "                \"encryptedValue\": \"809a09d78257af5379df0c454dcdf…353ed59fe72fd4a7735c69da4080e74f\"" +
    "            }" +
    "        }" +
    "    }" +
    "}";
var payload = FieldLevelEncryption.DecryptPayload(encryptedPayload, config);
Console.WriteLine(JObject.Parse(payload));
```

Output:
```json
{
    "path": {
        "to": {
            "foo": {
                "sensitiveField1": "sensitiveValue1",
                "sensitiveField2": "sensitiveValue2"
            }
        }
    }
}
```

##### • Encrypting Entire Payloads <a name="encrypting-entire-mastercard-payloads"></a>

Entire payloads can be encrypted using the "$" operator as encryption path:

```cs
var config = FieldLevelEncryptionConfigBuilder.AFieldLevelEncryptionConfig()
    .WithEncryptionCertificate(encryptionCertificate)
    .WithEncryptionPath("$", "$")
    // …
    .Build();
```

Example:
```cs
const string payload = "{" +
    "    \"sensitiveField1\": \"sensitiveValue1\"," +
    "    \"sensitiveField2\": \"sensitiveValue2\"" +
    "}";
var encryptedPayload = FieldLevelEncryption.EncryptPayload(payload, config);
Console.WriteLine(JObject.Parse(encryptedPayload));
```

Output:
```json
{
    "iv": "1b9396c98ab2bfd195de661d70905a45",
    "encryptedKey": "7d5112fa08e554e3dbc455d0628…52e826dd10311cf0d63bbfb231a1a63ecc13",
    "encryptedValue": "e5e9340f4d2618d27f8955828c86…379b13901a3b1e2efed616b6750a90fd379515"
}
```

##### • Decrypting Entire Payloads <a name="decrypting-entire-mastercard-payloads"></a>

Entire payloads can be decrypted using the "$" operator as decryption path:

```cs
var config = FieldLevelEncryptionConfigBuilder.AFieldLevelEncryptionConfig()
    .WithDecryptionKey(decryptionKey)
    .WithDecryptionPath("$", "$")
    // …
    .Build();
```

Example:
```cs
const string encryptedPayload = "{" +
    "  \"iv\": \"1b9396c98ab2bfd195de661d70905a45\"," +
    "  \"encryptedKey\": \"7d5112fa08e554e3dbc455d0628…52e826dd10311cf0d63bbfb231a1a63ecc13\"," +
    "  \"encryptedValue\": \"e5e9340f4d2618d27f8955828c86…379b13901a3b1e2efed616b6750a90fd379515\"" +
    "}";
var payload = FieldLevelEncryption.DecryptPayload(encryptedPayload, config);
Console.WriteLine(JObject.Parse(payload));
```

Output:
```json
{
    "sensitiveField1": "sensitiveValue1",
    "sensitiveField2": "sensitiveValue2"
}
```

##### • Using HTTP Headers for Encryption Params <a name="using-http-headers-for-encryption-params"></a>

In the sections above, encryption parameters (initialization vector, encrypted symmetric key, etc.) are part of the HTTP payloads.

Here is how to configure the library for using HTTP headers instead.

###### Configuration for Using HTTP Headers <a name="configuration-for-using-http-headers"></a>

Call `With{Param}HeaderName` instead of `With{Param}FieldName` when building a `FieldLevelEncryptionConfig` instance. Example:
```cs
var config = FieldLevelEncryptionConfigBuilder.AFieldLevelEncryptionConfig()
    .WithEncryptionCertificate(encryptionCertificate)
    .WithDecryptionKey(decryptionKey)
    .WithEncryptionPath("$", "$")
    .WithDecryptionPath("$", "$")
    .WithOaepPaddingDigestAlgorithm("SHA-256")
    .WithEncryptedValueFieldName("data")
    .WithIvHeaderName("x-iv")
    .WithEncryptedKeyHeaderName("x-encrypted-key")
    // …
    .WithValueEncoding(FieldValueEncoding.Hex)
    .Build();
```

See also:
* [FieldLevelEncryptionConfig.cs](https://github.com/Mastercard/client-encryption-csharp/blob/main/Mastercard.Developer.ClientEncryption.Core/Encryption/FieldLevelEncryptionConfig.cs) for all config options

###### Encrypting Using HTTP Headers

Encryption can be performed using the following steps:

1. Generate parameters by calling `FieldLevelEncryptionParams.Generate`:

```cs
var parameters = FieldLevelEncryptionParams.Generate(config);
```

2. Update the request headers:

```cs
request.SetHeader(config.IvHeaderName, parameters.IvValue);
request.SetHeader(config.EncryptedKeyHeaderName, parameters.EncryptedKeyValue);
// …
```

3. Call `EncryptPayload` with params:
```cs
FieldLevelEncryption.EncryptPayload(payload, config, parameters);
```

Example using the configuration [above](#configuration-for-using-http-headers):

```cs
const string payload = "{" +
    "    \"sensitiveField1\": \"sensitiveValue1\"," +
    "    \"sensitiveField2\": \"sensitiveValue2\"" +
    "}";
var encryptedPayload = FieldLevelEncryption.EncryptPayload(payload, config, parameters);
Console.WriteLine(JObject.Parse(encryptedPayload));
```

Output:
```json
{
    "data": "53b5f07ee46403af2e92abab900853…d560a0a08a1ed142099e3f4c84fe5e5"
}
```

###### Decrypting Using HTTP Headers

Decryption can be performed using the following steps:

1. Read the response headers:

```cs
var ivValue = response.GetHeader(config.IvHeaderName);
var encryptedKeyValue = response.GetHeader(config.EncryptedKeyHeaderName);
// …
```

2. Create a `FieldLevelEncryptionParams` instance:

```cs
var parameters = new FieldLevelEncryptionParams(config, ivValue, encryptedKeyValue, …);
```

3. Call `DecryptPayload` with params:
```cs
FieldLevelEncryption.DecryptPayload(encryptedPayload, config, parameters);
```

Example using the configuration [above](#configuration-for-using-http-headers):

```cs
const string encryptedPayload = "{" +
    "  \"data\": \"53b5f07ee46403af2e92abab900853…d560a0a08a1ed142099e3f4c84fe5e5\"" +
    "}";
var payload = FieldLevelEncryption.DecryptPayload(encryptedPayload, config, parameters);
Console.WriteLine(JObject.Parse(payload));
```

Output:
```json
{
    "sensitiveField1": "sensitiveValue1",
    "sensitiveField2": "sensitiveValue2"
}
```

### Integrating with OpenAPI Generator API Client Libraries <a name="integrating-with-openapi-generator-api-client-libraries"></a>

[OpenAPI Generator](https://github.com/OpenAPITools/openapi-generator) generates API client libraries from [OpenAPI Specs](https://github.com/OAI/OpenAPI-Specification). 
It provides generators and library templates for supporting multiple languages and frameworks.

This project provides you with some interceptor classes you can use when configuring your API client. 
These classes will take care of encrypting request and decrypting response payloads, but also of updating HTTP headers when needed.

Generators currently supported:
+ [csharp-netcore](#csharp-netcore-generator)
+ [csharp (deprecated)](#csharp-generator)

#### csharp-netcore <a name="csharp-netcore-generator"></a>

##### OpenAPI Generator

Client libraries can be generated using the following command:

```shell
openapi-generator-cli generate -i openapi-spec.yaml -g csharp-netcore -c config.json -o out
```
config.json:

```json
{ "targetFramework": "netstandard2.1" }
```

See also: 
* [OpenAPI Generator CLI Installation](https://openapi-generator.tech/docs/installation)
* [Config Options for csharp-netcore](https://github.com/OpenAPITools/openapi-generator/blob/master/docs/generators/csharp-netcore.md)

##### Usage of the `RestSharpEncryptionInterceptor`

`RestSharpEncryptionInterceptor` is located in the [`ClientEncryption.RestSharpV2`](https://www.nuget.org/packages/Mastercard.Developer.ClientEncryption.RestSharpV2/) package. 

##### Usage

1. Create a new file (for instance, `MastercardApiClient.cs`) extending the definition of the generated `ApiClient` class:

```cs
partial class ApiClient
{
    private readonly Uri _basePath;
    private readonly RestSharpSigner _signer;
    private readonly RestSharpEncryptionInterceptor _encryptionInterceptor;

    /// <summary>
    /// Construct an ApiClient which will automatically:
    /// - Sign requests
    /// - Encrypt/decrypt requests and responses
    /// </summary>
    public ApiClient(RSA signingKey, string basePath, string consumerKey, EncryptionConfig config)
    {
        _baseUrl = basePath;
        _basePath = new Uri(basePath);
        _signer = new RestSharpSigner(consumerKey, signingKey);
        _encryptionInterceptor = RestSharpEncryptionInterceptor.From(config);
    }

    partial void InterceptRequest(RestRequest request)
    {
        _encryptionInterceptor.InterceptRequest(request);
        _signer.Sign(_basePath, request);
    }
}
```

2. Configure your `ApiClient` instance the following way:

```cs
var client = new ApiClient(SigningKey, BasePath, ConsumerKey, config);
var serviceApi = new ServiceApi() { Client = client };
// …
```

#### csharp (deprecated)<a name="csharp-generator"></a>

##### OpenAPI Generator

Client libraries can be generated using the following command:

```shell
openapi-generator-cli generate -i openapi-spec.yaml -g csharp -c config.json -o out
```

config.json:
```json
{ "targetFramework": "netstandard2.1" }
```

⚠️ `v5.0` was used for `targetFramework` in OpenAPI Generator versions prior 5.0.0.

See also: 
* [OpenAPI Generator CLI Installation](https://openapi-generator.tech/docs/installation)
* [Config Options for csharp](https://github.com/OpenAPITools/openapi-generator/blob/master/docs/generators/csharp.md)

##### Usage of the `RestSharpFieldLevelEncryptionInterceptor`

`RestSharpFieldLevelEncryptionInterceptor` is located in the [`ClientEncryption.RestSharp`](https://www.nuget.org/packages/Mastercard.Developer.ClientEncryption.RestSharp/) package. 

##### Usage:
1. Create a new file (for instance, `MastercardApiClient.cs`) extending the definition of the generated `ApiClient` class:

```cs
partial class ApiClient
{
    public RestSharpFieldLevelEncryptionInterceptor EncryptionInterceptor { private get; set; }
    partial void InterceptRequest(RestRequest request) => EncryptionInterceptor.InterceptRequest(request);
    partial void InterceptResponse(RestRequest request, RestResponse response) => EncryptionInterceptor.InterceptResponse(response);
}
```

2. Configure your `ApiClient` instance the following way:

```cs
var config = Configuration.Default;
config.BasePath = "https://sandbox.api.mastercard.com";
config.ApiClient.RestClient.Authenticator = new RestSharpOAuth1Authenticator(ConsumerKey, signingKey, new Uri(config.BasePath));
var encryptionConfig = FieldLevelEncryptionConfigBuilder
    .AFieldLevelEncryptionConfig()
    // …
    .Build();
config.ApiClient.EncryptionInterceptor = new RestSharpFieldLevelEncryptionInterceptor(encryptionConfig);
var serviceApi = new ServiceApi(config);
// …
```
