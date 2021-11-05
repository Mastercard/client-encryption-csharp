# client-encryption-csharp
[![](https://developer.mastercard.com/_/_/src/global/assets/svg/mcdev-logo-dark.svg)](https://developer.mastercard.com/)

[![](https://github.com/Mastercard/client-encryption-csharp/workflows/Build%20&%20Test/badge.svg)](https://github.com/Mastercard/client-encryption-csharp/actions?query=workflow%3A%22Build+%26+Test%22)
[![](https://sonarcloud.io/api/project_badges/measure?project=Mastercard_client-encryption-csharp&metric=alert_status)](https://sonarcloud.io/dashboard?id=Mastercard_client-encryption-csharp)
[![](https://github.com/Mastercard/client-encryption-csharp/workflows/broken%20links%3F/badge.svg)](https://github.com/Mastercard/client-encryption-csharp/actions?query=workflow%3A%22broken+links%3F%22)
[![](https://img.shields.io/nuget/v/Mastercard.Developer.ClientEncryption.Core.svg?label=nuget%20|%20core)](https://www.nuget.org/packages/Mastercard.Developer.ClientEncryption.Core/)
[![](https://img.shields.io/nuget/v/Mastercard.Developer.ClientEncryption.RestSharp.svg?label=nuget%20|%20restsharp%20portable)](https://www.nuget.org/packages/Mastercard.Developer.ClientEncryption.RestSharp/)
[![](https://img.shields.io/nuget/v/Mastercard.Developer.ClientEncryption.RestSharpV2.svg?label=nuget%20|%20restsharp)](https://www.nuget.org/packages/Mastercard.Developer.ClientEncryption.RestSharpV2/)
[![](https://img.shields.io/badge/license-MIT-yellow.svg)](https://github.com/Mastercard/client-encryption-csharp/blob/master/LICENSE)

## Table of Contents
- [Overview](#overview)
  * [Compatibility](#compatibility)
  * [References](#references)
- [Usage](#usage)
  * [Prerequisites](#prerequisites)
  * [Adding the Libraries to Your Project](#adding-the-libraries-to-your-project)
  * [Loading the Encryption Certificate](#loading-the-encryption-certificate) 
  * [Loading the Decryption Key](#loading-the-decryption-key)
  * [Performing Field Level Encryption and Decryption](#performing-field-level-encryption-and-decryption)
  * [Integrating with OpenAPI Generator API Client Libraries](#integrating-with-openapi-generator-api-client-libraries)

## Overview <a name="overview"></a>
* [`ClientEncryption.Core`](https://www.nuget.org/packages/Mastercard.Developer.ClientEncryption.Core/) is a zero dependency library for Mastercard API compliant payload encryption/decryption.
* [`ClientEncryption.RestSharpV2`](https://www.nuget.org/packages/Mastercard.Developer.ClientEncryption.RestSharpV2/) is an extension dedicated to [RestSharp](https://restsharp.dev/)
* [`ClientEncryption.RestSharp`](https://www.nuget.org/packages/Mastercard.Developer.ClientEncryption.RestSharp) is an extension dedicated to [RestSharp Portable](https://github.com/FubarDevelopment/restsharp.portable) (project no longer maintained)

### Compatibility <a name="compatibility"></a>

#### .NET <a name="net"></a>
* `ClientEncryption.Core` and `ClientEncryption.RestSharp` require a .NET Framework implementing [.NET Standard](https://docs.microsoft.com/en-us/dotnet/standard/net-standard) 1.3.
* `ClientEncryption.RestSharpV2` requires a .NET Framework implementing [.NET Standard](https://docs.microsoft.com/en-us/dotnet/standard/net-standard) 2.0.

#### Strong Naming <a name="strong-naming"></a>
Assemblies are strong-named as per [Strong naming and .NET libraries](https://docs.microsoft.com/en-us/dotnet/standard/library-guidance/strong-naming).
The SN key is available here: [`Identity.snk`](https://github.com/Mastercard/client-encryption-csharp/blob/master/Identity.snk).

### References <a name="references"></a>
<img src="https://user-images.githubusercontent.com/3964455/55345820-c520a280-54a8-11e9-8235-407199fa1d97.png" alt="Encryption of sensitive data" width="75%" height="75%"/>

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

### Performing Field Level Encryption and Decryption <a name="performing-field-level-encryption-and-decryption"></a>

+ [Introduction](#introduction)
+ [Configuring the Field Level Encryption](#configuring-the-field-level-encryption)
+ [Performing Encryption](#performing-encryption)
+ [Performing Decryption](#performing-decryption)
+ [Encrypting Entire Payloads](#encrypting-entire-payloads)
+ [Decrypting Entire Payloads](#decrypting-entire-payloads)
+ [Using HTTP Headers for Encryption Params](#using-http-headers-for-encryption-params)

#### Introduction <a name="introduction"></a>

The core methods responsible for payload encryption and decryption are `EncryptPayload` and `DecryptPayload` in the `FieldLevelEncryption` class.

* `EncryptPayload` usage:
```cs
var encryptedRequestPayload = FieldLevelEncryption.EncryptPayload(requestPayload, config);
```

* `DecryptPayload` usage:
```cs
var responsePayload = FieldLevelEncryption.DecryptPayload(encryptedResponsePayload, config);
```

#### Configuring the Field Level Encryption <a name="configuring-the-field-level-encryption"></a>

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
* [FieldLevelEncryptionConfig.cs](https://github.com/Mastercard/client-encryption-csharp/blob/master/Mastercard.Developer.ClientEncryption.Core/Encryption/FieldLevelEncryptionConfig.cs) for all config options
* [Service Configurations for Client Encryption C#](https://github.com/Mastercard/client-encryption-csharp/wiki/Service-Configurations-for-Client-Encryption-C%23)

#### Performing Encryption <a name="performing-encryption"></a>

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
                "encryptedKey": "67f467d1b653d98411a0c6d3c(...)ffd4c09dd42f713a51bff2b48f937c8",
                "encryptedValue": "b73aabd267517fc09ed72455c2(...)dffb5fa04bf6e6ce9ade1ff514ed6141"
            }
        }
    }
}
```

#### Performing Decryption <a name="performing-decryption"></a>

Call `FieldLevelEncryption.DecryptPayload` with a JSON response payload and a `FieldLevelEncryptionConfig` instance.

Example using the configuration [above](#configuring-the-field-level-encryption):
```cs
const string encryptedPayload = "{" +
    "    \"path\": {" +
    "        \"to\": {" +
    "            \"encryptedFoo\": {" +
    "                \"iv\": \"e5d313c056c411170bf07ac82ede78c9\"," +
    "                \"encryptedKey\": \"e3a56746c0f9109d18b3a2652b76(...)f16d8afeff36b2479652f5c24ae7bd\"," +
    "                \"encryptedValue\": \"809a09d78257af5379df0c454dcdf(...)353ed59fe72fd4a7735c69da4080e74f\"" +
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

#### Encrypting Entire Payloads <a name="encrypting-entire-payloads"></a>

Entire payloads can be encrypted using the "$" operator as encryption path:

```cs
var config = FieldLevelEncryptionConfigBuilder.AFieldLevelEncryptionConfig()
    .WithEncryptionCertificate(encryptionCertificate)
    .WithEncryptionPath("$", "$")
    // ...
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
    "encryptedKey": "7d5112fa08e554e3dbc455d0628(...)52e826dd10311cf0d63bbfb231a1a63ecc13",
    "encryptedValue": "e5e9340f4d2618d27f8955828c86(...)379b13901a3b1e2efed616b6750a90fd379515"
}
```

#### Decrypting Entire Payloads <a name="decrypting-entire-payloads"></a>

Entire payloads can be decrypted using the "$" operator as decryption path:

```cs
var config = FieldLevelEncryptionConfigBuilder.AFieldLevelEncryptionConfig()
    .WithDecryptionKey(decryptionKey)
    .WithDecryptionPath("$", "$")
    // ...
    .Build();
```

Example:
```cs
const string encryptedPayload = "{" +
    "  \"iv\": \"1b9396c98ab2bfd195de661d70905a45\"," +
    "  \"encryptedKey\": \"7d5112fa08e554e3dbc455d0628(...)52e826dd10311cf0d63bbfb231a1a63ecc13\"," +
    "  \"encryptedValue\": \"e5e9340f4d2618d27f8955828c86(...)379b13901a3b1e2efed616b6750a90fd379515\"" +
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

#### Using HTTP Headers for Encryption Params <a name="using-http-headers-for-encryption-params"></a>

In the sections above, encryption parameters (initialization vector, encrypted symmetric key, etc.) are part of the HTTP payloads.

Here is how to configure the library for using HTTP headers instead.

##### Configuration for Using HTTP Headers <a name="configuration-for-using-http-headers"></a>

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
    // ...
    .WithValueEncoding(FieldValueEncoding.Hex)
    .Build();
```

See also:
* [FieldLevelEncryptionConfig.cs](https://github.com/Mastercard/client-encryption-csharp/blob/master/Mastercard.Developer.ClientEncryption.Core/Encryption/FieldLevelEncryptionConfig.cs) for all config options
* [Service Configurations for Client Encryption C#](https://github.com/Mastercard/client-encryption-csharp/wiki/Service-Configurations-for-Client-Encryption-C%23)

##### Encrypting Using HTTP Headers

Encryption can be performed using the following steps:

1. Generate parameters by calling `FieldLevelEncryptionParams.Generate`:

```cs
var parameters = FieldLevelEncryptionParams.Generate(config);
```

2. Update the request headers:

```cs
request.SetHeader(config.IvHeaderName, parameters.IvValue);
request.SetHeader(config.EncryptedKeyHeaderName, parameters.EncryptedKeyValue);
// ...
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
    "data": "53b5f07ee46403af2e92abab900853(...)d560a0a08a1ed142099e3f4c84fe5e5"
}
```

##### Decrypting Using HTTP Headers

Decryption can be performed using the following steps:

1. Read the response headers:

```cs
var ivValue = response.GetHeader(config.IvHeaderName);
var encryptedKeyValue = response.GetHeader(config.EncryptedKeyHeaderName);
// ...
```

2. Create a `FieldLevelEncryptionParams` instance:

```cs
var parameters = new FieldLevelEncryptionParams(config, ivValue, encryptedKeyValue, ...);
```

3. Call `DecryptPayload` with params:
```cs
FieldLevelEncryption.DecryptPayload(encryptedPayload, config, parameters);
```

Example using the configuration [above](#configuration-for-using-http-headers):

```cs
const string encryptedPayload = "{" +
    "  \"data\": \"53b5f07ee46403af2e92abab900853(...)d560a0a08a1ed142099e3f4c84fe5e5\"" +
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
java -jar openapi-generator-cli.jar generate -i openapi-spec.yaml -g csharp-netcore -c config.json -o out
```
config.json:

```json
{ "targetFramework": "netstandard2.0" }
```

See also: 
* [OpenAPI Generator (executable)](https://mvnrepository.com/artifact/org.openapitools/openapi-generator-cli)
* [Config Options for csharp-netcore](https://github.com/OpenAPITools/openapi-generator/blob/master/docs/generators/csharp-netcore.md)

##### Usage of the `RestSharpFieldLevelEncryptionInterceptor`

`RestSharpFieldLevelEncryptionInterceptor` is located in the [`ClientEncryption.RestSharpV2`](https://www.nuget.org/packages/Mastercard.Developer.ClientEncryption.RestSharpV2/) package. 

##### Usage

1. Create a new file (for instance, `ApiClientWithEncryption.cs`) extending the definition of the generated `ApiClient` class:

```cs
partial class ApiClient
{
    public RestSharpFieldLevelEncryptionInterceptor EncryptionInterceptor { private get; set; }
    
    public ApiClient(RSA signingKey, string basePath, string consumerKey)
    {
        this._baseUrl = basePath;
        this.BasePath = new Uri(basePath);
        this.Signer = new RestSharpSigner(consumerKey, signingKey);
    }
    
    partial void InterceptRequest(IRestRequest request) {
        EncryptionInterceptor.InterceptRequest(request);
        Signer.Sign(this.BasePath, request);
    }
}
```

2. Configure your `ApiClient` instance the following way:

```cs
var serviceApi = new ServiceApi();
var client = new ApiClient(SigningKey, BasePath, ConsumerKey);

var fieldLevelEncryptionConfig = FieldLevelEncryptionConfigBuilder
    .AFieldLevelEncryptionConfig()
    // ...
    .Build();

client.EncryptionInterceptor = new RestSharpFieldLevelEncryptionInterceptor(fieldLevelEncryptionConfig)
serviceApi.Client = client;
// ...
```

#### csharp (deprecated)<a name="csharp-generator"></a>

##### OpenAPI Generator

Client libraries can be generated using the following command:

```shell
openapi-generator-cli generate -i openapi-spec.yaml -g csharp -c config.json -o out
```

config.json:
```json
{ "targetFramework": "netstandard1.3" }
```

⚠️ `v5.0` was used for `targetFramework` in OpenAPI Generator versions prior 5.0.0.

See also: 
* [OpenAPI Generator (executable)](https://mvnrepository.com/artifact/org.openapitools/openapi-generator-cli)
* [Config Options for csharp](https://github.com/OpenAPITools/openapi-generator/blob/master/docs/generators/csharp.md)

##### Usage of the `RestSharpFieldLevelEncryptionInterceptor`

`RestSharpFieldLevelEncryptionInterceptor` is located in the [`ClientEncryption.RestSharp`](https://www.nuget.org/packages/Mastercard.Developer.ClientEncryption.RestSharp/) package. 

##### Usage:
1. Create a new file (for instance, `ApiClientWithEncryption.cs`) extending the definition of the generated `ApiClient` class:

```cs
partial class ApiClient
{
    public RestSharpFieldLevelEncryptionInterceptor EncryptionInterceptor { private get; set; }
    partial void InterceptRequest(IRestRequest request) => EncryptionInterceptor.InterceptRequest(request);
    partial void InterceptResponse(IRestRequest request, IRestResponse response) => EncryptionInterceptor.InterceptResponse(response);
}
```

2. Configure your `ApiClient` instance the following way:

```cs
var config = Configuration.Default;
config.BasePath = "https://sandbox.api.mastercard.com";
config.ApiClient.RestClient.Authenticator = new RestSharpOAuth1Authenticator(ConsumerKey, signingKey, new Uri(config.BasePath));
var fieldLevelEncryptionConfig = FieldLevelEncryptionConfigBuilder
    .AFieldLevelEncryptionConfig()
    // ...
    .Build();
config.ApiClient.EncryptionInterceptor = new RestSharpFieldLevelEncryptionInterceptor(fieldLevelEncryptionConfig);
var serviceApi = new ServiceApi(config);
// ...
```
