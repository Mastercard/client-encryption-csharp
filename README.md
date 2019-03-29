# client-encryption-csharp

[![](https://travis-ci.org/Mastercard/client-encryption-csharp.svg?branch=master)](https://travis-ci.org/Mastercard/client-encryption-csharp)
[![](https://sonarcloud.io/api/project_badges/measure?project=Mastercard_client-encryption-csharp&metric=alert_status)](https://sonarcloud.io/dashboard?id=Mastercard_client-encryption-csharp) 
[![](https://img.shields.io/nuget/v/Mastercard.Developer.ClientEncryption.Core.svg?label=nuget%20|%20core)](https://www.nuget.org/packages/Mastercard.Developer.ClientEncryption.Core/)
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

## Overview <a name="overview"></a>
Library for Mastercard API compliant payload encryption/decryption.

### Compatibility <a name="compatibility"></a>

#### .NET <a name="net"></a>
This library requires a .NET Framework implementing [.NET Standard](https://docs.microsoft.com/en-us/dotnet/standard/net-standard) 1.3.

#### Strong Naming <a name="strong-naming"></a>
Assemblies are strong-named as per [Strong naming and .NET libraries](https://docs.microsoft.com/en-us/dotnet/standard/library-guidance/strong-naming).
The SN key is available here: [`Identity.snk`](https://github.com/Mastercard/client-encryption-csharp/blob/master/Identity.snk).

### References <a name="references"></a>
* [Encryption of sensitive data](https://developer.mastercard.com/page/mdes-token-connect-encryption-of-sensitive-data) guide

## Usage <a name="usage"></a>
### Prerequisites <a name="prerequisites"></a>
Before using this library, you will need to set up a project in the [Mastercard Developers Portal](https://developer.mastercard.com). 

As part of this set up, you'll receive:
* A public request encryption certificate (aka _Client Encryption Keys_)
* A private response decryption key (aka _Mastercard Encryption Keys_)

### Adding the Libraries to Your Project <a name="adding-the-libraries-to-your-project"></a>

#### Package Manager
```shell
Install-Package Mastercard.Developer.ClientEncryption.Core
Install-Package Mastercard.Developer.ClientEncryption.RestSharp
```

#### .NET CLI
```shell
dotnet add package Mastercard.Developer.ClientEncryption.Core
dotnet add package Mastercard.Developer.ClientEncryption.RestSharp
```

### Loading the Encryption Certificate <a name="loading-the-encryption-certificate"></a>

A `System.Security.Cryptography.X509Certificates.X509Certificate` object can be created from a file by calling the `EncryptionUtils.LoadEncryptionCertificate` method:
```cs
var encryptionCertificate = EncryptionUtils.LoadEncryptionCertificate("<insert certificate file path>");
```

Supported certificate formats: PEM, DER.

### Loading the Decryption Key <a name="loading-the-decryption-key"></a>

#### From a PKCS#12 File

A `System.Security.Cryptography.RSA` object can be created from a PKCS#12 file by calling the `EncryptionUtils.LoadDecryptionKey` method:
```cs
var decryptionKey = EncryptionUtils.LoadDecryptionKey(
                                    "<insert PKCS#12 key file path>", 
                                    "<insert key alias>", 
                                    "<insert key password>");
```

#### From an Unencrypted Key File

A `System.Security.Cryptography.RSA` object can be created from an unencrypted key file by calling the `EncryptionUtils.LoadDecryptionKey` method:
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

The methods that do all the heavy lifting are `EncryptPayload` and `DecryptPayload` in the `FieldLevelEncryption` class.

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
* [FieldLevelEncryptionConfigBuilder.cs](https://github.com/Mastercard/client-encryption-csharp/blob/master/Mastercard.Developer.ClientEncryption.Core/Encryption/FieldLevelEncryptionConfigBuilder.cs) for all config options
* [Service configurations](https://github.com/Mastercard/client-encryption-csharp/wiki/C%23-Service-Configurations) wiki page

#### Performing Encryption <a name="performing-encryption"></a>

Call `FieldLevelEncryption.EncryptPayload` with a JSON request payload and a `FieldLevelEncryptionConfig` instance.

Example using the configuration [above](#configuring-the-field-level-encryption):
```cs
const string = "{" +
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

TODO

Output:

TODO

#### Encrypting Entire Payloads <a name="encrypting-entire-payloads"></a>

Entire payloads can be encrypted using the "$" operator as encryption path:

TODO

Example:

TODO

Output:

TODO

#### Decrypting Entire Payloads <a name="decrypting-entire-payloads"></a>

Entire payloads can be decrypted using the "$" operator as decryption path:

TODO

Example:

TODO

Output:

TODO

#### Using HTTP Headers for Encryption Params <a name="using-http-headers-for-encryption-params"></a>

In the sections above, encryption parameters (initialization vector, encrypted symmetric key, etc.) are part of the HTTP payloads.

Here is how to configure the library for using HTTP headers instead.

##### Configuration for Using HTTP Headers <a name="configuration-for-using-http-headers"></a>

TODO

##### Encrypting Using HTTP Headers

Encryption can be performed using the following steps:

TODO

Example using the configuration [above](#configuration-for-using-http-headers):

TODO

Output:

TODO

##### Decrypting Using HTTP Headers

Decryption can be performed using the following steps:

TODO

Example using the configuration [above](#configuration-for-using-http-headers):

TODO

Output:

TODO
